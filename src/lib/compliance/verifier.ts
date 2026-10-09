import crypto from "node:crypto";
import type { SessionUser } from "@/lib/auth/session";
import type { HashChainAuditRecord } from "@/lib/fleet/fleet";
import { AuditExportGenerator } from "./exportGenerator";
import { computeEventHash, computeEventHashStandard } from "./evidenceVault";
import { buildMerkleTree } from "./merkle";

export interface VerifiedBlockDetail {
  blockIndex: number;
  id: string;
  eventType: string;
  actorId: string;
  createdAt: string;
  prevHash: string;
  currentHash: string;
  computedHash: string;
  merkleLeafHash: string;
  payload: Record<string, unknown>;
  status: "VALID" | "TAMPERED" | "BROKEN_LINK" | "GENESIS";
  linkStatus: "LINKED" | "BROKEN";
}

export interface DetailedVerificationReport {
  valid: boolean;
  tenantId: string;
  verifiedAt: string;
  totalBlocks: number;
  genesisHash: string;
  chainHeadHash: string;
  headHash?: string;
  merkleRoot: string;
  verdictMessage: string;
  blocks: VerifiedBlockDetail[];
  tamperCount: number;
  tamperedCount?: number;
  brokenLinkCount: number;
  brokenIndex?: number;
  failureReason?: string;
}

/**
 * Recalculates and verifies SHA-256 cryptographic hashes from Genesis to Head
 * for all blocks in the tenant's ledger.
 */
export async function verifyTenantLedger(
  caller: SessionUser,
  customEvents?: HashChainAuditRecord[]
): Promise<DetailedVerificationReport> {
  const tenantId = caller.tenant_id;
  const events = customEvents || (await AuditExportGenerator.fetchEventsForTenant(tenantId));

  if (!events || events.length === 0) {
    return {
      valid: false,
      tenantId,
      verifiedAt: new Date().toISOString(),
      totalBlocks: 0,
      genesisHash: "",
      chainHeadHash: "",
      merkleRoot: "",
      verdictMessage: "Hash-chain ledger contains 0 blocks.",
      blocks: [],
      tamperCount: 0,
      brokenLinkCount: 0,
      failureReason: "Ledger is empty",
    };
  }

  const leafHashes = events.map((e) =>
    crypto.createHash("sha256").update(e.current_hash).digest("hex")
  );
  const merkleTree = buildMerkleTree(leafHashes);

  let tamperCount = 0;
  let brokenLinkCount = 0;
  let firstBrokenIndex: number | undefined;
  let failureReason: string | undefined;

  const blocks: VerifiedBlockDetail[] = [];

  for (let i = 0; i < events.length; i++) {
    const cur = events[i];
    const leafHash = leafHashes[i];

    let computedHash = cur.current_hash;
    let blockStatus: "VALID" | "TAMPERED" | "BROKEN_LINK" | "GENESIS" = "VALID";
    let linkStatus: "LINKED" | "BROKEN" = "LINKED";

    if (cur.event_type === "GENESIS") {
      blockStatus = "GENESIS";
      computedHash = cur.current_hash;
    } else {
      const canonical = computeEventHash(cur.prev_hash, cur.actor_id, cur.payload);
      const standard = computeEventHashStandard(cur.prev_hash, cur.actor_id, cur.payload);

      if (cur.current_hash === canonical || cur.current_hash === standard) {
        computedHash = cur.current_hash;
      } else {
        computedHash = canonical;
        blockStatus = "TAMPERED";
        tamperCount++;
        if (firstBrokenIndex === undefined) {
          firstBrokenIndex = i;
          failureReason = `Block #${i} (${cur.id}) payload does not match recorded SHA-256 hash.`;
        }
      }
    }

    if (i > 0) {
      const prev = events[i - 1];
      if (cur.prev_hash !== prev.current_hash) {
        linkStatus = "BROKEN";
        brokenLinkCount++;
        if (blockStatus !== "TAMPERED") {
          blockStatus = "BROKEN_LINK";
        }
        if (firstBrokenIndex === undefined) {
          firstBrokenIndex = i;
          failureReason = `Block #${i} prev_hash does not match previous block current_hash.`;
        }
      }
    }

    blocks.push({
      blockIndex: i,
      id: cur.id,
      eventType: cur.event_type,
      actorId: cur.actor_id,
      createdAt: cur.created_at,
      prevHash: cur.prev_hash,
      currentHash: cur.current_hash,
      computedHash,
      merkleLeafHash: leafHash,
      payload: cur.payload || {},
      status: blockStatus,
      linkStatus,
    });
  }

  const isValid = tamperCount === 0 && brokenLinkCount === 0;

  return {
    valid: isValid,
    tenantId,
    verifiedAt: new Date().toISOString(),
    totalBlocks: events.length,
    genesisHash: events[0].current_hash,
    chainHeadHash: events[events.length - 1].current_hash,
    headHash: events[events.length - 1].current_hash,
    merkleRoot: merkleTree.root,
    verdictMessage: isValid
      ? "100% Mathematically Validated — Zero Tampering Detected"
      : `Ledger Validation FAILED: ${tamperCount} tampered blocks, ${brokenLinkCount} broken links detected.`,
    blocks,
    tamperCount,
    tamperedCount: tamperCount,
    brokenLinkCount,
    brokenIndex: firstBrokenIndex,
    failureReason,
  };
}

/**
 * Direct array verifier helper for unit test suites and export integrity testing.
 */
export async function verifyHashChainDetailed(
  events: HashChainAuditRecord[]
): Promise<DetailedVerificationReport & { headHash: string; tamperedCount: number }> {
  const tenantId = events[0]?.tenant_id || "default";
  const rep = await verifyTenantLedger(
    { id: "system", tenant_id: tenantId, role: "system_admin" },
    events
  );
  return {
    ...rep,
    headHash: rep.chainHeadHash,
    tamperedCount: rep.tamperCount,
  };
}
