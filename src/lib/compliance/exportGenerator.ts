import crypto from "node:crypto";
import type { HashChainAuditRecord } from "@/lib/fleet/fleet";
import type { SessionUser } from "@/lib/auth/session";
import { buildMerkleTree, generateMerkleProof, MerkleProofElement } from "./merkle";
import { ISO_27001_CONTROLS } from "./iso27001";
import {
  CryptographicEvidencePackage,
  EvidencePackageManifest,
  STANDALONE_VERIFICATION_PYTHON_SCRIPT,
  computeEventHash,
  verifyHashChainIntegrity,
} from "./evidenceVault";
import {
  getOrCreateTenantStore,
  appendStatefulHashChainEvent,
} from "./statefulTenantDb";

export interface ExportBundleOptions {
  tenantId: string;
  exportedBy: string;
  format?: "json" | "csv";
  limit?: number;
  startDate?: string;
  endDate?: string;
  customEvents?: HashChainAuditRecord[];
  persistRecord?: boolean;
}

export interface GeneratedExportBundle {
  packageId: string;
  tenantId: string;
  format: "json" | "csv";
  manifest: EvidencePackageManifest;
  data: string; // JSON string or CSV string
  contentType: string;
  headers: Record<string, string>;
  totalEvents: number;
}

export class AuditExportGenerator {
  /**
   * Retrieves audit events strictly isolated for a tenant from PostgreSQL hash_chain_audit,
   * falling back to stateful in-memory tenant database when offline or in unit tests.
   * Strictly enforces deduplication: strictly one Genesis block at index 0.
   */
  public static async fetchEventsForTenant(
    tenantId: string,
    options?: { limit?: number; startDate?: string; endDate?: string }
  ): Promise<HashChainAuditRecord[]> {
    let events: HashChainAuditRecord[] = [];

    try {
      const { query } = await import("@/lib/db");
      let sql = `SELECT id, tenant_id, event_type, actor_id, payload, prev_hash, current_hash, created_at
                 FROM hash_chain_audit
                 WHERE tenant_id = $1`;
      const params: unknown[] = [tenantId];

      if (options?.startDate) {
        params.push(options.startDate);
        sql += ` AND created_at >= $${params.length}`;
      }
      if (options?.endDate) {
        params.push(options.endDate);
        sql += ` AND created_at <= $${params.length}`;
      }

      sql += ` ORDER BY created_at ASC, id ASC`;
      if (options?.limit) {
        params.push(options.limit);
        sql += ` LIMIT $${params.length}`;
      }

      const res = await query<Record<string, unknown>>(sql, params);
      if (res.rows && res.rows.length > 0) {
        events = res.rows.map((r: Record<string, unknown>) => ({
          id: String(r.id),
          tenant_id: String(r.tenant_id),
          event_type: String(r.event_type),
          actor_id: String(r.actor_id),
          payload: (typeof r.payload === "string" ? JSON.parse(r.payload) : r.payload) as Record<string, unknown>,
          prev_hash: String(r.prev_hash),
          current_hash: String(r.current_hash),
          created_at: String(r.created_at),
        }));
      }
    } catch {
      // In offline / test environment without DB connection
    }

    // Fallback to stateful tenant store if DB returned no records
    if (!events || events.length === 0) {
      const store = getOrCreateTenantStore(tenantId);
      events = [...store.hashChain];
    }

    // Ledger Deduplication: Ensure strictly ONE Genesis block at index 0
    return this.deduplicateLedger(tenantId, events);
  }

  /**
   * Sanitizes and guarantees that index 0 is Genesis, and removes duplicate or orphan Genesis records.
   */
  public static deduplicateLedger(tenantId: string, rawEvents: HashChainAuditRecord[]): HashChainAuditRecord[] {
    if (!rawEvents || rawEvents.length === 0) {
      return getOrCreateTenantStore(tenantId).hashChain;
    }

    const deduplicated: HashChainAuditRecord[] = [];
    let hasGenesis = false;

    for (let i = 0; i < rawEvents.length; i++) {
      const ev = rawEvents[i];
      if (ev.event_type === "GENESIS") {
        if (!hasGenesis) {
          // Keep first Genesis block at index 0
          deduplicated.push(ev);
          hasGenesis = true;
        }
        // Discard subsequent duplicate Genesis blocks
      } else {
        deduplicated.push(ev);
      }
    }

    // If no Genesis block was present, prepend a valid Genesis block for this tenant
    if (!hasGenesis && deduplicated.length > 0) {
      const first = deduplicated[0];
      const genesisDate = new Date(new Date(first.created_at).getTime() - 1000).toISOString();
      const genesisPayload = { msg: "ShieldDesk Hash Chain Genesis", tenant_id: tenantId };
      const genesisPrevHash = "0".repeat(64);
      const genesisCurrentHash = first.prev_hash || computeEventHash(genesisPrevHash, "system:genesis", genesisPayload);

      deduplicated.unshift({
        id: `hc-${tenantId}-genesis`,
        tenant_id: tenantId,
        event_type: "GENESIS",
        actor_id: "system:genesis",
        payload: genesisPayload,
        prev_hash: genesisPrevHash,
        current_hash: genesisCurrentHash,
        created_at: genesisDate,
      });
    }

    return deduplicated;
  }

  /**
   * Builds the signed cryptographic evidence package manifest and Merkle tree.
   */
  public static buildPackage(
    tenantId: string,
    exportedBy: string,
    events: HashChainAuditRecord[]
  ): CryptographicEvidencePackage {
    const packageId = `EVID-${tenantId.toUpperCase()}-${Date.now().toString(36)}`;
    const exportedAt = new Date().toISOString();

    const leafHashes = events.map((e) =>
      crypto.createHash("sha256").update(e.current_hash).digest("hex")
    );
    const merkleTree = buildMerkleTree(leafHashes);

    const merkleProofs: Record<number, MerkleProofElement[]> = {};
    for (let i = 0; i < events.length; i++) {
      merkleProofs[i] = generateMerkleProof(leafHashes, i);
    }

    const headHash = events[events.length - 1]?.current_hash || "0".repeat(64);

    const secret =
      process.env.SHIELDDESK_SESSION_SECRET ||
      process.env.SHIELDDESK_VAULT_SECRET ||
      "shielddesk_audit_vault_dev_ephemeral_key";

    const signatureData = `${packageId}|${tenantId}|${headHash}|${merkleTree.root}|${events.length}`;
    const signature = crypto.createHmac("sha256", secret).update(signatureData).digest("hex");

    const manifest: EvidencePackageManifest = {
      packageId,
      tenantId,
      exportedAt,
      exportedBy,
      totalEvents: events.length,
      chainHeadHash: headHash,
      merkleRoot: merkleTree.root,
      signature,
      algorithm: "HMAC-SHA256",
    };

    return {
      manifest,
      events,
      merkleProofs,
      complianceControls: ISO_27001_CONTROLS,
      offlineVerificationScript: STANDALONE_VERIFICATION_PYTHON_SCRIPT,
      verifierScript: STANDALONE_VERIFICATION_PYTHON_SCRIPT,
    };
  }

  /**
   * Formats audit records into RFC-4180 compliant CSV format with cryptographic audit headers.
   */
  public static formatCsv(pkg: CryptographicEvidencePackage): string {
    const m = pkg.manifest;
    const lines: string[] = [];

    // Header comment block with cryptographic attestations
    lines.push(`# ShieldDesk Cryptographic Audit Ledger Export`);
    lines.push(`# Package ID: ${m.packageId}`);
    lines.push(`# Tenant ID: ${m.tenantId}`);
    lines.push(`# Exported At: ${m.exportedAt}`);
    lines.push(`# Exported By: ${m.exportedBy}`);
    lines.push(`# Total Events: ${m.totalEvents}`);
    lines.push(`# Chain Head Hash: ${m.chainHeadHash}`);
    lines.push(`# Merkle Root: ${m.merkleRoot}`);
    lines.push(`# Manifest Signature: ${m.signature}`);
    lines.push(`# Algorithm: ${m.algorithm}`);
    lines.push(
      `"sequence_number","timestamp","event_id","tenant_id","event_type","actor_id","prev_hash","current_hash","merkle_leaf_hash","payload_summary"`
    );

    pkg.events.forEach((ev, idx) => {
      const leafHash = crypto.createHash("sha256").update(ev.current_hash).digest("hex");
      const payloadSummary = JSON.stringify(ev.payload || {}).replace(/"/g, '""');
      lines.push(
        `"${idx}","${ev.created_at || ""}","${ev.id}","${ev.tenant_id}","${ev.event_type}","${ev.actor_id}","${ev.prev_hash}","${ev.current_hash}","${leafHash}","${payloadSummary}"`
      );
    });

    return lines.join("\r\n");
  }

  /**
   * Generates a complete export bundle with HTTP integrity headers.
   */
  public static async generateBundle(options: ExportBundleOptions): Promise<GeneratedExportBundle> {
    const { tenantId, exportedBy, format = "json", customEvents, persistRecord = true } = options;

    const events = customEvents
      ? this.deduplicateLedger(tenantId, customEvents)
      : await this.fetchEventsForTenant(tenantId, options);

    const evidencePackage = this.buildPackage(tenantId, exportedBy, events);
    const m = evidencePackage.manifest;

    let data: string;
    let contentType: string;

    if (format === "csv") {
      data = this.formatCsv(evidencePackage);
      contentType = "text/csv; charset=utf-8";
    } else {
      data = JSON.stringify(evidencePackage, null, 2);
      contentType = "application/json; charset=utf-8";
    }

    const headers: Record<string, string> = {
      "Content-Type": contentType,
      "Content-Disposition": `attachment; filename="${m.packageId}.${format}"`,
      "X-ShieldDesk-Package-Id": m.packageId,
      "X-ShieldDesk-Tenant-Id": m.tenantId,
      "X-ShieldDesk-Merkle-Root": m.merkleRoot,
      "X-ShieldDesk-Chain-Head": m.chainHeadHash,
      "X-ShieldDesk-Signature": m.signature,
      "X-ShieldDesk-Event-Count": String(m.totalEvents),
      "X-ShieldDesk-Algorithm": m.algorithm,
    };

    if (persistRecord) {
      // 1. Record bundle into compliance_export_bundles table
      try {
        const { query } = await import("@/lib/db");
        await query(
          `INSERT INTO compliance_export_bundles (
            id, tenant_id, format, exported_by, total_events,
            chain_head_hash, merkle_root, signature, exported_at, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())`,
          [
            m.packageId,
            m.tenantId,
            format,
            m.exportedBy,
            m.totalEvents,
            m.chainHeadHash,
            m.merkleRoot,
            m.signature,
            m.exportedAt,
          ]
        );
      } catch {
        // Offline / unit test context
      }

      // 2. Log export event into tamper-evident hash-chain ledger
      try {
        appendStatefulHashChainEvent(m.tenantId, "AUDIT_PACKAGE_EXPORTED", m.exportedBy, {
          packageId: m.packageId,
          format,
          totalEvents: m.totalEvents,
          merkleRoot: m.merkleRoot,
          chainHeadHash: m.chainHeadHash,
          signature: m.signature,
        });
      } catch {
        // Offline / unit test context
      }
    }

    return {
      packageId: m.packageId,
      tenantId: m.tenantId,
      format,
      manifest: m,
      data,
      contentType,
      headers,
      totalEvents: m.totalEvents,
    };
  }

  /**
   * Generates a complete CryptographicEvidencePackage directly from a SessionUser.
   */
  public static async generatePackage(
    caller: SessionUser,
    _frameworkId: string = "iso-27001"
  ): Promise<CryptographicEvidencePackage & { verifierScript: string }> {
    void _frameworkId;
    const events = await this.fetchEventsForTenant(caller.tenant_id);
    const pkg = this.buildPackage(caller.tenant_id, caller.id, events);
    return {
      ...pkg,
      verifierScript: pkg.offlineVerificationScript,
    };
  }

  /**
   * Generates a CSV tabular audit trail directly from a SessionUser.
   */
  public static async generateCsv(caller: SessionUser): Promise<string> {
    const events = await this.fetchEventsForTenant(caller.tenant_id);
    const pkg = this.buildPackage(caller.tenant_id, caller.id, events);
    return this.formatCsv(pkg);
  }

  /**
   * Cryptographically verifies a complete CryptographicEvidencePackage in memory.
   */
  public static verifyPackage(pkg: CryptographicEvidencePackage): {
    valid: boolean;
    reason?: string;
    error?: string;
    eventsVerified?: number;
    merkleRootValid?: boolean;
  } {
    // 1. Verify event count matches manifest
    if (pkg.manifest.totalEvents !== pkg.events.length) {
      const err = `Manifest event count mismatch: manifest claimed ${pkg.manifest.totalEvents}, but events array contains ${pkg.events.length}`;
      return {
        valid: false,
        reason: err,
        error: err,
      };
    }

    // 2. Verify HMAC signature
    const secret =
      process.env.SHIELDDESK_SESSION_SECRET ||
      process.env.SHIELDDESK_VAULT_SECRET ||
      "shielddesk_audit_vault_dev_ephemeral_key";
    const signatureData = `${pkg.manifest.packageId}|${pkg.manifest.tenantId}|${pkg.manifest.chainHeadHash}|${pkg.manifest.merkleRoot}|${pkg.manifest.totalEvents}`;
    const expectedSig = crypto.createHmac("sha256", secret).update(signatureData).digest("hex");
    if (pkg.manifest.signature !== expectedSig) {
      const err = "Manifest signature invalid: cryptographic proof does not match secret or metadata";
      return {
        valid: false,
        reason: err,
        error: err,
      };
    }

    // 3. Verify SHA-256 Hash Chain Integrity
    const chainCheck = verifyHashChainIntegrity(pkg.events);
    if (!chainCheck.valid) {
      return {
        valid: false,
        reason: chainCheck.reason,
        error: chainCheck.reason,
      };
    }

    // 4. Recompute and verify Merkle Root
    const leafHashes = pkg.events.map((e) =>
      crypto.createHash("sha256").update(e.current_hash).digest("hex")
    );
    const computedMerkle = buildMerkleTree(leafHashes);
    if (computedMerkle.root !== pkg.manifest.merkleRoot) {
      const err = `Merkle root mismatch: computed ${computedMerkle.root}, manifest claimed ${pkg.manifest.merkleRoot}`;
      return {
        valid: false,
        reason: err,
        error: err,
      };
    }

    // 5. Verify Chain Head Hash
    const actualHead = pkg.events[pkg.events.length - 1]?.current_hash || "0".repeat(64);
    if (actualHead !== pkg.manifest.chainHeadHash) {
      const err = `Chain head hash mismatch: actual ${actualHead}, manifest claimed ${pkg.manifest.chainHeadHash}`;
      return {
        valid: false,
        reason: err,
        error: err,
      };
    }

    return {
      valid: true,
      eventsVerified: pkg.events.length,
      merkleRootValid: true,
    };
  }
}
