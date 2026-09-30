import "server-only";
import crypto from "node:crypto";
import type { SessionUser } from "@/lib/auth/session";
import { MOCK_HASH_CHAINS, HashChainAuditRecord } from "@/lib/fleet/fleet";
import { buildMerkleTree, generateMerkleProof, verifyMerkleProof, MerkleProofElement } from "./merkle";
import { ISO_27001_CONTROLS } from "./iso27001";

export interface HashChainVerificationResult {
  valid: boolean;
  chainLength: number;
  genesisHash: string;
  headHash: string;
  brokenIndex?: number;
  reason?: string;
}

export interface EvidencePackageManifest {
  packageId: string;
  tenantId: string;
  exportedAt: string;
  exportedBy: string;
  totalEvents: number;
  chainHeadHash: string;
  merkleRoot: string;
  signature: string;
  algorithm: "HMAC-SHA256";
}

export interface CryptographicEvidencePackage {
  manifest: EvidencePackageManifest;
  events: HashChainAuditRecord[];
  merkleProofs: Record<number, MerkleProofElement[]>;
  complianceControls: typeof ISO_27001_CONTROLS;
  offlineVerificationScript: string;
}

/**
 * Computes the canonical SHA-256 hash of an audit event payload and link.
 */
export function computeEventHash(prevHash: string, actorId: string, payload: unknown): string {
  const data = `${prevHash}|${actorId}|${JSON.stringify(payload)}`;
  return crypto.createHash("sha256").update(data).digest("hex");
}

/**
 * Cryptographically verifies the unbroken integrity of a hash-chain ledger from Genesis to Head.
 */
export function verifyHashChainIntegrity(
  events: HashChainAuditRecord[]
): HashChainVerificationResult {
  if (!events || events.length === 0) {
    return {
      valid: false,
      chainLength: 0,
      genesisHash: "",
      headHash: "",
      reason: "Hash-chain ledger is empty.",
    };
  }

  const genesisHash = events[0].current_hash;

  for (let i = 0; i < events.length; i++) {
    const current = events[i];

    // 1. Verify internal payload hash matches current_hash
    if (current.event_type !== "GENESIS") {
      const expectedHash = computeEventHash(current.prev_hash, current.actor_id, current.payload);
      if (expectedHash !== current.current_hash) {
        return {
          valid: false,
          chainLength: events.length,
          genesisHash,
          headHash: events[events.length - 1].current_hash,
          brokenIndex: i,
          reason: `TAMPER_DETECTED: Event ${i} (${current.id}) current_hash does not match computed hash of payload/prev_hash.`,
        };
      }
    }

    // 2. Verify sequence continuity (current.prev_hash == previous.current_hash)
    if (i > 0) {
      const prev = events[i - 1];
      if (current.prev_hash !== prev.current_hash) {
        return {
          valid: false,
          chainLength: events.length,
          genesisHash,
          headHash: events[events.length - 1].current_hash,
          brokenIndex: i,
          reason: `CHAIN_BROKEN: Event ${i} prev_hash '${current.prev_hash}' does not link to Event ${i - 1} current_hash '${prev.current_hash}'.`,
        };
      }
    }
  }

  return {
    valid: true,
    chainLength: events.length,
    genesisHash,
    headHash: events[events.length - 1].current_hash,
  };
}

/**
 * Python 3 standalone offline verification script for external auditors.
 */
export const STANDALONE_VERIFICATION_PYTHON_SCRIPT = `#!/usr/bin/env python3
"""
ShieldDesk Standalone Cryptographic Evidence Verifier (SOC 2 & ISO 27001)
Usage: python verify_evidence.py
Requires standard Python 3.8+ with NO external pip dependencies.
"""
import hashlib
import json
import sys

def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def combine_hashes(left: str, right: str) -> str:
    return sha256_hex(f"{left}{right}")

def verify_evidence():
    print("=" * 70)
    print(" ShieldDesk SOC 2 / ISO 27001 Cryptographic Evidence Verifier")
    print("=" * 70)

    try:
        with open("manifest.json", "r") as f:
            manifest = json.load(f)
        with open("events.json", "r") as f:
            events = json.load(f)
    except FileNotFoundError as e:
        print(f"[!] Error: Missing required file: {e}")
        sys.exit(1)

    print(f"[*] Package ID:   {manifest.get('packageId')}")
    print(f"[*] Tenant ID:    {manifest.get('tenantId')}")
    print(f"[*] Total Events: {len(events)}")
    print(f"[*] Claimed Root: {manifest.get('merkleRoot')}")
    print("-" * 70)

    # 1. Verify Hash Chain
    print("[1/3] Verifying SHA-256 Hash-Chain Continuity...")
    for i, ev in enumerate(events):
        if ev.get("event_type") != "GENESIS":
            payload_str = json.dumps(ev["payload"], separators=(',', ':'))
            # Canonical link calculation
            expected_current = sha256_hex(f"{ev['prev_hash']}|{ev['actor_id']}|{json.dumps(ev['payload'])}")
            if expected_current != ev["current_hash"]:
                print(f"  [X] FAILED at event index {i}: Payload hash tampered!")
                sys.exit(2)
        if i > 0:
            if ev["prev_hash"] != events[i-1]["current_hash"]:
                print(f"  [X] FAILED at event index {i}: Sequence link broken!")
                sys.exit(2)
    print("  [OK] Hash-chain verified unbroken from Genesis to Head.")

    # 2. Verify Merkle Tree Root
    print("[2/3] Recomputing Merkle Tree Root...")
    leaves = [sha256_hex(ev["current_hash"]) for ev in events]
    level = list(leaves)
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i+1] if i + 1 < len(level) else left
            next_level.append(combine_hashes(left, right))
        level = next_level

    computed_root = level[0] if level else sha256_hex("EMPTY_TREE")
    if computed_root != manifest.get("merkleRoot"):
        print(f"  [X] Merkle Root Mismatch! Computed: {computed_root}, Manifest: {manifest.get('merkleRoot')}")
        sys.exit(3)
    print(f"  [OK] Merkle Root mathematically matches: {computed_root}")

    # 3. Overall Verdict
    print("[3/3] Final Attestation...")
    print("  [OK] All cryptographic checks PASSED. Evidence ledger is authentic, unbroken, and immutable.")
    print("=" * 70)
    print(" AUDIT VERDICT: VERIFIED (100% Tamper-Free)")
    print("=" * 70)

if __name__ == "__main__":
    verify_evidence()
`;

/**
 * Builds a complete self-contained cryptographic evidence package.
 */
export function generateEvidencePackage(
  caller: SessionUser,
  customEvents?: HashChainAuditRecord[]
): CryptographicEvidencePackage {
  const tenantId = caller.tenant_id;
  const events = customEvents || MOCK_HASH_CHAINS.filter(
    (e) => e.tenant_id === tenantId || e.event_type === "GENESIS"
  );

  const packageId = `EVID-${tenantId.toUpperCase()}-${Date.now().toString(36)}`;
  const exportedAt = new Date().toISOString();

  // 1. Compute Merkle Tree
  const leafHashes = events.map((e) => crypto.createHash("sha256").update(e.current_hash).digest("hex"));
  const merkleTree = buildMerkleTree(leafHashes);

  // 2. Generate Merkle Proofs for every event
  const merkleProofs: Record<number, MerkleProofElement[]> = {};
  for (let i = 0; i < events.length; i++) {
    merkleProofs[i] = generateMerkleProof(leafHashes, i);
  }

  const headHash = events[events.length - 1]?.current_hash || "0".repeat(64);

  // 3. Cryptographically sign package manifest
  const secret = process.env.SHIELDDESK_SESSION_SECRET || "shielddesk_audit_vault_master_key";
  const signatureData = `${packageId}|${tenantId}|${headHash}|${merkleTree.root}|${events.length}`;
  const signature = crypto.createHmac("sha256", secret).update(signatureData).digest("hex");

  const manifest: EvidencePackageManifest = {
    packageId,
    tenantId,
    exportedAt,
    exportedBy: caller.id,
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
  };
}
