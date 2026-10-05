import crypto from "node:crypto";
import { HashChainAuditRecord, MOCK_HASH_CHAINS, recordHashChainEvent } from "../fleet/fleet";
import { buildMerkleTree, generateMerkleProof, MerkleProofElement } from "./merkle";
import { ISO_27001_CONTROLS } from "./iso27001";
import {
  CryptographicEvidencePackage,
  EvidencePackageManifest,
  STANDALONE_VERIFICATION_PYTHON_SCRIPT,
  verifyHashChainIntegrity,
} from "./evidenceVault";

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
   * Retrieves audit events for a tenant from PostgreSQL hash_chain_audit,
   * falling back to in-memory fixtures when offline or in unit tests.
   */
  public static async fetchEventsForTenant(
    tenantId: string,
    options?: { limit?: number; startDate?: string; endDate?: string }
  ): Promise<HashChainAuditRecord[]> {
    try {
      const { query } = await import("../db");
      let sql = `SELECT id, tenant_id, event_type, actor_id, payload, prev_hash, current_hash, created_at
                 FROM hash_chain_audit
                 WHERE tenant_id = $1 OR event_type = 'GENESIS'`;
      const params: any[] = [tenantId];

      if (options?.startDate) {
        params.push(options.startDate);
        sql += ` AND created_at >= $${params.length}`;
      }
      if (options?.endDate) {
        params.push(options.endDate);
        sql += ` AND created_at <= $${params.length}`;
      }

      sql += ` ORDER BY id ASC`;
      if (options?.limit) {
        params.push(options.limit);
        sql += ` LIMIT $${params.length}`;
      }

      const res = await query<any>(sql, params);
      if (res.rows && res.rows.length > 0) {
        return res.rows.map((r: any) => ({
          id: String(r.id),
          tenant_id: r.tenant_id,
          event_type: r.event_type,
          actor_id: r.actor_id,
          payload: typeof r.payload === "string" ? JSON.parse(r.payload) : r.payload,
          prev_hash: r.prev_hash,
          current_hash: r.current_hash,
          created_at: r.created_at,
        }));
      }
    } catch {
      // In offline / test environment without DB connection
    }

    // Fallback to in-memory mock chain
    const filtered = MOCK_HASH_CHAINS.filter(
      (e) => e.tenant_id === tenantId || e.event_type === "GENESIS"
    );
    return filtered.length > 0 ? filtered : MOCK_HASH_CHAINS.slice(0, 10);
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

    const events = customEvents || (await this.fetchEventsForTenant(tenantId, options));
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
        const { query } = await import("../db");
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
        await recordHashChainEvent({
          tenantId: m.tenantId,
          eventType: "AUDIT_PACKAGE_EXPORTED",
          actorId: m.exportedBy,
          payload: {
            packageId: m.packageId,
            format,
            totalEvents: m.totalEvents,
            merkleRoot: m.merkleRoot,
            chainHeadHash: m.chainHeadHash,
            signature: m.signature,
          },
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
   * Cryptographically verifies a full evidence package for tamper-resistance.
   */
  public static verifyPackage(pkg: CryptographicEvidencePackage): {
    valid: boolean;
    reason?: string;
  } {
    // 1. Verify Hash-Chain Continuity
    const chainVerification = verifyHashChainIntegrity(pkg.events);
    if (!chainVerification.valid) {
      return { valid: false, reason: chainVerification.reason };
    }

    // 2. Recompute Merkle Root
    const leafHashes = pkg.events.map((e) =>
      crypto.createHash("sha256").update(e.current_hash).digest("hex")
    );
    const recomputedTree = buildMerkleTree(leafHashes);
    if (recomputedTree.root !== pkg.manifest.merkleRoot) {
      return {
        valid: false,
        reason: `Merkle Root mismatch! Expected: ${pkg.manifest.merkleRoot}, Recomputed: ${recomputedTree.root}`,
      };
    }

    // 3. Verify Event Count Consistency
    if (pkg.manifest.totalEvents !== pkg.events.length) {
      return {
        valid: false,
        reason: `Manifest event count mismatch! Manifest claims ${pkg.manifest.totalEvents}, but found ${pkg.events.length} events.`,
      };
    }

    // 4. Verify Manifest Signature
    const secret =
      process.env.SHIELDDESK_SESSION_SECRET ||
      process.env.SHIELDDESK_VAULT_SECRET ||
      "shielddesk_audit_vault_dev_ephemeral_key";

    const signatureData = `${pkg.manifest.packageId}|${pkg.manifest.tenantId}|${pkg.manifest.chainHeadHash}|${pkg.manifest.merkleRoot}|${pkg.manifest.totalEvents}`;
    const expectedSignature = crypto.createHmac("sha256", secret).update(signatureData).digest("hex");

    if (expectedSignature !== pkg.manifest.signature) {
      return {
        valid: false,
        reason: `Manifest HMAC signature invalid. Potential tampering in metadata or signing key mismatch.`,
      };
    }

    return { valid: true };
  }
}
