import type { SessionUser } from "@/lib/auth/session";

export interface CompliancePolicy {
  id: string;
  tenantId: string;
  policyCode: string;
  title: string;
  category: string;
  status: "active" | "draft" | "archived";
  version: string;
  description: string;
  documentUrl?: string;
  controlMappings: string[];
  uploadedBy: string;
  effectiveDate: string;
  reviewDate: string;
  createdAt: string;
  updatedAt: string;
}

const inMemoryPolicies = new Map<string, CompliancePolicy[]>();

export const DEFAULT_ENTERPRISE_POLICIES: Omit<CompliancePolicy, "id" | "tenantId" | "createdAt" | "updatedAt">[] = [
  {
    policyCode: "POL-SEC-01",
    title: "Incident Management & Cyber Response Plan",
    category: "Incident Response",
    status: "active",
    version: "2.4",
    description: "Standard operating procedure for deterministic triage, MITRE ATT&CK correlation, and 3-horizon mitigation execution.",
    controlMappings: ["A.5.24", "A.5.25", "A.5.26", "CC7.3", "RS.RP-01", "164.308(a)(6)"],
    uploadedBy: "chief-compliance-officer@shielddesk.internal",
    effectiveDate: "2026-01-01T00:00:00.000Z",
    reviewDate: "2027-01-01T00:00:00.000Z",
  },
  {
    policyCode: "POL-SEC-02",
    title: "Access Control & Separation of Duties Policy",
    category: "Identity & Access",
    status: "active",
    version: "3.1",
    description: "Mandates dual-custody approval gating (requested_by <> approved_by) for Tier 2 and Tier 3 destructive operations.",
    controlMappings: ["A.9.2", "CC6.1", "PR.AC-01", "164.312(a)(1)"],
    uploadedBy: "security-architect@shielddesk.internal",
    effectiveDate: "2026-01-01T00:00:00.000Z",
    reviewDate: "2027-01-01T00:00:00.000Z",
  },
  {
    policyCode: "POL-SEC-03",
    title: "Cryptographic Integrity & Audit Vault Standard",
    category: "Cryptography & Data",
    status: "active",
    version: "1.9",
    description: "Specifies SHA-256 hash-chaining, Merkle proof tree generation, and HMAC digital signatures for all operational ledgers.",
    controlMappings: ["A.5.28", "A.8.24", "CC6.2", "PR.DS-01", "164.312(c)(1)"],
    uploadedBy: "sec-ops-lead@shielddesk.internal",
    effectiveDate: "2026-01-01T00:00:00.000Z",
    reviewDate: "2027-01-01T00:00:00.000Z",
  },
  {
    policyCode: "POL-SEC-04",
    title: "Endpoint Protection & Malware Containment Standard",
    category: "Endpoint Security",
    status: "active",
    version: "2.0",
    description: "Governs universal endpoint agent telemetry, real-time YARA signature matching, memory-dump baselines, and SIGKILL containment.",
    controlMappings: ["A.8.7", "CC6.8", "DE.CM-01", "164.312(b)"],
    uploadedBy: "endpoint-sec@shielddesk.internal",
    effectiveDate: "2026-01-01T00:00:00.000Z",
    reviewDate: "2027-01-01T00:00:00.000Z",
  },
  {
    policyCode: "POL-SEC-05",
    title: "Vulnerability Management & Remediation SLA Policy",
    category: "Vulnerability Management",
    status: "active",
    version: "1.5",
    description: "Defines strict remediation SLAs: Critical CVSS 9.0+ within 7 days, High CVSS 7.0+ within 30 days, cross-referenced with CISA KEV.",
    controlMappings: ["A.8.8", "CC7.1", "ID.RA-01"],
    uploadedBy: "vulnerability-lead@shielddesk.internal",
    effectiveDate: "2026-01-01T00:00:00.000Z",
    reviewDate: "2027-01-01T00:00:00.000Z",
  },
];

function initializeInMemoryPolicies(tenantId: string): CompliancePolicy[] {
  const existing = inMemoryPolicies.get(tenantId);
  if (existing) return existing;

  const policies: CompliancePolicy[] = DEFAULT_ENTERPRISE_POLICIES.map((p, idx) => ({
    ...p,
    id: `pol-${tenantId}-${String(idx + 1).padStart(2, "0")}`,
    tenantId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }));

  inMemoryPolicies.set(tenantId, policies);
  return policies;
}

export async function listCompliancePolicies(caller: SessionUser): Promise<CompliancePolicy[]> {
  try {
    const { query } = await import("@/lib/db");
    const res = await query<Record<string, unknown>>(
      `SELECT id, tenant_id, policy_code, title, category, status, version,
              description, document_url, control_mappings, uploaded_by,
              effective_date, review_date, created_at, updated_at
       FROM compliance_policies
       WHERE tenant_id = $1
       ORDER BY policy_code ASC`,
      [caller.tenant_id]
    );

    if (res.rows && res.rows.length > 0) {
      return res.rows.map((r: Record<string, unknown>) => ({
        id: String(r.id),
        tenantId: String(r.tenant_id),
        policyCode: String(r.policy_code),
        title: String(r.title),
        category: String(r.category),
        status: (r.status as "active" | "draft" | "archived") || "active",
        version: String(r.version),
        description: String(r.description || ""),
        documentUrl: r.document_url ? String(r.document_url) : undefined,
        controlMappings: Array.isArray(r.control_mappings) ? (r.control_mappings as string[]) : [],
        uploadedBy: String(r.uploaded_by),
        effectiveDate: String(r.effective_date),
        reviewDate: String(r.review_date),
        createdAt: String(r.created_at),
        updatedAt: String(r.updated_at),
      }));
    }
  } catch {
    // Fail-open: database offline or migration pending
  }

  return initializeInMemoryPolicies(caller.tenant_id);
}

export async function getPoliciesForControl(
  caller: SessionUser,
  controlCode: string
): Promise<CompliancePolicy[]> {
  const all = await listCompliancePolicies(caller);
  return all.filter((p) =>
    p.controlMappings.some(
      (m) => m.toLowerCase() === controlCode.toLowerCase()
    )
  );
}

export async function createOrUpdatePolicy(
  caller: SessionUser,
  policy: {
    policyCode: string;
    title: string;
    category: string;
    description: string;
    version?: string;
    controlMappings: string[];
    documentUrl?: string;
  }
): Promise<CompliancePolicy> {
  const newPolicy: CompliancePolicy = {
    id: `pol-${caller.tenant_id}-${Date.now().toString(36)}`,
    tenantId: caller.tenant_id,
    policyCode: policy.policyCode,
    title: policy.title,
    category: policy.category,
    status: "active",
    version: policy.version || "1.0",
    description: policy.description,
    documentUrl: policy.documentUrl,
    controlMappings: policy.controlMappings,
    uploadedBy: caller.id,
    effectiveDate: new Date().toISOString(),
    reviewDate: new Date(Date.now() + 86400000 * 365).toISOString(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  try {
    const { query } = await import("@/lib/db");
    const res = await query<Record<string, unknown>>(
      `INSERT INTO compliance_policies (
        id, tenant_id, policy_code, title, category, status, version,
        description, document_url, control_mappings, uploaded_by,
        effective_date, review_date, created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
      ON CONFLICT (id) DO UPDATE SET
        title = EXCLUDED.title,
        category = EXCLUDED.category,
        description = EXCLUDED.description,
        version = EXCLUDED.version,
        control_mappings = EXCLUDED.control_mappings,
        document_url = EXCLUDED.document_url,
        updated_at = NOW()
      RETURNING *`,
      [
        newPolicy.id,
        newPolicy.tenantId,
        newPolicy.policyCode,
        newPolicy.title,
        newPolicy.category,
        newPolicy.status,
        newPolicy.version,
        newPolicy.description,
        newPolicy.documentUrl || null,
        newPolicy.controlMappings,
        newPolicy.uploadedBy,
        newPolicy.effectiveDate,
        newPolicy.reviewDate,
      ]
    );

    if (res.rows && res.rows[0]) {
      const r = res.rows[0];
      return {
        id: String(r.id),
        tenantId: String(r.tenant_id),
        policyCode: String(r.policy_code),
        title: String(r.title),
        category: String(r.category),
        status: (r.status as "active" | "draft" | "archived") || "active",
        version: String(r.version),
        description: String(r.description || ""),
        documentUrl: r.document_url ? String(r.document_url) : undefined,
        controlMappings: Array.isArray(r.control_mappings) ? (r.control_mappings as string[]) : [],
        uploadedBy: String(r.uploaded_by),
        effectiveDate: String(r.effective_date),
        reviewDate: String(r.review_date),
        createdAt: String(r.created_at),
        updatedAt: String(r.updated_at),
      };
    }
  } catch {
    // Fail-open: append to in-memory store
  }

  const list = initializeInMemoryPolicies(caller.tenant_id);
  list.push(newPolicy);
  return newPolicy;
}
