import { NextRequest, NextResponse } from "next/server";
import { trackError } from "@/lib/observability/errorTracker";

function verifyScimBearer(req: NextRequest): { valid: boolean; tenantId: string } {
  const authHeader = req.headers.get("authorization");
  const expectedSecret = process.env.SCIM_BEARER_TOKEN || "scim-dev-bearer-token";
  
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return { valid: false, tenantId: "" };
  }
  const token = authHeader.substring(7).trim();
  if (token !== expectedSecret) {
    return { valid: false, tenantId: "" };
  }

  const tenantId = req.headers.get("x-shielddesk-tenant-id") || "acme-tenant";
  return { valid: true, tenantId };
}

const DEFAULT_GROUPS = [
  { id: "grp-soc-analysts", displayName: "SOC Analysts", members: [] },
  { id: "grp-incident-responders", displayName: "Incident Responders", members: [] },
  { id: "grp-security-leads", displayName: "Security Leads", members: [] },
];

/**
 * GET /api/scim/v2/Groups
 * SCIM 2.0 Groups Query (RFC 7644)
 */
export async function GET(req: NextRequest) {
  const auth = verifyScimBearer(req);
  if (!auth.valid) {
    return NextResponse.json({ schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], status: "401", detail: "Unauthorized" }, { status: 401 });
  }

  const resources = DEFAULT_GROUPS.map((g) => ({
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    id: g.id,
    displayName: g.displayName,
    members: g.members,
    meta: {
      resourceType: "Group",
      location: `/api/scim/v2/Groups/${g.id}`,
    },
  }));

  return NextResponse.json({
    schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    totalResults: resources.length,
    startIndex: 1,
    itemsPerPage: resources.length,
    Resources: resources,
  });
}
