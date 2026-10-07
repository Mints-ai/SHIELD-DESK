import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { isDevPersonaAllowed } from "@/lib/config/environment";
import {
  getYaraRuleById,
  updateYaraRule,
  deleteYaraRule,
} from "@/lib/detection/yara/store";

export const dynamic = "force-dynamic";

async function resolveSession(req: NextRequest) {
  let session = await getSessionFromRequest(req);
  if (!session && isDevPersonaAllowed()) {
    const userHdr = req.headers.get("x-shielddesk-user") || "dev-admin";
    session = {
      uid: userHdr,
      role: userHdr.includes("admin") ? "system_admin" : "analyst",
      tenantId: "acme-tenant",
      email: `${userHdr}@acme.corp`,
    };
  }
  return session;
}

/**
 * PATCH /api/threats/yara/[id]
 * Updates rule status (enabled / disabled) or modifies metadata / raw content.
 */
export async function PATCH(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const session = await resolveSession(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await context.params;
  const body = await req.json().catch(() => ({}));

  try {
    const tenantId = session.tenantId || "acme-tenant";
    const existing = await getYaraRuleById(id, tenantId);
    if (!existing) {
      return NextResponse.json({ error: "Rule not found" }, { status: 404 });
    }

    const updated = await updateYaraRule(id, body, tenantId);
    return NextResponse.json({ success: true, rule: updated });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Failed to update rule";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}

/**
 * DELETE /api/threats/yara/[id]
 * Deletes custom rules. System rules (is_system = true) are protected and return 403.
 */
export async function DELETE(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const session = await resolveSession(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await context.params;
  const tenantId = session.tenantId || "acme-tenant";

  try {
    const existing = await getYaraRuleById(id, tenantId);
    if (!existing) {
      return NextResponse.json({ error: "Rule not found" }, { status: 404 });
    }

    if (existing.is_system) {
      return NextResponse.json(
        { error: "System default rules cannot be deleted" },
        { status: 403 }
      );
    }

    const res = await deleteYaraRule(id, tenantId);
    if (!res.success) {
      return NextResponse.json({ error: res.error || "Failed to delete" }, { status: 400 });
    }

    return NextResponse.json({ success: true, deletedId: id });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Failed to delete rule";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
