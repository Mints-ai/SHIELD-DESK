import type { ShieldDeskRole } from "@/lib/permissions";

export interface OperatorIdentity {
  id: string;
  label: string;
  role: ShieldDeskRole;
  tenantId: string;
  tenantName: string;
  email: string;
  description: string;
}

const roleLabels: Record<ShieldDeskRole, string> = {
  system_admin: "System Admin", super_admin: "Super Admin", responder: "Responder", analyst: "Analyst",
};

export const SIGNED_OUT_OPERATOR: OperatorIdentity = {
  id: "", label: "Signed out", role: "analyst", tenantId: "", tenantName: "", email: "", description: "Sign in to access your workspace",
};

/** Display metadata derives only from the server-verified session. */
export function operatorFromSession(session: { uid: string; tenantId: string; role: ShieldDeskRole; email?: string }): OperatorIdentity {
  const role = Object.hasOwn(roleLabels, session.role) ? session.role : "analyst";
  return { id: session.uid, tenantId: session.tenantId, tenantName: session.tenantId, role, label: roleLabels[role], email: session.email || "", description: "Authenticated operator" };
}
