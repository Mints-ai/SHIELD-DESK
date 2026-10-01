import { randomUUID } from "crypto";
import { DEV_USERS, type DevUserId } from "@/lib/constants/devUsers";

export interface ThreatAlert {
  id: string;
  type: "auth_failure" | "brute_force_spike";
  severity: "medium" | "high" | "critical";
  title: string;
  description: string;
  targetUser: string;
  clientIp: string;
  failureReason: string;
  attemptsCount: number;
  allowedRecipients: string[];
  status: "active" | "acknowledged" | "resolved";
  createdAt: string;
}

// Global in-memory storage so alerts persist across requests in dev/Node runtime
declare global {
  // eslint-disable-next-line no-var
  var __shieldDeskThreatAlerts: ThreatAlert[] | undefined;
  // eslint-disable-next-line no-var
  var __shieldDeskRecentLoginFailures: Map<string, number> | undefined;
}

if (!global.__shieldDeskThreatAlerts) {
  global.__shieldDeskThreatAlerts = [];
}

if (!global.__shieldDeskRecentLoginFailures) {
  global.__shieldDeskRecentLoginFailures = new Map<string, number>();
}

const alertsStore = global.__shieldDeskThreatAlerts;
const failureTracker = global.__shieldDeskRecentLoginFailures;

/**
 * Determine if a user/persona is authorized to view or manage threat alerts.
 * Strictly restricted to System Admin (dev-admin / system_admin) and Globex Analyst (dev-other / globex-tenant).
 */
export function isUserAuthorizedForAlerts(userId?: string | null): boolean {
  if (!userId) return false;
  if (userId === "dev-admin" || userId === "dev-other") return true;
  const devUser = DEV_USERS[userId as DevUserId];
  if (devUser) {
    return devUser.role === "system_admin" || devUser.tenantId === "globex-tenant";
  }
  return false;
}

/**
 * Record an authentication failure alert in the Threat Engine store.
 * Automatically tracks consecutive failures per IP/email to escalate severity.
 */
export function recordThreatAlert(params: {
  targetUser: string;
  clientIp: string;
  failureReason: string;
  severity?: "medium" | "high" | "critical";
  type?: "auth_failure" | "brute_force_spike";
}): ThreatAlert {
  const cleanIp = params.clientIp === "::1" || !params.clientIp ? "127.0.0.1" : params.clientIp;
  const cleanEmail = (params.targetUser || "unknown").toLowerCase().trim();
  const key = `${cleanIp}:${cleanEmail}`;
  const currentCount = (failureTracker.get(key) || 0) + 1;
  failureTracker.set(key, currentCount);

  // Escalate severity based on repetition
  let severity: "medium" | "high" | "critical" = params.severity || "medium";
  if (currentCount >= 3) {
    severity = "critical";
  } else if (currentCount >= 2) {
    severity = "high";
  }

  const alertTitle =
    currentCount >= 3
      ? "CRITICAL SECURITY ALERT: Multiple Invalid Login Attempts Detected"
      : currentCount === 2
      ? "HIGH SEVERITY ALERT: Repeated Invalid Login Attempts Detected"
      : "SECURITY ALERT: Invalid Login Attempt Detected";

  const alertDescription = `Consecutive failed login attempt (${currentCount}) for account '${cleanEmail}' from IP ${cleanIp}`;

  // Check if an existing active alert for this email and IP exists
  const existingIndex = alertsStore.findIndex(
    (a) => a.status === "active" && a.targetUser.toLowerCase().trim() === cleanEmail && a.clientIp === cleanIp
  );

  let alert: ThreatAlert;

  if (existingIndex !== -1) {
    // Update existing active alert and move to front
    const [existing] = alertsStore.splice(existingIndex, 1);
    alert = {
      ...existing,
      type: currentCount >= 3 ? "brute_force_spike" : params.type || "auth_failure",
      severity,
      title: alertTitle,
      description: alertDescription,
      failureReason: params.failureReason,
      attemptsCount: currentCount,
      allowedRecipients: ["dev-admin", "dev-other"],
      createdAt: new Date().toISOString(),
    };
  } else {
    // Create new alert
    alert = {
      id: `alt-${randomUUID().slice(0, 8)}`,
      type: currentCount >= 3 ? "brute_force_spike" : params.type || "auth_failure",
      severity,
      title: alertTitle,
      description: alertDescription,
      targetUser: cleanEmail,
      clientIp: cleanIp,
      failureReason: params.failureReason,
      attemptsCount: currentCount,
      allowedRecipients: ["dev-admin", "dev-other"],
      status: "active",
      createdAt: new Date().toISOString(),
    };
  }

  // Add to front of alerts list (max 50 alerts kept)
  alertsStore.unshift(alert);
  if (alertsStore.length > 50) {
    alertsStore.pop();
  }

  return alert;
}

/**
 * Retrieve active threat alerts authorized for the given persona/user ID.
 * Returns alerts only for System Admin and Globex Analyst.
 */
export function getThreatAlertsForUser(userId?: string | null): ThreatAlert[] {
  if (!isUserAuthorizedForAlerts(userId)) {
    return [];
  }
  return alertsStore.filter((a) => a.status === "active");
}

/**
 * Acknowledge or dismiss an alert
 */
export function acknowledgeThreatAlert(alertId: string, userId?: string | null): boolean {
  if (!isUserAuthorizedForAlerts(userId)) {
    return false;
  }

  const alert = alertsStore.find((a) => a.id === alertId);
  if (alert) {
    alert.status = "acknowledged";
    return true;
  }
  return false;
}

/**
 * Clear or reset all threat alerts (for testing/demo)
 */
export function resetThreatAlerts(): void {
  alertsStore.length = 0;
  failureTracker.clear();
}
