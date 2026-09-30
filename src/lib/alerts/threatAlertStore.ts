import { randomUUID } from "crypto";

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
  allowedRecipients: Array<"dev-admin" | "dev-other">;
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
  const key = `${params.clientIp}:${params.targetUser.toLowerCase().trim()}`;
  const currentCount = (failureTracker.get(key) || 0) + 1;
  failureTracker.set(key, currentCount);

  // Escalate severity based on repetition
  let severity: "medium" | "high" | "critical" = params.severity || "medium";
  if (currentCount >= 3) {
    severity = "critical";
  } else if (currentCount >= 2) {
    severity = "high";
  }

  const alert: ThreatAlert = {
    id: `alt-${randomUUID().slice(0, 8)}`,
    type: currentCount >= 3 ? "brute_force_spike" : params.type || "auth_failure",
    severity,
    title:
      currentCount >= 3
        ? "CRITICAL SECURITY ALERT: Multiple Invalid Login Attempts Detected"
        : "SECURITY ALERT: Invalid Login Attempt Detected",
    description: `Consecutive failed login attempt (${currentCount}) for account '${params.targetUser}' from IP ${params.clientIp}`,
    targetUser: params.targetUser,
    clientIp: params.clientIp,
    failureReason: params.failureReason,
    attemptsCount: currentCount,
    // Only System Admin (dev-admin) and Globex Analyst (dev-other) receive this alert
    allowedRecipients: ["dev-admin", "dev-other"],
    status: "active",
    createdAt: new Date().toISOString(),
  };

  // Add to front of alerts list (max 50 alerts kept)
  alertsStore.unshift(alert);
  if (alertsStore.length > 50) {
    alertsStore.pop();
  }

  return alert;
}

/**
 * Retrieve active threat alerts authorized for the given persona/user ID.
 * Returns alerts ONLY if the user is 'dev-admin' or 'dev-other'.
 */
export function getThreatAlertsForUser(userId?: string | null): ThreatAlert[] {
  if (!userId) return [];

  // Strictly filter: Only System Admin and Globex Analyst can view auth alerts
  const isAuthorized = userId === "dev-admin" || userId === "dev-other";
  if (!isAuthorized) {
    return [];
  }

  return alertsStore.filter((a) => a.status === "active");
}

/**
 * Acknowledge or dismiss an alert
 */
export function acknowledgeThreatAlert(alertId: string, userId?: string | null): boolean {
  if (userId !== "dev-admin" && userId !== "dev-other") {
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
