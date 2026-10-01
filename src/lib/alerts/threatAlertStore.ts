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
  isBlocked?: boolean;
  allowedRecipients: string[];
  status: "active" | "acknowledged" | "resolved";
  createdAt: string;
}

export interface BlockedIpRecord {
  ip: string;
  blockedAt: string;
  reason: string;
  attempts: number;
}

// Global in-memory storage so alerts persist across requests in dev/Node runtime
declare global {
  // eslint-disable-next-line no-var
  var __shieldDeskThreatAlerts: ThreatAlert[] | undefined;
  // eslint-disable-next-line no-var
  var __shieldDeskRecentLoginFailures: Map<string, number> | undefined;
  // eslint-disable-next-line no-var
  var __shieldDeskIpLoginFailures: Map<string, number> | undefined;
  // eslint-disable-next-line no-var
  var __shieldDeskBlockedIps: Map<string, BlockedIpRecord> | undefined;
}

if (!global.__shieldDeskThreatAlerts) {
  global.__shieldDeskThreatAlerts = [];
}

if (!global.__shieldDeskRecentLoginFailures) {
  global.__shieldDeskRecentLoginFailures = new Map<string, number>();
}

if (!global.__shieldDeskIpLoginFailures) {
  global.__shieldDeskIpLoginFailures = new Map<string, number>();
}

if (!global.__shieldDeskBlockedIps) {
  global.__shieldDeskBlockedIps = new Map<string, BlockedIpRecord>();
}

const alertsStore = global.__shieldDeskThreatAlerts;
const failureTracker = global.__shieldDeskRecentLoginFailures;
const ipFailureTracker = global.__shieldDeskIpLoginFailures;
const blockedIpsStore = global.__shieldDeskBlockedIps;

/**
 * Maximum allowed login failures before automatic IP containment kicks in
 */
export const MAX_LOGIN_ATTEMPTS_BEFORE_BLOCK = 5;

/**
 * Check if a given client IP is currently blocked
 */
export function isIpBlocked(ip?: string | null): boolean {
  if (!ip) return false;
  const cleanIp = ip === "::1" || !ip ? "127.0.0.1" : ip;
  return blockedIpsStore.has(cleanIp);
}

/**
 * Block a specific IP address
 */
export function blockIp(ip: string, reason: string = "Exceeded 5 failed login attempts", attempts: number = 6): void {
  const cleanIp = ip === "::1" || !ip ? "127.0.0.1" : ip;
  blockedIpsStore.set(cleanIp, {
    ip: cleanIp,
    blockedAt: new Date().toISOString(),
    reason,
    attempts,
  });
}

/**
 * Unblock a specific IP address and clear its failure records
 */
export function unblockIp(ip: string): boolean {
  const cleanIp = ip === "::1" || !ip ? "127.0.0.1" : ip;
  const deleted = blockedIpsStore.delete(cleanIp);
  ipFailureTracker.delete(cleanIp);
  for (const key of failureTracker.keys()) {
    if (key.startsWith(`${cleanIp}:`)) {
      failureTracker.delete(key);
    }
  }
  // Update any existing active alert for this IP
  for (const alert of alertsStore) {
    if (alert.clientIp === cleanIp) {
      alert.isBlocked = false;
    }
  }
  return deleted;
}

/**
 * Retrieve all currently blocked IPs
 */
export function getBlockedIps(): BlockedIpRecord[] {
  return Array.from(blockedIpsStore.values());
}

/**
 * Clear failed login attempts for a specific IP (e.g., on successful authentication)
 */
export function clearIpFailures(ip: string): void {
  const cleanIp = ip === "::1" || !ip ? "127.0.0.1" : ip;
  ipFailureTracker.delete(cleanIp);
  for (const key of failureTracker.keys()) {
    if (key.startsWith(`${cleanIp}:`)) {
      failureTracker.delete(key);
    }
  }
}

/**
 * Get current failure count for an IP
 */
export function getIpFailureCount(ip: string): number {
  const cleanIp = ip === "::1" || !ip ? "127.0.0.1" : ip;
  return ipFailureTracker.get(cleanIp) || 0;
}

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
 * Automatically tracks consecutive failures per IP/email to escalate severity
 * and triggers autonomous IP containment if failures exceed 5 attempts.
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

  // Track failures per IP across all target emails
  const ipFailures = (ipFailureTracker.get(cleanIp) || 0) + 1;
  ipFailureTracker.set(cleanIp, ipFailures);

  // Autonomous IP Containment: Block IP if failures exceed 5
  const isBlocked = ipFailures > MAX_LOGIN_ATTEMPTS_BEFORE_BLOCK;
  if (isBlocked && !blockedIpsStore.has(cleanIp)) {
    blockedIpsStore.set(cleanIp, {
      ip: cleanIp,
      blockedAt: new Date().toISOString(),
      reason: `Autonomous IP Containment: Exceeded ${MAX_LOGIN_ATTEMPTS_BEFORE_BLOCK} failed login attempts`,
      attempts: ipFailures,
    });
  }

  // Escalate severity based on repetition and blocking status
  let severity: "medium" | "high" | "critical" = params.severity || "medium";
  if (isBlocked || ipFailures >= 3 || currentCount >= 3) {
    severity = "critical";
  } else if (ipFailures >= 2 || currentCount >= 2) {
    severity = "high";
  }

  const alertTitle = isBlocked
    ? `CRITICAL SECURITY ALERT: Source IP ${cleanIp} Blocked (>5 Failed Logins)`
    : currentCount >= 3 || ipFailures >= 3
    ? "CRITICAL SECURITY ALERT: Multiple Invalid Login Attempts Detected"
    : currentCount === 2 || ipFailures === 2
    ? "HIGH SEVERITY ALERT: Repeated Invalid Login Attempts Detected"
    : "SECURITY ALERT: Invalid Login Attempt Detected";

  const alertDescription = isBlocked
    ? `Autonomous Containment Triggered: Source IP ${cleanIp} has been BLOCKED after ${ipFailures} failed login attempts.`
    : `Consecutive failed login attempt (${ipFailures}) for account '${cleanEmail}' from IP ${cleanIp}`;

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
      type: isBlocked || ipFailures >= 3 ? "brute_force_spike" : params.type || "auth_failure",
      severity,
      title: alertTitle,
      description: alertDescription,
      failureReason: isBlocked
        ? `IP Blocked (>5 attempts): ${params.failureReason}`
        : params.failureReason,
      attemptsCount: ipFailures,
      isBlocked,
      allowedRecipients: ["dev-admin", "dev-other"],
      createdAt: new Date().toISOString(),
    };
  } else {
    // Create new alert
    alert = {
      id: `alt-${randomUUID().slice(0, 8)}`,
      type: isBlocked || ipFailures >= 3 ? "brute_force_spike" : params.type || "auth_failure",
      severity,
      title: alertTitle,
      description: alertDescription,
      targetUser: cleanEmail,
      clientIp: cleanIp,
      failureReason: isBlocked
        ? `IP Blocked (>5 attempts): ${params.failureReason}`
        : params.failureReason,
      attemptsCount: ipFailures,
      isBlocked,
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
 * Clear or reset all threat alerts, failures, and unblock IPs (for testing/demo)
 */
export function resetThreatAlerts(): void {
  alertsStore.length = 0;
  failureTracker.clear();
  ipFailureTracker.clear();
  blockedIpsStore.clear();
}
