import { randomUUID } from "crypto";
import { DEV_USERS, type DevUserId } from "@/lib/constants/devUsers";
import { resetRateLimit } from "@/lib/security/rateLimit";

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
  // eslint-disable-next-line no-var
  var __shieldDeskFailureTimestamps: number[] | undefined;
  // eslint-disable-next-line no-var
  var __shieldDeskSudoTimestamps: number[] | undefined;
  // eslint-disable-next-line no-var
  var __shieldDeskEgressBursts: { timestamp: number; mb: number }[] | undefined;
  // eslint-disable-next-line no-var
  var __shieldDeskPIIMetrics: PIIScrubMetrics | undefined;
}

export interface PIIScrubMetrics {
  totalRedacted: number;
  categories: {
    jwt_tokens: number;
    passwords_and_secrets: number;
    credit_cards: number;
    ssn_and_national_ids: number;
    emails: number;
  };
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

if (!global.__shieldDeskFailureTimestamps) {
  global.__shieldDeskFailureTimestamps = [];
}

if (!global.__shieldDeskSudoTimestamps) {
  global.__shieldDeskSudoTimestamps = [];
}

if (!global.__shieldDeskEgressBursts) {
  global.__shieldDeskEgressBursts = [];
}

if (!global.__shieldDeskPIIMetrics) {
  global.__shieldDeskPIIMetrics = {
    totalRedacted: 0,
    categories: {
      jwt_tokens: 0,
      passwords_and_secrets: 0,
      credit_cards: 0,
      ssn_and_national_ids: 0,
      emails: 0,
    },
  };
}

const alertsStore = global.__shieldDeskThreatAlerts!;
const failureTracker = global.__shieldDeskRecentLoginFailures!;
const ipFailureTracker = global.__shieldDeskIpLoginFailures!;
const blockedIpsStore = global.__shieldDeskBlockedIps!;
const failureTimestamps = global.__shieldDeskFailureTimestamps!;
const sudoTimestamps = global.__shieldDeskSudoTimestamps!;
const egressBursts = global.__shieldDeskEgressBursts!;
const piiMetricsStore = global.__shieldDeskPIIMetrics!;

// Clear any stale local loopback containment from prior test iterations
if (blockedIpsStore.has("127.0.0.1")) {
  blockedIpsStore.delete("127.0.0.1");
}
if (ipFailureTracker.has("127.0.0.1")) {
  ipFailureTracker.delete("127.0.0.1");
}

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
 * Block a specific IP address and sync with Go Threat Engine
 */
export function blockIp(ip: string, reason: string = "Exceeded 5 failed login attempts", attempts: number = 6, tenantId: string = "acme-tenant"): void {
  const cleanIp = ip === "::1" || !ip ? "127.0.0.1" : ip;
  blockedIpsStore.set(cleanIp, {
    ip: cleanIp,
    blockedAt: new Date().toISOString(),
    reason,
    attempts,
  });

  // Sync to Go Threat Microservice asynchronously
  const threatServiceUrl = process.env.THREAT_SERVICE_URL || "http://localhost:8003";
  fetch(`${threatServiceUrl}/api/threats/containment`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      action: "block_ip",
      tenant_id: tenantId,
      ip: cleanIp,
      reason,
    }),
    signal: AbortSignal.timeout(600),
  }).catch(() => {});
}

/**
 * Unblock a specific IP address and clear its failure records
 */
export function unblockIp(ip: string, tenantId: string = "acme-tenant"): boolean {
  const cleanIp = ip === "::1" || !ip ? "127.0.0.1" : ip;
  const deleted = blockedIpsStore.delete(cleanIp);
  ipFailureTracker.delete(cleanIp);
  resetRateLimit(`login:${cleanIp}`);
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

  // Sync to Go Threat Microservice asynchronously
  const threatServiceUrl = process.env.THREAT_SERVICE_URL || "http://localhost:8003";
  fetch(`${threatServiceUrl}/api/threats/containment`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      action: "unblock_ip",
      tenant_id: tenantId,
      ip: cleanIp,
    }),
    signal: AbortSignal.timeout(600),
  }).catch(() => {});

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
 * Record failure timestamp(s) for the sliding window rate calculation.
 */
export function recordFailureTimestamp(timestamp: number = Date.now(), count: number = 1): void {
  for (let i = 0; i < count; i++) {
    failureTimestamps.push(timestamp);
  }
  const threatServiceUrl = process.env.THREAT_SERVICE_URL || "http://localhost:8003";
  fetch(`${threatServiceUrl}/api/threats/simulate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: "auth_failure", count, tenant_id: "acme-tenant" }),
    signal: AbortSignal.timeout(500),
  }).catch(() => {});
}

/**
 * Returns the live login failure rate (failures in the last 60 seconds).
 * Prunes timestamps older than 60 seconds.
 */
export function getLiveFailureRatePerMin(): number {
  const cutoff = Date.now() - 60_000;
  let writeIdx = 0;
  for (let readIdx = 0; readIdx < failureTimestamps.length; readIdx++) {
    if (failureTimestamps[readIdx] > cutoff) {
      failureTimestamps[writeIdx] = failureTimestamps[readIdx];
      writeIdx++;
    }
  }
  failureTimestamps.length = writeIdx;
  return failureTimestamps.length;
}

/**
 * Record sudo execution timestamp(s) for the sliding window rate calculation.
 */
export function recordSudoExecution(count: number = 1): void {
  const now = Date.now();
  for (let i = 0; i < count; i++) {
    sudoTimestamps.push(now);
  }
  const threatServiceUrl = process.env.THREAT_SERVICE_URL || "http://localhost:8003";
  fetch(`${threatServiceUrl}/api/threats/simulate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: "sudo_burst", count, tenant_id: "acme-tenant" }),
    signal: AbortSignal.timeout(500),
  }).catch(() => {});
}

/**
 * Returns the live sudo command execution rate (executions in the last 60 seconds).
 * Prunes timestamps older than 60 seconds.
 */
export function getLiveSudoRatePerMin(): number {
  const cutoff = Date.now() - 60_000;
  let writeIdx = 0;
  for (let readIdx = 0; readIdx < sudoTimestamps.length; readIdx++) {
    if (sudoTimestamps[readIdx] > cutoff) {
      sudoTimestamps[writeIdx] = sudoTimestamps[readIdx];
      writeIdx++;
    }
  }
  sudoTimestamps.length = writeIdx;
  return sudoTimestamps.length;
}

/**
 * Record network egress volume in MB for sliding window calculations.
 */
export function recordNetworkEgress(mb: number, timestamp: number = Date.now()): void {
  egressBursts.push({ timestamp, mb });
  const threatServiceUrl = process.env.THREAT_SERVICE_URL || "http://localhost:8003";
  fetch(`${threatServiceUrl}/api/threats/simulate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: "egress_spike", mb, tenant_id: "acme-tenant" }),
    signal: AbortSignal.timeout(500),
  }).catch(() => {});
}

/**
 * Returns the live outbound network egress rate in MB/min.
 * Combines sliding-window telemetry bursts with smooth baseline variance.
 */
export function getLiveEgressRateMBPerMin(): { current_value: number; is_anomaly: boolean } {
  const cutoff = Date.now() - 60_000;
  let writeIdx = 0;
  let burstMb = 0;
  for (let readIdx = 0; readIdx < egressBursts.length; readIdx++) {
    if (egressBursts[readIdx].timestamp > cutoff) {
      egressBursts[writeIdx] = egressBursts[readIdx];
      burstMb += egressBursts[readIdx].mb;
      writeIdx++;
    }
  }
  egressBursts.length = writeIdx;

  // Pure real data: actual MB transferred in the last 60 seconds (0.0 when idle)
  const actualMb = Math.round(burstMb * 10) / 10;
  return {
    current_value: actualMb,
    is_anomaly: actualMb > 215.0,
  };
}

/**
 * Determine if a user/persona is authorized to view or manage threat alerts.
 * Restricted to system_admin and super_admin roles only.
 */
export function isUserAuthorizedForAlerts(userId?: string | null): boolean {
  if (!userId) return false;
  const devUser = DEV_USERS[userId as DevUserId];
  if (devUser) {
    return devUser.role === "system_admin" || devUser.role === "super_admin";
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
  recordFailureTimestamp();

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
      allowedRecipients: ["dev-admin"],
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
      allowedRecipients: ["dev-admin"],
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
 * Reset all live sliding-window anomaly telemetry buffers back to nominal baseline.
 * Also removes synthetic simulated burst alerts and notifies Go Threat service.
 */
export function resetAnomalyBaselines(tenantId: string = "acme-tenant"): void {
  failureTimestamps.length = 0;
  sudoTimestamps.length = 0;
  egressBursts.length = 0;

  // Remove synthetic anomaly alerts from active alerts store
  const filtered = alertsStore.filter(
    (a) =>
      !a.failureReason.toLowerCase().includes("synthetic anomaly") &&
      !a.title.toLowerCase().includes("synthetic")
  );
  alertsStore.length = 0;
  alertsStore.push(...filtered);

  // Sync reset to Go Threat Microservice
  const threatServiceUrl = process.env.THREAT_SERVICE_URL || "http://localhost:8003";
  fetch(`${threatServiceUrl}/api/threats/reset`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tenant_id: tenantId }),
    signal: AbortSignal.timeout(600),
  }).catch(() => {});
}

/**
 * Clear or reset all threat alerts, failures, and unblock IPs (for testing/demo)
 */
export function resetThreatAlerts(tenantId: string = "acme-tenant"): void {
  alertsStore.length = 0;
  failureTracker.clear();
  ipFailureTracker.clear();
  blockedIpsStore.clear();
  failureTimestamps.length = 0;
  sudoTimestamps.length = 0;
  egressBursts.length = 0;

  // Sync reset to Go Threat Microservice
  const threatServiceUrl = process.env.THREAT_SERVICE_URL || "http://localhost:8003";
  fetch(`${threatServiceUrl}/api/threats/reset`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tenant_id: tenantId }),
    signal: AbortSignal.timeout(600),
  }).catch(() => {});
  resetPIIMetrics();
}

/**
 * Returns a live snapshot of in-memory PII scrubbing metrics
 */
export function getLivePIIMetrics(): PIIScrubMetrics {
  return {
    totalRedacted: piiMetricsStore.totalRedacted,
    categories: { ...piiMetricsStore.categories },
  };
}

/**
 * Record redacted PII token occurrences in memory
 */
export function recordScrubbedPII(counts: Partial<PIIScrubMetrics["categories"]>): PIIScrubMetrics {
  const jwt = counts.jwt_tokens || 0;
  const pass = counts.passwords_and_secrets || 0;
  const cc = counts.credit_cards || 0;
  const ssn = counts.ssn_and_national_ids || 0;
  const emails = counts.emails || 0;
  const sum = jwt + pass + cc + ssn + emails;

  piiMetricsStore.totalRedacted += sum;
  piiMetricsStore.categories.jwt_tokens += jwt;
  piiMetricsStore.categories.passwords_and_secrets += pass;
  piiMetricsStore.categories.credit_cards += cc;
  piiMetricsStore.categories.ssn_and_national_ids += ssn;
  piiMetricsStore.categories.emails += emails;

  return getLivePIIMetrics();
}

/**
 * Reset live PII counters
 */
export function resetPIIMetrics(): void {
  piiMetricsStore.totalRedacted = 0;
  piiMetricsStore.categories = {
    jwt_tokens: 0,
    passwords_and_secrets: 0,
    credit_cards: 0,
    ssn_and_national_ids: 0,
    emails: 0,
  };
}

/**
 * Real in-flight PII scrubber for telemetry payloads (matches Go pii.go tokenizers)
 */
export function scrubTelemetryPayload(payload: Record<string, string>): {
  cleaned: Record<string, string>;
  redactedCount: number;
  categories: Partial<PIIScrubMetrics["categories"]>;
} {
  const emailRegex = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
  const ccRegex = /\b(?:\d{4}[-\s]?){3}\d{4}\b/g;
  const jwtRegex = /\beyJ[a-zA-Z0-9_\-.]+\.[a-zA-Z0-9_\-.]+\.[a-zA-Z0-9_\-.]+\b/g;
  const bearerRegex = /bearer\s+[a-zA-Z0-9_\-.]{20,}/gi;
  const sensitiveKeys = new Set([
    "password", "passwd", "secret", "private_key", "credit_card",
    "ssn", "token", "api_key", "authorization", "cookie"
  ]);

  let passCount = 0;
  let emailCount = 0;
  let ccCount = 0;
  let jwtCount = 0;
  const cleaned: Record<string, string> = {};

  for (const [k, v] of Object.entries(payload)) {
    const lowerKey = k.toLowerCase();
    if (sensitiveKeys.has(lowerKey)) {
      cleaned[k] = "[REDACTED_SENSITIVE_KEY]";
      passCount++;
      continue;
    }

    let val = String(v);
    const emailsFound = val.match(emailRegex);
    if (emailsFound) {
      emailCount += emailsFound.length;
      val = val.replace(emailRegex, "[REDACTED_EMAIL]");
    }
    const ccFound = val.match(ccRegex);
    if (ccFound) {
      ccCount += ccFound.length;
      val = val.replace(ccRegex, "[REDACTED_CREDIT_CARD]");
    }
    const jwtFound = val.match(jwtRegex);
    if (jwtFound) {
      jwtCount += jwtFound.length;
      val = val.replace(jwtRegex, "[REDACTED_JWT]");
    }
    const bearerFound = val.match(bearerRegex);
    if (bearerFound) {
      passCount += bearerFound.length;
      val = val.replace(bearerRegex, "[REDACTED_BEARER]");
    }
    cleaned[k] = val;
  }

  const catCounts = {
    jwt_tokens: jwtCount,
    passwords_and_secrets: passCount,
    credit_cards: ccCount,
    emails: emailCount,
  };

  recordScrubbedPII(catCounts);

  return {
    cleaned,
    redactedCount: passCount + emailCount + ccCount + jwtCount,
    categories: catCounts,
  };
}

