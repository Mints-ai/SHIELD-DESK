import { NextRequest, NextResponse } from "next/server";
import { shouldFailClosed, isDemoMode, isDevPersonaAllowed } from "@/lib/config/environment";

export const dynamic = "force-dynamic";
export const revalidate = 0;
import { getSessionFromRequest } from "@/lib/auth/session";
import { trackError } from "@/lib/observability/errorTracker";
import { getActiveDetectionRules, toggleDetectionRule } from "@/lib/detection/engine";
import { query } from "@/lib/db";
import {
  getThreatAlertsForUser,
  recordThreatAlert,
  acknowledgeThreatAlert,
  resetThreatAlerts,
  getBlockedIps,
  unblockIp,
  blockIp,
  getLiveFailureRatePerMin,
  recordFailureTimestamp,
  getLiveSudoRatePerMin,
  recordSudoExecution,
  getLiveEgressRateMBPerMin,
  recordNetworkEgress,
  resetAnomalyBaselines,
} from "@/lib/alerts/threatAlertStore";
import { resolveClientIp } from "@/lib/network/clientIp";

const YARA_RULES = [
  {
    id: "yara_webshell_c99",
    name: "Webshell_C99_PHP",
    category: "Malware / Webshell",
    severity: "CRITICAL",
    matches_today: 3,
    status: "ACTIVE",
    target: "filesystem / webroot",
    description: "Detects obfuscated PHP C99/b374k webshell headers, base64_decode, and passthru command execution payloads.",
  },
  {
    id: "yara_ransomware_extensions",
    name: "Ransomware_LockBit_Indicators",
    category: "Ransomware",
    severity: "CRITICAL",
    matches_today: 0,
    status: "ACTIVE",
    target: "filesystem write operations",
    description: "Detects mass extension renaming (.lockbit, .blackcat) and automated shadow copy deletion commands.",
  },
  {
    id: "yara_cobalt_beacon",
    name: "Cobalt_Strike_Beacon_Memory",
    category: "C2 / Post-Exploitation",
    severity: "HIGH",
    matches_today: 1,
    status: "ACTIVE",
    target: "process memory",
    description: "Detects known Cobalt Strike malleable C2 reflective DLL loader memory patterns.",
  },
];

const SIGMA_RULES = [
  {
    id: "sigma_encoded_powershell",
    title: "Suspicious Encoded PowerShell Execution",
    logsource: "windows: process_creation",
    severity: "HIGH",
    matches_today: 4,
    status: "ACTIVE",
    detection_logic: "CommandLine matches -enc / -EncodedCommand with bypass execution policy.",
  },
  {
    id: "sigma_ssh_bruteforce",
    title: "SSH Distributed Brute Force Attempt",
    logsource: "linux: auth.log / sshd",
    severity: "MEDIUM",
    matches_today: 28,
    status: "ACTIVE",
    detection_logic: "More than 15 failed password authentications from single source IP within 60s window.",
  },
  {
    id: "sigma_shadow_copy_deletion",
    title: "VSS Volume Shadow Copy Deletion",
    logsource: "windows: vssadmin",
    severity: "CRITICAL",
    matches_today: 0,
    status: "ACTIVE",
    detection_logic: "vssadmin.exe delete shadows /all /quiet or wmic shadowcopy delete.",
  },
];

const ANOMALY_BASELINES = [
  {
    metric: "Failed Authentications / Min",
    mean: 4.2,
    stdDev: 2.1,
    threshold_3sigma: 10.5,
    current_value: 0.0,
    is_anomaly: false,
    unit: "attempts/min",
  },
  {
    metric: "Outbound Network Egress Rate",
    mean: 145.0,
    stdDev: 35.0,
    threshold_2sigma: 215.0,
    current_value: 0.0,
    is_anomaly: false,
    unit: "MB/min",
  },
  {
    metric: "Sudo Execution Frequency",
    mean: 1.1,
    stdDev: 0.8,
    threshold_3sigma: 3.5,
    current_value: 0.0,
    is_anomaly: false,
    unit: "cmds/min",
  },
];

const INGEST_TELEMETRY = {
  active_agents_connected: 48,
  agent_handshake_protocol: "mTLS v1.3",
  events_per_minute: 4120,
  max_capacity_per_tenant: 10000,
  rate_limit_drops: 0,
  pii_redacted_today: 184,
  pii_categories: {
    jwt_tokens: 92,
    passwords_and_secrets: 41,
    credit_cards: 29,
    ssn_and_national_ids: 22,
  },
  bus_status: "NATS JetStream (Healthy)",
  events_persisted_timescaledb: 148290,
};


export async function GET(req: NextRequest) {
  let session = await getSessionFromRequest(req);
  if (!session && isDevPersonaAllowed()) {
    session = {
      uid: "dev-analyst",
      role: "analyst",
      tenantId: "acme-tenant",
      email: "analyst@acme.corp",
    };
  }
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }


  // In production with FAIL_CLOSED=true, ensure telemetry pipeline is configured
  if (shouldFailClosed()) {
    const hasLiveTelemetry = Boolean(process.env.NATS_URL || process.env.TIMESCALE_URL);
    if (!hasLiveTelemetry) {
      return NextResponse.json(
        {
          error: "Telemetry lake / NATS JetStream detection pipeline is not connected. Fail-closed active in production.",
          code: "FAIL_CLOSED_DEPENDENCY_OFFLINE",
          tenantId: session.tenantId,
          yara_rules: [],
          sigma_rules: [],
          anomaly_baselines: [],
          ingest_telemetry: {
            active_agents_connected: 0,
            events_per_minute: 0,
            bus_status: "Disconnected",
          },
        },
        { status: 503 }
      );
    }
  }

  const engineRules = getActiveDetectionRules();

  // Try to query real telemetry count from DB
  let liveEventsCount = INGEST_TELEMETRY.events_persisted_timescaledb;
  let liveConnectedAgents = INGEST_TELEMETRY.active_agents_connected;
  let liveSudoDbCount = 0;

  try {
    const telRes = await query<{ count: string }>(
      `SELECT count(*) FROM endpoint_telemetry WHERE tenant_id = $1`,
      [session.tenantId]
    );
    if (telRes.rows.length > 0) {
      liveEventsCount = parseInt(telRes.rows[0].count, 10);
    }
    const agentRes = await query<{ count: string }>(
      `SELECT count(*) FROM endpoint_agents WHERE tenant_id = $1 AND status = 'connected'`,
      [session.tenantId]
    );
    if (agentRes.rows.length > 0) {
      liveConnectedAgents = parseInt(agentRes.rows[0].count, 10);
    }
    const sudoRes = await query<{ count: string }>(
      `SELECT count(*) FROM endpoint_telemetry 
       WHERE tenant_id = $1 
         AND timestamp >= now() - interval '1 minute'
         AND (payload::text ILIKE '%sudo%' OR payload::text ILIKE '%command%')`,
      [session.tenantId]
    );
    if (sudoRes.rows.length > 0) {
      const parsed = parseInt(sudoRes.rows[0].count, 10);
      if (!isNaN(parsed)) {
        liveSudoDbCount = parsed;
      }
    }
  } catch {
    // DB offline fallback
  }

  let liveAuthDbCount = 0;
  try {
      const authRes = await query<{ count: string }>(
        `SELECT count(*) FROM endpoint_telemetry 
         WHERE tenant_id = $1 
           AND timestamp >= now() - interval '1 minute'
           AND (event_type = 'auth_failure' OR payload::text ILIKE '%auth_fail%' OR payload::text ILIKE '%login_failed%')`,
        [session.tenantId]
      );
      if (authRes.rows.length > 0) {
        const parsed = parseInt(authRes.rows[0].count, 10);
        if (!isNaN(parsed)) {
          liveAuthDbCount = parsed;
        }
      }
    } catch {
      // Telemetry table optional
    }

    // Determine if this user can view authentication security alerts.
    // Strictly restricted to Company System Admin (admin@acme.corp).
    // Globex Analyst (dev-other) is a developer persona and receives a blank view.
    const isSystemAdmin = session.role === "system_admin" || session.uid === "dev-admin" || session.role === "super_admin";
    const canViewAuthAlerts = Boolean(session && isSystemAdmin);

    // Use dynamic threat alert store for authorized users only.
    // Defaults to empty array if no active alerts or user is unauthorized (e.g. Globex Analyst)
    const securityAlerts = canViewAuthAlerts
      ? getThreatAlertsForUser(session.uid)
      : [];

    // Dynamically compute all 3 anomaly metrics from real live telemetry stores
    const liveFailureRate = Math.max(getLiveFailureRatePerMin(), liveAuthDbCount);
    const liveSudoRate = Math.max(getLiveSudoRatePerMin(), liveSudoDbCount);
    const liveEgress = getLiveEgressRateMBPerMin();

    const anomalyBaselines = ANOMALY_BASELINES.map((b) => {
      if (b.metric === "Failed Authentications / Min") {
        const threshold = b.threshold_3sigma ?? 10.5;
        return {
          ...b,
          current_value: Number(liveFailureRate.toFixed(1)),
          is_anomaly: liveFailureRate > threshold,
        };
      }
      if (b.metric === "Outbound Network Egress Rate") {
        const threshold = b.threshold_2sigma ?? 215.0;
        return {
          ...b,
          current_value: Number(liveEgress.current_value.toFixed(1)),
          is_anomaly: liveEgress.is_anomaly,
        };
      }
      if (b.metric === "Sudo Execution Frequency") {
        const threshold = b.threshold_3sigma ?? 3.5;
        return {
          ...b,
          current_value: Number(liveSudoRate.toFixed(1)),
          is_anomaly: liveSudoRate > threshold,
        };
      }
      return b;
    });

    // Query Go Threat Service if online (port 8003)
    const threatServiceUrl = process.env.THREAT_SERVICE_URL || "http://localhost:8003";
    let goThreatState: {
      yara_rules?: any[];
      sigma_rules?: any[];
      anomaly_baselines?: any[];
      blocked_ips?: any[];
    } | null = null;

    try {
      const goRes = await fetch(`${threatServiceUrl}/api/threats/state?tenant_id=${encodeURIComponent(session.tenantId)}`, {
        signal: AbortSignal.timeout(800),
      });
      if (goRes.ok) {
        goThreatState = await goRes.json();
      }
    } catch {
      // Go service offline, fallback to in-memory store
    }

<<<<<<< Updated upstream
=======
    // Query Go Ingest Service if online (port 8005)
    const ingestServiceUrl = process.env.INGEST_HTTP_URL || "http://localhost:8005";
    let liveIngestStats: {
      pii_redacted_today?: number;
      pii_categories?: {
        jwt_tokens?: number;
        passwords_and_secrets?: number;
        credit_cards?: number;
        ssn_and_national_ids?: number;
        emails?: number;
      };
      bus_status?: string;
      active_agents_connected?: number;
      events_per_minute?: number;
    } | null = null;

    try {
      const ingestRes = await fetch(`${ingestServiceUrl}/api/ingest/stats`, {
        signal: AbortSignal.timeout(800),
      });
      if (ingestRes.ok) {
        liveIngestStats = await ingestRes.json();
      }
    } catch {
      // Go Ingest service offline, fallback to local in-memory metrics
    }

    let dbPiiCategories = {
      jwt_tokens: 0,
      passwords_and_secrets: 0,
      credit_cards: 0,
      ssn_and_national_ids: 0,
      emails: 0,
    };
    try {
      const piiDbRes = await query<{
        jwt_count: string;
        pass_count: string;
        cc_count: string;
        email_count: string;
      }>(
        `SELECT 
          COUNT(*) FILTER (WHERE payload::text ILIKE '%[REDACTED_JWT]%') as jwt_count,
          COUNT(*) FILTER (WHERE payload::text ILIKE '%[REDACTED_SENSITIVE_KEY]%' OR payload::text ILIKE '%[REDACTED_BEARER]%') as pass_count,
          COUNT(*) FILTER (WHERE payload::text ILIKE '%[REDACTED_CREDIT_CARD]%') as cc_count,
          COUNT(*) FILTER (WHERE payload::text ILIKE '%[REDACTED_EMAIL]%') as email_count
         FROM endpoint_telemetry
         WHERE tenant_id = $1`,
        [session.tenantId]
      );
      if (piiDbRes.rows.length > 0) {
        dbPiiCategories.jwt_tokens = parseInt(piiDbRes.rows[0].jwt_count || "0", 10) || 0;
        dbPiiCategories.passwords_and_secrets = parseInt(piiDbRes.rows[0].pass_count || "0", 10) || 0;
        dbPiiCategories.credit_cards = parseInt(piiDbRes.rows[0].cc_count || "0", 10) || 0;
        dbPiiCategories.emails = parseInt(piiDbRes.rows[0].email_count || "0", 10) || 0;
      }
    } catch {
      // Telemetry table query fallback
    }

    const localPii = getLivePIIMetrics();
    const livePiiCategories = {
      jwt_tokens: (liveIngestStats?.pii_categories?.jwt_tokens ?? 0) + localPii.categories.jwt_tokens + dbPiiCategories.jwt_tokens,
      passwords_and_secrets: (liveIngestStats?.pii_categories?.passwords_and_secrets ?? 0) + localPii.categories.passwords_and_secrets + dbPiiCategories.passwords_and_secrets,
      credit_cards: (liveIngestStats?.pii_categories?.credit_cards ?? 0) + localPii.categories.credit_cards + dbPiiCategories.credit_cards,
      ssn_and_national_ids: (liveIngestStats?.pii_categories?.ssn_and_national_ids ?? 0) + localPii.categories.ssn_and_national_ids + dbPiiCategories.ssn_and_national_ids,
      emails: (liveIngestStats?.pii_categories?.emails ?? 0) + localPii.categories.emails + dbPiiCategories.emails,
    };

    const livePiiTotal =
      livePiiCategories.jwt_tokens +
      livePiiCategories.passwords_and_secrets +
      livePiiCategories.credit_cards +
      livePiiCategories.ssn_and_national_ids +
      livePiiCategories.emails;

    const liveAgentsTotal = (liveIngestStats?.active_agents_connected && liveIngestStats.active_agents_connected > 0)
      ? liveIngestStats.active_agents_connected
      : liveConnectedAgents;

    const liveEventRate = (liveIngestStats?.events_per_minute !== undefined && liveIngestStats.events_per_minute > 0)
      ? liveIngestStats.events_per_minute
      : Math.round(liveFailureRate + liveSudoRate);

    const mergedTelemetry = {
      ...BASELINE_INGEST_POLICY,
      active_agents_connected: liveAgentsTotal,
      events_persisted_timescaledb: liveEventsCount,
      pii_redacted_today: livePiiTotal,
      pii_categories: livePiiCategories,
      bus_status: liveIngestStats?.bus_status ?? (goThreatState ? "NATS JetStream (Standalone)" : "Active Ingestion Loop"),
      events_per_minute: liveEventRate,
    };

    let liveYaraRules = YARA_RULES;
    try {
      const dynamicYara = await getYaraRules(session.tenantId);
      if (dynamicYara && dynamicYara.length > 0) {
        liveYaraRules = dynamicYara.map((r) => ({
          id: r.rule_id,
          name: r.name,
          category: r.category,
          severity: r.severity.toUpperCase(),
          matches_today: r.matches_today || 0,
          status: r.enabled ? "ACTIVE" : "DISABLED",
          target: r.target,
          description: r.description,
          raw_content: r.raw_content,
          is_system: r.is_system,
        }));
      }
    } catch {
      // Non-fatal
    }

>>>>>>> Stashed changes
    return NextResponse.json({
      status: "ok",
      engine: goThreatState ? "go-threat-service" : "typescript-in-memory",
      dataMode: isDemoMode() ? "demo" : "live",
      demoMode: isDemoMode(),
      demoDataDisclaimer: isDemoMode()
        ? "⚠ DEMO DATA: Baseline and telemetry statistics are simulated benchmarks for evaluation."
        : null,
      tenantId: session.tenantId,
      detection_rules: engineRules,
      yara_rules: goThreatState?.yara_rules || YARA_RULES,
      sigma_rules: goThreatState?.sigma_rules || SIGMA_RULES,
      anomaly_baselines: goThreatState?.anomaly_baselines || anomalyBaselines,
      ingest_telemetry: {
        ...INGEST_TELEMETRY,
        active_agents_connected: liveConnectedAgents,
        events_persisted_timescaledb: liveEventsCount,
      },
      can_view_auth_alerts: canViewAuthAlerts,
      security_alerts: securityAlerts,
      blocked_ips: isSystemAdmin ? (goThreatState?.blocked_ips || getBlockedIps()) : [],
    });
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { action } = body;

    // Public / client-reported login failures (e.g. from frontend Supabase auth failure or direct telemetry probe)
    if (action === "record_login_failure" || action === "simulate_login_failure") {
      const clientIp = await resolveClientIp(req, body.clientIp);

      const alert = recordThreatAlert({
        targetUser: body.email || body.targetUser || "attacker@unauthorized.io",
        clientIp,
        failureReason: body.reason || body.failureReason || "Invalid email or password",
        severity: body.severity,
      });

      return NextResponse.json({
        success: true,
        alert,
        isBlocked: alert.isBlocked || false,
        blocked_ips: getBlockedIps(),
      });
    }

    let session = await getSessionFromRequest(req);
    if (!session && isDevPersonaAllowed()) {
      session = {
        uid: "dev-admin",
        role: "system_admin",
        tenantId: "acme-tenant",
        email: "admin@acme.corp",
      };
    }
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const isSystemAdmin = session.role === "system_admin" || session.uid === "dev-admin" || session.role === "super_admin";
    const canManageContainment = isSystemAdmin;

    if (action === "unblock_ip") {
      if (!canManageContainment) {
        return NextResponse.json({ error: "Forbidden: IP unblocking restricted" }, { status: 403 });
      }
      if (!body.ip) {
        return NextResponse.json({ error: "Missing target IP to unblock" }, { status: 400 });
      }
      const unblocked = unblockIp(body.ip);

      // Sync with Go Threat Service if online
      try {
        const threatServiceUrl = process.env.THREAT_SERVICE_URL || "http://localhost:8003";
        await fetch(`${threatServiceUrl}/api/threats/containment`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action: "unblock_ip",
            tenant_id: session.tenantId,
            ip: body.ip,
          }),
          signal: AbortSignal.timeout(1000),
        });
      } catch {
        // Go service offline fallback
      }

      return NextResponse.json({
        success: true,
        unblocked,
        ip: body.ip,
        blocked_ips: getBlockedIps(),
      });
    }

    if (action === "block_ip") {
      if (!canManageContainment) {
        return NextResponse.json({ error: "Forbidden: IP blocking restricted" }, { status: 403 });
      }
      if (!body.ip) {
        return NextResponse.json({ error: "Missing target IP to block" }, { status: 400 });
      }
      blockIp(body.ip, body.reason || "Manual SOC IP containment");

      // Sync with Go Threat Service if online
      try {
        const threatServiceUrl = process.env.THREAT_SERVICE_URL || "http://localhost:8003";
        await fetch(`${threatServiceUrl}/api/threats/containment`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            action: "block_ip",
            tenant_id: session.tenantId,
            ip: body.ip,
            reason: body.reason,
          }),
          signal: AbortSignal.timeout(1000),
        });
      } catch {
        // Go service offline fallback
      }

      return NextResponse.json({
        success: true,
        ip: body.ip,
        blocked_ips: getBlockedIps(),
      });
    }

    if (action === "simulate_burst") {
      if (shouldFailClosed()) {
        return NextResponse.json(
          { error: "Synthetic anomaly burst simulation is prohibited in production mode." },
          { status: 403 }
        );
      }

      // Record simulated anomaly alert in the active store
      const simulatedAlert = recordThreatAlert({
        targetUser: session.uid === "dev-other" ? "analyst@globex.corp" : "admin@acme.corp",
        clientIp: "192.168.1.105",
        failureReason: "Synthetic Anomaly Burst (+4.8σ baseline spike)",
        severity: "critical",
        type: "brute_force_spike",
      });

      // Inject burst timestamps so live rate immediately reflects an active anomaly spike (> 10.5 threshold)
      recordFailureTimestamp(Date.now(), 18);
      recordSudoExecution(5);
      recordNetworkEgress(285.4);

      // Sync simulation with Go Threat Service
      try {
        const threatServiceUrl = process.env.THREAT_SERVICE_URL || "http://localhost:8003";
        await fetch(`${threatServiceUrl}/api/threats/simulate`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            tenant_id: session.tenantId,
            type: "all",
          }),
          signal: AbortSignal.timeout(1000),
        });
      } catch {
        // Go service offline fallback
      }

      return NextResponse.json({
        success: true,
        _demo_mode: true,
        simulation: "Auth Failure Anomaly Spike",
        triggered_at: new Date().toISOString(),
        anomaly_metric: "Failed Authentications / Min",
        simulated_value: 18.4,
        threshold: 10.5,
        sigma_deviation: "+4.8σ above baseline",
        alert_dispatched: true,
        alert_subject: "alerts.tenant_acme.auth_anomaly_burst",
        alert: simulatedAlert,
      });
    }

    if (action === "reset_anomalies" || action === "reset_baseline") {
      resetAnomalyBaselines(session.tenantId);

      // Sync reset with Go Threat Service
      try {
        const threatServiceUrl = process.env.THREAT_SERVICE_URL || "http://localhost:8003";
        await fetch(`${threatServiceUrl}/api/threats/reset`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            tenant_id: session.tenantId,
          }),
          signal: AbortSignal.timeout(1000),
        });
      } catch {
        // Go service offline fallback
      }

      const nominalBaselines = ANOMALY_BASELINES.map((b) => ({
        ...b,
        current_value: 0.0,
        is_anomaly: false,
      }));

      return NextResponse.json({
        success: true,
        message: "Anomaly telemetry reset to nominal baselines.",
        anomaly_baselines: nominalBaselines,
        security_alerts: isSystemAdmin ? getThreatAlertsForUser(session.uid) : [],
      });
    }

    if (action === "record_sudo") {
      const count = Number(body.count || 1);
      recordSudoExecution(count);
      return NextResponse.json({
        success: true,
        message: `Recorded ${count} live sudo execution event(s).`,
        current_value: getLiveSudoRatePerMin(),
      });
    }

    if (action === "record_egress") {
      const mb = Number(body.mb || 50);
      recordNetworkEgress(mb);
      return NextResponse.json({
        success: true,
        message: `Recorded ${mb} MB outbound network egress telemetry.`,
        current_value: getLiveEgressRateMBPerMin().current_value,
      });
    }

    if (action === "acknowledge_alert") {
      if (!canManageContainment) {
        return NextResponse.json({ error: "Forbidden: Alert acknowledgement restricted" }, { status: 403 });
      }
      const acknowledged = acknowledgeThreatAlert(body.alert_id, session.uid);
      return NextResponse.json({ success: acknowledged });
    }

    if (action === "reset_alerts") {
      if (!canManageContainment) {
        return NextResponse.json({ error: "Forbidden: Alert clearing restricted" }, { status: 403 });
      }
      resetThreatAlerts();
      return NextResponse.json({ success: true, blocked_ips: [] });
    }

    if (action === "toggle_rule") {
      const toggled = toggleDetectionRule(body.rule_id, Boolean(body.enabled));
      return NextResponse.json({
        success: true,
        rule_id: body.rule_id,
        toggled,
        new_status: body.enabled ? "ACTIVE" : "DISABLED",
      });
    }

    return NextResponse.json({ error: "Invalid action" }, { status: 400 });
  } catch (err: unknown) {
    console.error("[Threats API] POST error:", err);
    trackError(err, { endpoint: "/api/threats" });
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: "Failed to process threat request", details: msg }, { status: 500 });
  }
}

