import { NextRequest, NextResponse } from "next/server";

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
    current_value: 3.8,
    is_anomaly: false,
    unit: "attempts/min",
  },
  {
    metric: "Outbound Network Egress Rate",
    mean: 145.0,
    stdDev: 35.0,
    threshold_2sigma: 215.0,
    current_value: 122.4,
    is_anomaly: false,
    unit: "MB/min",
  },
  {
    metric: "Sudo Execution Frequency",
    mean: 1.1,
    stdDev: 0.8,
    threshold_3sigma: 3.5,
    current_value: 0.9,
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

import { getSessionFromRequest } from "@/lib/auth/session";

export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  return NextResponse.json({
    status: "ok",
    tenantId: session.tenantId,
    yara_rules: YARA_RULES,
    sigma_rules: SIGMA_RULES,
    anomaly_baselines: ANOMALY_BASELINES,
    ingest_telemetry: INGEST_TELEMETRY,
  });
}

export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const body = await req.json();
    const { action } = body;

    if (action === "simulate_burst") {
      return NextResponse.json({
        success: true,
        simulation: "Auth Failure Anomaly Spike",
        triggered_at: new Date().toISOString(),
        anomaly_metric: "Failed Authentications / Min",
        simulated_value: 18.4,
        threshold: 10.5,
        sigma_deviation: "+4.8σ above baseline",
        alert_dispatched: true,
        alert_subject: "alerts.tenant_acme.auth_anomaly_burst",
      });
    }

    if (action === "toggle_rule") {
      return NextResponse.json({
        success: true,
        rule_id: body.rule_id,
        new_status: body.enabled ? "ACTIVE" : "DISABLED",
      });
    }

    return NextResponse.json({ error: "Invalid action" }, { status: 400 });
  } catch {
    return NextResponse.json({ error: "Failed to process threat request" }, { status: 500 });
  }
}
