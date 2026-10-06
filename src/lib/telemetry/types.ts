export type EventCategory =
  | "process"
  | "network"
  | "authentication"
  | "file"
  | "service"
  | "system";

export type TelemetrySeverity = "low" | "medium" | "high" | "critical";

export type SourceFormat =
  | "shielddesk_native"
  | "windows_sysmon"
  | "windows_security"
  | "linux_auditd"
  | "linux_ebpf"
  | "crowdstrike"
  | "wazuh"
  | "defender"
  | "generic_json";

export interface ProcessContext {
  pid?: number;
  ppid?: number;
  name?: string;
  commandLine?: string;
  executablePath?: string;
  parentName?: string;
  parentCommandLine?: string;
  sha256?: string;
  user?: string;
}

export interface NetworkContext {
  sourceIp?: string;
  sourcePort?: number;
  destinationIp?: string;
  destinationPort?: number;
  protocol?: "tcp" | "udp" | "icmp" | "other";
  dnsQuery?: string;
  bytesSent?: number;
  bytesReceived?: number;
}

export interface AuthContext {
  userName?: string;
  userDomain?: string;
  logonType?: string;
  authResult?: "success" | "failure";
  failureReason?: string;
  sourceIp?: string;
}

export interface FileContext {
  path?: string;
  operation?: "create" | "modify" | "delete" | "rename" | "read";
  fileExtension?: string;
  sha256?: string;
  sizeBytes?: number;
}

export interface ServiceContext {
  serviceName?: string;
  displayName?: string;
  state?: "running" | "stopped" | "paused" | "installed" | "deleted";
  startType?: string;
  binaryPath?: string;
}

export interface CanonicalTelemetryEvent {
  id: string;
  tenantId: string;
  agentId: string;
  hostname: string;
  category: EventCategory;
  eventType: string;
  severity: TelemetrySeverity;
  timestamp: string;
  fingerprint: string;
  sourceFormat: SourceFormat;
  process?: ProcessContext;
  network?: NetworkContext;
  auth?: AuthContext;
  file?: FileContext;
  service?: ServiceContext;
  raw?: Record<string, unknown>;
}

export interface TelemetryIngestContext {
  tenantId: string;
  agentId: string;
  hostname?: string;
  sourceFormat?: SourceFormat;
}

export interface TelemetryBatchResult {
  success: boolean;
  ingestedCount: number;
  duplicateCount: number;
  droppedCount: number;
  deadLetterEvents: Array<{ event: unknown; error: string }>;
  detectionsCount: number;
  detections: unknown[];
  events: CanonicalTelemetryEvent[];
}
