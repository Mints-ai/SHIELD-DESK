export type ConnectorType =
  | "wazuh"
  | "defender"
  | "crowdstrike"
  | "webhook"
  | "generic_siem";

export type EventSeverity = "low" | "medium" | "high" | "critical";

export interface NormalizedAssetRef {
  id?: string;
  hostname?: string;
  ip?: string;
  os?: string;
}

export interface UniversalSecurityEvent {
  id: string;
  tenantId: string;
  source: ConnectorType;
  externalId: string;
  timestamp: string;
  severity: EventSeverity;
  title: string;
  description: string;
  affectedAsset: NormalizedAssetRef;
  processContext?: {
    name?: string;
    pid?: number;
    commandLine?: string;
    sha256?: string;
    user?: string;
  };
  networkContext?: {
    srcIp?: string;
    dstIp?: string;
    dstPort?: number;
    protocol?: string;
  };
  tags: string[];
  rawPayload: Record<string, unknown>;
}

export interface IngestConnectorResult {
  success: boolean;
  event?: UniversalSecurityEvent;
  error?: string;
}
