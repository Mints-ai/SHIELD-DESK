export type TwinNodeType =
  | "endpoint"
  | "server"
  | "device"
  | "application"
  | "api"
  | "container"
  | "cloud_resource"
  | "network_segment"
  | "database"
  | "user"
  | "identity"
  | "secret"
  | "vulnerability"
  | "business_service";

export type AssetCriticality = "low" | "medium" | "high" | "critical";

export type TwinEdgeType =
  | "depends_on"
  | "runs_on"
  | "can_reach"
  | "authenticates_as"
  | "has_vulnerability"
  | "stores_secret"
  | "connects_to"
  | "manages"
  | "member_of";

export interface TwinNode {
  id: string;
  tenantId: string;
  name: string;
  type: TwinNodeType;
  criticality: AssetCriticality;
  ipAddress?: string;
  hostname?: string;
  os?: string;
  environment?: "production" | "staging" | "development" | "dmz" | "internal";
  status?: "healthy" | "compromised" | "isolated" | "degraded" | "offline";
  tags?: string[];
  metadata?: Record<string, unknown>;
  createdAt?: string;
  updatedAt?: string;
}

export interface TwinEdge {
  id: string;
  tenantId: string;
  sourceId: string;
  targetId: string;
  relationType: TwinEdgeType;
  port?: number;
  protocol?: string;
  bidirectional?: boolean;
  metadata?: Record<string, unknown>;
}

export interface IsolationSimulationResult {
  tenantId: string;
  isolatedAssetId: string;
  isolatedAssetName: string;
  severedEdgesCount: number;
  affectedUpstreamAssets: TwinNode[];
  affectedDownstreamAssets: TwinNode[];
  disruptedBusinessServices: TwinNode[];
  disconnectedIdentities: TwinNode[];
  blastRadiusScore: number;
  residualRisk: "negligible" | "low" | "medium" | "high" | "critical";
  summary: string;
}
