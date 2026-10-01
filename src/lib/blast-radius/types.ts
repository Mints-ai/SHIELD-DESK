export type BlastCalculationMode = "measured" | "inferred" | "simulated" | "estimated";

export type SensitiveCategory =
  | "pii"
  | "pci"
  | "sox"
  | "hipaa"
  | "crown_jewel"
  | "production_core";

export interface SensitiveSystemsAnalysis {
  detected: boolean;
  categories: SensitiveCategory[];
  systems: Array<{
    id: string;
    name: string;
    reasons: string[];
    criticality?: string;
  }>;
}

export type RollbackMethod =
  | "restore_host"
  | "revert_network_rules"
  | "restart_service"
  | "reinstall_package"
  | "manual_only";

export interface RollbackAvailabilityReport {
  available: boolean;
  method: RollbackMethod;
  estimatedRollbackMinutes: number;
  preFlightSnapshotRequired: boolean;
  reversibilityRisk: "low" | "medium" | "high";
  evidence: string[];
}

export interface MitigationOption {
  strategy: "isolate_asset" | "block_port" | "sever_chokepoint" | "patch_vulnerability";
  targetAssetId: string;
  riskReduction: number;
  residualBlastScore: number;
  description: string;
}

export interface BlastRadiusReport {
  tenantId: string;
  targetAssetId: string;
  targetAssetName: string;
  action: string;
  score: number;
  exceeded: boolean;
  calculationMode: BlastCalculationMode;
  confidence: number;
  affectedAssets: Array<{ id: string; name: string; type: string; criticality: string }>;
  affectedServices: Array<{ id: string; name: string; tier: string }>;
  affectedUsers: Array<{ id: string; name: string; department?: string }>;
  affectedApps?: Array<{ id: string; name: string; type: string; criticality: string; environment?: string }>;
  sensitiveSystems?: SensitiveSystemsAnalysis;
  rollbackAvailability?: RollbackAvailabilityReport;
  mitigationOptions?: MitigationOption[];
  estimatedDowntime: {
    minutes: number;
    severity: "none" | "minimal" | "moderate" | "major" | "catastrophic";
    description: string;
  };
  securityImpact: {
    riskReductionScore: number;
    threatContainment: string;
    lingeringVulnerabilities: string[];
  };
  businessImpact: {
    revenueImpactTier: "negligible" | "low" | "medium" | "high" | "critical";
    regulatoryRisk: "none" | "low" | "medium" | "high";
    serviceDisruptions: string[];
  };
  evidence: string[];
  calculatedAt: string;
}
