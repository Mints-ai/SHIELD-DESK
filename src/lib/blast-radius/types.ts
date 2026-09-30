export type BlastCalculationMode = "measured" | "inferred" | "simulated" | "estimated";

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
