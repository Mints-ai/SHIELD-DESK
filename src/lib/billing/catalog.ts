import "server-only";

export type BillingTier = "community" | "professional" | "enterprise";
export type BillingInterval = "month" | "year";
export type SupportedCurrency = "USD" | "EUR" | "AED";
export type DeploymentModel = "saas" | "customer-hosted" | "both";

export interface PlanFeatureMatrix {
  telemetryIngest: boolean;
  realTimeDetection: boolean;
  aiInvestigation: boolean;
  automatedRemediationTier1: boolean;
  governedRemediationTier2: boolean;
  dualApprovalTier3: boolean;
  siemConnectors: boolean;
  customRules: boolean;
  discordSlackAlerts: boolean;
  endpointFleet: boolean;
  complianceVault: boolean;
  airGappedSupport: boolean;
  dedicatedPKI: boolean;
}

export interface PricingIntervalDef {
  priceCents: number; // in minor units (e.g. USD cents)
  displayPrice: number; // e.g. 49, 39, 499
  stripePriceIdEnvVar: string;
  defaultPriceId: string;
}

export interface CanonicalPlan {
  id: BillingTier;
  name: string;
  tagline: string;
  description: string;
  deploymentModel: DeploymentModel;
  maxEndpoints: number;
  maxUsers: number;
  retentionDays: number;
  trialDays: number;
  trialEligible: boolean;
  supportSla: "community" | "priority_email" | "dedicated_soc";
  licenseDurationDays: number; // default license token duration before renewal
  activationLimit: number;
  features: PlanFeatureMatrix;
  supportedIntegrations: string[];
  pricing: Record<BillingInterval, PricingIntervalDef>;
  upgradeAllowedTo: BillingTier[];
  downgradeAllowedTo: BillingTier[];
}

export const CANONICAL_CATALOG: Record<BillingTier, CanonicalPlan> = {
  community: {
    id: "community",
    name: "ShieldDesk Community Pilot",
    tagline: "Open-source & evaluation edition for developers and small labs",
    description: "Full incident queue, real-time telemetry ingestion, and native YARA scanning for up to 5 endpoints.",
    deploymentModel: "both",
    maxEndpoints: 5,
    maxUsers: 3,
    retentionDays: 7,
    trialDays: 14,
    trialEligible: true,
    supportSla: "community",
    licenseDurationDays: 30,
    activationLimit: 5,
    features: {
      telemetryIngest: true,
      realTimeDetection: true,
      aiInvestigation: true,
      automatedRemediationTier1: false,
      governedRemediationTier2: true,
      dualApprovalTier3: false,
      siemConnectors: false,
      customRules: false,
      discordSlackAlerts: true,
      endpointFleet: false,
      complianceVault: false,
      airGappedSupport: false,
      dedicatedPKI: false,
    },
    supportedIntegrations: ["wazuh", "crowdstrike", "defender"],
    pricing: {
      month: {
        priceCents: 0,
        displayPrice: 0,
        stripePriceIdEnvVar: "STRIPE_PRICE_COMMUNITY_MONTHLY",
        defaultPriceId: "price_community_free",
      },
      year: {
        priceCents: 0,
        displayPrice: 0,
        stripePriceIdEnvVar: "STRIPE_PRICE_COMMUNITY_ANNUAL",
        defaultPriceId: "price_community_free",
      },
    },
    upgradeAllowedTo: ["professional", "enterprise"],
    downgradeAllowedTo: [],
  },
  professional: {
    id: "professional",
    name: "ShieldDesk SOC Pro",
    tagline: "Cloud-managed platform for growing security teams & mid-market",
    description: "AI blast radius simulation, 3-horizon remediation pipelines, RSA-2048 signed fleet dispatch, and automated CVE correlation for up to 100 endpoints.",
    deploymentModel: "both",
    maxEndpoints: 100,
    maxUsers: 25,
    retentionDays: 90,
    trialDays: 14,
    trialEligible: true,
    supportSla: "priority_email",
    licenseDurationDays: 365,
    activationLimit: 100,
    features: {
      telemetryIngest: true,
      realTimeDetection: true,
      aiInvestigation: true,
      automatedRemediationTier1: true,
      governedRemediationTier2: true,
      dualApprovalTier3: true,
      siemConnectors: true,
      customRules: true,
      discordSlackAlerts: true,
      endpointFleet: true,
      complianceVault: true,
      airGappedSupport: false,
      dedicatedPKI: false,
    },
    supportedIntegrations: [
      "wazuh",
      "crowdstrike",
      "defender",
      "trivy",
      "gitleaks",
      "slack",
      "discord",
    ],
    pricing: {
      month: {
        priceCents: 4900, // $49.00 / month
        displayPrice: 49,
        stripePriceIdEnvVar: "STRIPE_PRICE_PRO_MONTHLY",
        defaultPriceId: "price_shielddesk_pro_monthly",
      },
      year: {
        priceCents: 46800, // $39/mo billed as $468.00 / year (save 20%)
        displayPrice: 39,
        stripePriceIdEnvVar: "STRIPE_PRICE_PRO_ANNUAL",
        defaultPriceId: "price_shielddesk_pro_annual",
      },
    },
    upgradeAllowedTo: ["enterprise"],
    downgradeAllowedTo: ["community"],
  },
  enterprise: {
    id: "enterprise",
    name: "ShieldDesk Autonomous Enterprise",
    tagline: "Air-gapped dual-custody governance for regulated infrastructure",
    description: "Strict separation of duties, Tier 3 dual-MFA sign-off, HSM keys, custom SIEM connectors, and immutable Merkle audit vault for up to 10,000 endpoints.",
    deploymentModel: "both",
    maxEndpoints: 10000,
    maxUsers: 250,
    retentionDays: 365,
    trialDays: 30,
    trialEligible: false,
    supportSla: "dedicated_soc",
    licenseDurationDays: 365,
    activationLimit: 10000,
    features: {
      telemetryIngest: true,
      realTimeDetection: true,
      aiInvestigation: true,
      automatedRemediationTier1: true,
      governedRemediationTier2: true,
      dualApprovalTier3: true,
      siemConnectors: true,
      customRules: true,
      discordSlackAlerts: true,
      endpointFleet: true,
      complianceVault: true,
      airGappedSupport: true,
      dedicatedPKI: true,
    },
    supportedIntegrations: [
      "wazuh",
      "crowdstrike",
      "defender",
      "trivy",
      "gitleaks",
      "sentinel",
      "splunk",
      "aws_guardduty",
      "slack",
      "teams",
    ],
    pricing: {
      month: {
        priceCents: 199900, // $1999.00 / month
        displayPrice: 1999,
        stripePriceIdEnvVar: "STRIPE_PRICE_ENTERPRISE_MONTHLY",
        defaultPriceId: "price_shielddesk_enterprise_monthly",
      },
      year: {
        priceCents: 1918800, // $1599/mo billed as $19,188.00 / year (save 20%)
        displayPrice: 1599,
        stripePriceIdEnvVar: "STRIPE_PRICE_ENTERPRISE_ANNUAL",
        defaultPriceId: "price_shielddesk_enterprise_annual",
      },
    },
    upgradeAllowedTo: [],
    downgradeAllowedTo: ["professional", "community"],
  },
};

/**
 * Resolves the server-authoritative Stripe Price ID for a plan and interval.
 * Never trust client-supplied Stripe Price IDs or amounts.
 */
export function resolveServerStripePriceId(
  tier: BillingTier,
  interval: BillingInterval = "month"
): string {
  const plan = CANONICAL_CATALOG[tier];
  if (!plan) {
    throw new Error(`Unknown plan tier '${tier}'.`);
  }

  const intervalDef = plan.pricing[interval];
  if (!intervalDef) {
    throw new Error(`Unsupported billing interval '${interval}' for plan '${tier}'.`);
  }

  const envPriceId = process.env[intervalDef.stripePriceIdEnvVar];
  if (envPriceId && envPriceId.trim()) {
    return envPriceId.trim();
  }

  return intervalDef.defaultPriceId;
}

/**
 * Public catalogue representation sanitized for clients (browsers, public API).
 * Never exposes server env vars or internal secrets.
 */
export interface PublicCatalogPlan {
  id: BillingTier;
  name: string;
  tagline: string;
  description: string;
  deploymentModel: DeploymentModel;
  maxEndpoints: number;
  maxUsers: number;
  retentionDays: number;
  trialDays: number;
  trialEligible: boolean;
  supportSla: string;
  features: PlanFeatureMatrix;
  supportedIntegrations: string[];
  pricing: {
    month: {
      amountUSD: number;
      priceCents: number;
      interval: "month";
    };
    year: {
      amountUSD: number;
      monthlyEquivalentUSD: number;
      priceCents: number;
      interval: "year";
      savingsPercent: number;
    };
  };
}

export function getPublicCatalog(): PublicCatalogPlan[] {
  return Object.values(CANONICAL_CATALOG).map((plan) => ({
    id: plan.id,
    name: plan.name,
    tagline: plan.tagline,
    description: plan.description,
    deploymentModel: plan.deploymentModel,
    maxEndpoints: plan.maxEndpoints,
    maxUsers: plan.maxUsers,
    retentionDays: plan.retentionDays,
    trialDays: plan.trialDays,
    trialEligible: plan.trialEligible,
    supportSla: plan.supportSla,
    features: { ...plan.features },
    supportedIntegrations: [...plan.supportedIntegrations],
    pricing: {
      month: {
        amountUSD: plan.pricing.month.displayPrice,
        priceCents: plan.pricing.month.priceCents,
        interval: "month",
      },
      year: {
        amountUSD: Math.round(plan.pricing.year.priceCents / 100),
        monthlyEquivalentUSD: plan.pricing.year.displayPrice,
        priceCents: plan.pricing.year.priceCents,
        interval: "year",
        savingsPercent: 20,
      },
    },
  }));
}
