import { z } from "zod";

export const AppEnvironmentSchema = z.enum(["development", "test", "staging", "production"]);
export type AppEnvironment = z.infer<typeof AppEnvironmentSchema>;

/**
 * Base raw environment variables schema parsed from process.env
 */
export const RawEnvironmentSchema = z.object({
  NODE_ENV: z.string().optional(),
  APP_ENV: AppEnvironmentSchema.optional(),
  PORT: z.string().regex(/^\d+$/).optional().default("3000"),

  // Persistence & Database
  DATABASE_URL: z.string().optional(),
  REDIS_URL: z.string().optional(),

  // Safety & Mode Toggles
  DEMO_MODE: z.enum(["true", "false"]).optional(),
  FAIL_CLOSED: z.enum(["true", "false"]).optional(),
  DEV_SIMULATION: z.enum(["true", "false"]).optional(),
  STAGING_SIMULATION: z.enum(["true", "false"]).optional(),

  // Cryptographic Secrets
  SHIELDDESK_SESSION_SECRET: z.string().optional(),
  SHIELDDESK_INGEST_API_KEY: z.string().optional(),
  CONTROL_PLANE_CA_PRIVATE_KEY: z.string().optional(),
  CONTROL_PLANE_CA_CERTIFICATE: z.string().optional(),
  RSA_SIGNING_PRIVATE_KEY: z.string().optional(),
  RSA_SIGNING_PUBLIC_KEY: z.string().optional(),

  // AI & Threat Microservices
  PYTHON_AI_SERVICE_URL: z.string().url().optional().default("http://localhost:8000"),
  OLLAMA_BASE_URL: z.string().url().optional().default("http://localhost:11434/v1"),
  OLLAMA_MODEL: z.string().optional().default("qwen3:4b"),
  OPENAI_API_KEY: z.string().optional(),
  OPENAI_BASE_URL: z.string().url().optional(),

  // Notification Integrations
  SLACK_WEBHOOK_URL: z.string().url().optional().or(z.literal("")),
  TEAMS_WEBHOOK_URL: z.string().url().optional().or(z.literal("")),
  SECURITY_WEBHOOK_URL: z.string().url().optional().or(z.literal("")),

  // Observability & Sentry
  SENTRY_DSN: z.string().optional().or(z.literal("")),
  NEXT_PUBLIC_SENTRY_DSN: z.string().optional().or(z.literal("")),

  // External Attack Surface & Threat Intelligence (Optional)
  SHODAN_API_KEY: z.string().optional(),
  HIBP_API_KEY: z.string().optional(),

  // SaaS & Billing
  STRIPE_SECRET_KEY: z.string().optional(),
  STRIPE_WEBHOOK_SECRET: z.string().optional(),
});

export type RawEnvironment = z.infer<typeof RawEnvironmentSchema>;

/**
 * Validated, typed configuration container with strict production assertions
 */
export interface ShieldDeskConfig {
  environment: AppEnvironment;
  port: number;
  isProduction: boolean;
  isStaging: boolean;
  isTest: boolean;
  isDevelopment: boolean;

  // Runtime Safety Gates
  demoMode: boolean;
  failClosed: boolean;
  simulationAllowed: boolean;
  devPersonasAllowed: boolean;

  // Configuration Health & Validation Issues
  validationErrors: string[];

  // Database
  database: {
    url?: string;
    isConfigured: boolean;
    poolMax: number;
    ssl: boolean;
  };

  // Redis
  redis: {
    url?: string;
    isConfigured: boolean;
  };

  // Cryptography & Tokens
  auth: {
    sessionSecret: string;
    sessionTtlSeconds: number;
  };
  ingest: {
    apiKey?: string;
  };
  pki: {
    caPrivateKeyPem?: string;
    caCertificatePem?: string;
    signingPrivateKeyPem?: string;
    signingPublicKeyPem?: string;
  };

  // AI & ML Services
  services: {
    pythonAiUrl: string;
    ollamaBaseUrl: string;
    ollamaModel: string;
    openAiApiKey?: string;
    openAiBaseUrl?: string;
  };

  // Observability
  observability: {
    sentryDsn?: string;
  };

  // Billing
  billing: {
    stripeConfigured: boolean;
    stripeSecretKey?: string;
    stripeWebhookSecret?: string;
  };

  // External Attack Surface & Threat Intel
  threatIntel: {
    shodanApiKey?: string;
    shodanConfigured: boolean;
    hibpApiKey?: string;
    hibpConfigured: boolean;
  };
}

/**
 * Validates the raw environment with strict rules depending on target environment.
 */
export function validateEnvironment(env: Record<string, string | undefined> = process.env): ShieldDeskConfig {
  const parsed = RawEnvironmentSchema.safeParse(env);
  const validationErrors: string[] = [];

  if (!parsed.success) {
    const errorDetails = parsed.error.issues
      .map((i) => `  - [${i.path.join(".")}]: ${i.message}`)
      .join("\n");
    validationErrors.push(`Environment syntax validation failed:\n${errorDetails}`);
  }

  const raw = parsed.success ? parsed.data : (env as unknown as RawEnvironment);

  // Resolve deployment environment: APP_ENV takes precedence over NODE_ENV
  let environment: AppEnvironment = "development";
  if (raw.APP_ENV) {
    environment = raw.APP_ENV;
  } else if (raw.NODE_ENV === "production") {
    environment = "production";
  } else if (raw.NODE_ENV === "test") {
    environment = "test";
  }

  const isProduction = environment === "production";
  const isStaging = environment === "staging";
  const isTest = environment === "test";
  const isDevelopment = environment === "development";

  // Production Rule: DEMO_MODE must NEVER be true in production
  if (isProduction && raw.DEMO_MODE === "true") {
    validationErrors.push(
      "SECURITY VIOLATION: DEMO_MODE=true is strictly forbidden in production deployments."
    );
  }

  // Resolve demo mode
  let demoMode = false;
  if (!isProduction) {
    if (raw.DEMO_MODE === "true") demoMode = true;
    else if (raw.DEMO_MODE === "false") demoMode = false;
    else demoMode = isDevelopment || isTest; // Defaults to true in dev/test, false in staging/prod
  }

  // Production Rule: FAIL_CLOSED is always true in production
  const failClosed = isProduction || raw.FAIL_CLOSED === "true";

  // Production Rule: Simulation gating
  let simulationAllowed = false;
  if (!isProduction) {
    if (isStaging) {
      simulationAllowed = raw.STAGING_SIMULATION === "true";
    } else {
      simulationAllowed = raw.DEV_SIMULATION !== "false" && demoMode;
    }
  }

  // Dev Personas: strictly blocked in production and staging
  const devPersonasAllowed = !isProduction && !isStaging && demoMode;

  // Production Rule: DATABASE_URL is strictly required in production and staging
  if ((isProduction || isStaging) && (!raw.DATABASE_URL || raw.DATABASE_URL.trim() === "")) {
    validationErrors.push(
      `CRITICAL: DATABASE_URL is mandatory when running in '${environment}' environment.`
    );
  }

  // Production Rule: SHIELDDESK_SESSION_SECRET must be at least 32 characters in production
  if (isProduction) {
    if (!raw.SHIELDDESK_SESSION_SECRET || raw.SHIELDDESK_SESSION_SECRET.length < 32) {
      validationErrors.push(
        "CRITICAL: SHIELDDESK_SESSION_SECRET must be at least 32 characters in production deployments."
      );
    }
  }

  // Production Rule: SHIELDDESK_INGEST_API_KEY must be provided in production
  if (isProduction && (!raw.SHIELDDESK_INGEST_API_KEY || raw.SHIELDDESK_INGEST_API_KEY.length < 16)) {
    validationErrors.push(
      "CRITICAL: SHIELDDESK_INGEST_API_KEY must be at least 16 characters in production."
    );
  }

  const sessionSecret =
    raw.SHIELDDESK_SESSION_SECRET ||
    (isProduction
      ? ""
      : "dev-ephemeral-session-secret-min-32-chars-for-testing-only");

  return {
    environment,
    port: parseInt(raw.PORT || "3000", 10),
    isProduction,
    isStaging,
    isTest,
    isDevelopment,

    demoMode,
    failClosed,
    simulationAllowed,
    devPersonasAllowed,

    validationErrors,

    database: {
      url: raw.DATABASE_URL,
      isConfigured: Boolean(raw.DATABASE_URL && raw.DATABASE_URL.trim() !== ""),
      poolMax: isProduction ? 50 : 10,
      ssl: isProduction || raw.DATABASE_URL?.includes("sslmode=require") || false,
    },

    redis: {
      url: raw.REDIS_URL,
      isConfigured: Boolean(raw.REDIS_URL && raw.REDIS_URL.trim() !== ""),
    },

    auth: {
      sessionSecret,
      sessionTtlSeconds: 86400 * 7, // 7 days
    },

    ingest: {
      apiKey: raw.SHIELDDESK_INGEST_API_KEY,
    },

    pki: {
      caPrivateKeyPem: raw.CONTROL_PLANE_CA_PRIVATE_KEY,
      caCertificatePem: raw.CONTROL_PLANE_CA_CERTIFICATE,
      signingPrivateKeyPem: raw.RSA_SIGNING_PRIVATE_KEY,
      signingPublicKeyPem: raw.RSA_SIGNING_PUBLIC_KEY,
    },

    services: {
      pythonAiUrl: raw.PYTHON_AI_SERVICE_URL || "http://localhost:8000",
      ollamaBaseUrl: raw.OLLAMA_BASE_URL || "http://localhost:11434/v1",
      ollamaModel: raw.OLLAMA_MODEL || "qwen3:4b",
      openAiApiKey: raw.OPENAI_API_KEY,
      openAiBaseUrl: raw.OPENAI_BASE_URL,
    },

    observability: {
      sentryDsn: raw.SENTRY_DSN || raw.NEXT_PUBLIC_SENTRY_DSN,
    },

    billing: {
      stripeConfigured: Boolean(raw.STRIPE_SECRET_KEY && raw.STRIPE_WEBHOOK_SECRET),
      stripeSecretKey: raw.STRIPE_SECRET_KEY,
      stripeWebhookSecret: raw.STRIPE_WEBHOOK_SECRET,
    },

    threatIntel: {
      shodanApiKey: raw.SHODAN_API_KEY,
      shodanConfigured: Boolean(raw.SHODAN_API_KEY && raw.SHODAN_API_KEY.trim() !== ""),
      hibpApiKey: raw.HIBP_API_KEY,
      hibpConfigured: Boolean(raw.HIBP_API_KEY && raw.HIBP_API_KEY.trim() !== ""),
    },
  };
}

/**
 * Asserts that the environment configuration is valid for deployment.
 * Fails fast with ConfigurationValidationError if any critical validation errors are present.
 */
export function assertValidConfiguration(env: Record<string, string | undefined> = process.env): ShieldDeskConfig {
  const config = validateEnvironment(env);
  if (config.validationErrors.length > 0) {
    throw new ConfigurationValidationError(
      `ShieldDesk Startup Configuration Validation Failed:\n${config.validationErrors.join("\n")}`
    );
  }
  return config;
}

export class ConfigurationValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigurationValidationError";
  }
}
