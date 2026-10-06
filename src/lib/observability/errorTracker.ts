/**
 * ShieldDesk Enterprise Observability & Error Tracking
 * Captures, formats, and dispatches uncaught exceptions to configured monitoring backends.
 */

// Sentry is dynamically imported when configured to avoid premature OTel instrumentation initialization

export interface TrackedErrorContext {
  userId?: string;
  tenantId?: string;
  endpoint?: string;
  route?: string;
  component?: string;
  extra?: Record<string, unknown>;
}

export function trackError(error: unknown, context: TrackedErrorContext = {}): string {
  const errorId = `err_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 7)}`;
  const timestamp = new Date().toISOString();
  
  const errorMessage = error instanceof Error ? error.message : String(error);
  const errorStack = error instanceof Error ? error.stack : undefined;

  const payload = {
    errorId,
    timestamp,
    message: errorMessage,
    stack: errorStack,
    context: {
      environment: process.env.NODE_ENV || "development",
      ...context,
    },
  };

  // Structured stdout logging for log shippers (Fluentbit, Datadog agent, Grafana Loki)
  console.error(`[SHIELDDESK_ERROR] ${JSON.stringify(payload)}`);

  // Forward to Sentry if configured and not running in unit test mode
  const sentryDsn = process.env.SENTRY_DSN || process.env.NEXT_PUBLIC_SENTRY_DSN;
  if (sentryDsn && process.env.NODE_ENV !== "test") {
    import("@sentry/nextjs")
      .then((Sentry) => {
        Sentry.withScope((scope) => {
          if (context.userId) {
            scope.setUser({ id: context.userId });
          }
          if (context.tenantId) {
            scope.setTag("tenantId", context.tenantId);
          }
          const effectiveEndpoint = context.endpoint || context.route;
          if (effectiveEndpoint) {
            scope.setTag("endpoint", effectiveEndpoint);
          }
          if (context.component) {
            scope.setTag("component", context.component);
          }
          scope.setExtra("errorId", errorId);
          if (context.extra) {
            scope.setExtras(context.extra);
          }
          Sentry.captureException(error);
        });
      })
      .catch(() => {
        // Avoid recursive crash if Sentry client encounters an error
      });
  }

  // Live Alert Webhook (Slack, Discord, Teams, or SecOps HTTP receiver)
  const webhookUrl = process.env.ERROR_WEBHOOK_URL || process.env.SECURITY_WEBHOOK_URL;
  if (webhookUrl && process.env.NODE_ENV !== "test") {
    fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: `🚨 *ShieldDesk System Exception [${errorId}]*\n*Message:* ${errorMessage}\n*Endpoint/Component:* ${context.endpoint || context.component || "App"}\n*Tenant:* ${context.tenantId || "N/A"}`,
        errorId,
        message: errorMessage,
        context,
        timestamp,
      }),
    }).catch(() => {
      // Avoid recursive crash
    });
  }

  return errorId;
}
