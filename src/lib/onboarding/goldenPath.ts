import "server-only";

export type OnboardingStep =
  | "SIGNUP"
  | "ORGANIZATION_CREATED"
  | "ENROLLMENT_TOKEN_ISSUED"
  | "INSTALLATION_COMMAND_GENERATED"
  | "FIRST_AGENT_CONNECTED"
  | "CANARY_DETECTION_TRIGGERED"
  | "INCIDENT_SURFACED"
  | "FIRST_REMEDIATION_VERIFIED";

export interface OnboardingState {
  tenantId: string;
  currentStep: OnboardingStep;
  completedSteps: OnboardingStep[];
  startedAt: string;
  completedAt: string | null;
  timeToFirstRemediationMinutes?: number;
}

export const ONBOARDING_STEP_ORDER: OnboardingStep[] = [
  "SIGNUP",
  "ORGANIZATION_CREATED",
  "ENROLLMENT_TOKEN_ISSUED",
  "INSTALLATION_COMMAND_GENERATED",
  "FIRST_AGENT_CONNECTED",
  "CANARY_DETECTION_TRIGGERED",
  "INCIDENT_SURFACED",
  "FIRST_REMEDIATION_VERIFIED",
];

const ONBOARDING_STATE_STORE: Map<string, OnboardingState> = new Map();

/**
 * Initializes or retrieves the customer onboarding state.
 */
export function getOnboardingState(tenantId: string): OnboardingState {
  let state = ONBOARDING_STATE_STORE.get(tenantId);
  if (!state) {
    state = {
      tenantId,
      currentStep: "SIGNUP",
      completedSteps: [],
      startedAt: new Date().toISOString(),
      completedAt: null,
    };
    ONBOARDING_STATE_STORE.set(tenantId, state);
  }
  return state;
}

/**
 * Advances the customer onboarding progress to the specified milestone.
 */
export function advanceOnboardingStep(
  tenantId: string,
  completedStep: OnboardingStep
): OnboardingState {
  const state = getOnboardingState(tenantId);

  if (!state.completedSteps.includes(completedStep)) {
    state.completedSteps.push(completedStep);
  }

  const currentIndex = ONBOARDING_STEP_ORDER.indexOf(completedStep);
  if (currentIndex < ONBOARDING_STEP_ORDER.length - 1) {
    state.currentStep = ONBOARDING_STEP_ORDER[currentIndex + 1];
  } else {
    state.currentStep = "FIRST_REMEDIATION_VERIFIED";
    if (!state.completedAt) {
      state.completedAt = new Date().toISOString();
      const durationMs = new Date(state.completedAt).getTime() - new Date(state.startedAt).getTime();
      state.timeToFirstRemediationMinutes = Math.max(1, Math.round(durationMs / 60000));
    }
  }

  return state;
}

/**
 * Generates the one-line endpoint installation command for the customer golden path.
 */
export function generateAgentInstallCommand(params: {
  controlUrl: string;
  enrollToken: string;
  osType: "linux" | "windows";
}): string {
  const { controlUrl, enrollToken, osType } = params;

  if (osType === "windows") {
    return `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iwr -useb "${controlUrl}/install/windows" | iex; Initialize-ShieldDeskAgent -ControlUrl "${controlUrl}" -EnrollToken "${enrollToken}"`;
  }

  return `curl -sSL "${controlUrl}/install/linux" | sudo sh -s -- --control-url "${controlUrl}" --enroll-token "${enrollToken}"`;
}

/**
 * Triggers a harmless, non-destructive canary incident alert for initial product testing.
 */
export function generateCanaryDetection(tenantId: string): {
  incidentId: string;
  title: string;
  severity: "low" | "medium";
  description: string;
  recommendedAction: string;
} {
  const incidentId = `inc_canary_${Date.now().toString(36)}`;
  advanceOnboardingStep(tenantId, "CANARY_DETECTION_TRIGGERED");

  return {
    incidentId,
    title: "Canary Security Verification Event (Harmless Test)",
    severity: "low",
    description: "Benign EICAR/synthetic probe telemetry triggered to verify the closed-loop incident advisor and verification pipeline.",
    recommendedAction: "file.quarantine",
  };
}
