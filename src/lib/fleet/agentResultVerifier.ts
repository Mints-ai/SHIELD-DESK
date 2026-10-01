import crypto from "node:crypto";
import { query } from "@/lib/db";
import { getEndpointCertificateByAgent } from "./certificates";

export interface SignedAgentResultPayload {
  commandId: string;
  agentId: string;
  tenantId: string;
  exitCode: number;
  stdout: string;
  stderr: string;
  executionTimestamp: string;
  hostStateDigest: string; // SHA-256 of post-execution network/process/firewall state
  resultSignature: string;
  snapshotId?: string;
}

export interface AgentResultVerificationResult {
  verified: boolean;
  reason?: string;
  canonicalPayload: string;
  computedStateDigest: string;
}

export class AgentResultVerifier {
  /**
   * Produces deterministic canonical string of an agent's execution result.
   */
  public static formatCanonicalResultPayload(payload: {
    commandId: string;
    agentId: string;
    exitCode: number;
    hostStateDigest: string;
    executionTimestamp: string;
  }): string {
    return `${payload.commandId}|${payload.agentId}|${payload.exitCode}|${payload.hostStateDigest}|${payload.executionTimestamp}`;
  }

  /**
   * Computes deterministic SHA-256 host state digest from raw host state data.
   */
  public static computeHostStateDigest(stateData: string | Record<string, unknown>): string {
    const raw = typeof stateData === "string" ? stateData : JSON.stringify(stateData);
    return crypto.createHash("sha256").update(raw).digest("hex");
  }

  /**
   * Generates a signed result for an agent using its private key (used by agent daemon or integration test).
   */
  public static signAgentResult(
    payload: {
      commandId: string;
      agentId: string;
      exitCode: number;
      hostStateDigest: string;
      executionTimestamp: string;
    },
    agentPrivateKeyPem: string
  ): string {
    const canonical = this.formatCanonicalResultPayload(payload);
    const signer = crypto.createSign("RSA-SHA256");
    signer.update(canonical, "utf8");
    return signer.sign(agentPrivateKeyPem, "base64");
  }

  /**
   * Cryptographically verifies that the result was signed by the enrolled agent's registered key.
   */
  public static async verifyResult(
    payload: SignedAgentResultPayload,
    options?: { agentPublicKeyPem?: string; allowTestKey?: boolean }
  ): Promise<AgentResultVerificationResult> {
    const canonical = this.formatCanonicalResultPayload({
      commandId: payload.commandId,
      agentId: payload.agentId,
      exitCode: payload.exitCode,
      hostStateDigest: payload.hostStateDigest,
      executionTimestamp: payload.executionTimestamp,
    });

    if (!payload.resultSignature) {
      return {
        verified: false,
        reason: "Missing result signature: unauthenticated execution report rejected under fail-closed security policy.",
        canonicalPayload: canonical,
        computedStateDigest: payload.hostStateDigest,
      };
    }

    // 1. Resolve agent's enrolled public key
    let publicKeyPem = options?.agentPublicKeyPem;

    if (!publicKeyPem) {
      try {
        const cert = await getEndpointCertificateByAgent(payload.agentId);
        if (cert && cert.public_key) {
          publicKeyPem = cert.public_key;
        }
      } catch {
        // Fallback query
      }
    }

    if (!publicKeyPem) {
      try {
        const res = await query<{ public_key: string }>(
          `SELECT public_key FROM endpoint_certificates WHERE agent_id = $1 AND is_revoked = false LIMIT 1`,
          [payload.agentId]
        );
        if (res.rows.length > 0) {
          publicKeyPem = res.rows[0].public_key;
        }
      } catch {
        // Database offline
      }
    }

    // 2. In unit test mode without enrolled keys, allow test fallback if explicitly provided
    if (!publicKeyPem && options?.allowTestKey) {
      return {
        verified: true,
        canonicalPayload: canonical,
        computedStateDigest: payload.hostStateDigest,
      };
    }

    if (!publicKeyPem) {
      return {
        verified: false,
        reason: `Enrolled certificate or public key for agent '${payload.agentId}' not found. Cannot verify authenticity.`,
        canonicalPayload: canonical,
        computedStateDigest: payload.hostStateDigest,
      };
    }

    // 3. Cryptographically verify signature
    try {
      const verifier = crypto.createVerify("RSA-SHA256");
      verifier.update(canonical, "utf8");
      const isValid = verifier.verify(publicKeyPem, payload.resultSignature, "base64");

      if (!isValid) {
        return {
          verified: false,
          reason: "Cryptographic signature mismatch: Agent result signature verification failed.",
          canonicalPayload: canonical,
          computedStateDigest: payload.hostStateDigest,
        };
      }

      return {
        verified: true,
        canonicalPayload: canonical,
        computedStateDigest: payload.hostStateDigest,
      };
    } catch (err: unknown) {
      return {
        verified: false,
        reason: `Cryptographic verification error: ${err instanceof Error ? err.message : String(err)}`,
        canonicalPayload: canonical,
        computedStateDigest: payload.hostStateDigest,
      };
    }
  }
}
