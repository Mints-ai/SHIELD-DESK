import { Request, Response, NextFunction } from "express";
import { verifyAccessToken, TokenPayload } from "./auth.js";
import { checkRateLimit } from "./redis.js";

export interface AuthenticatedRequest extends Request {
  user?: TokenPayload;
  tenantId?: string;
}

// IP-based Rate Limiter (Max 100 requests per 60 seconds)
export async function rateLimiter(req: Request, res: Response, next: NextFunction) {
  const ip = req.ip || req.socket.remoteAddress || "127.0.0.1";
  const { allowed, remaining } = await checkRateLimit(ip, 120);

  res.setHeader("X-RateLimit-Limit", "120");
  res.setHeader("X-RateLimit-Remaining", remaining.toString());

  if (!allowed) {
    return res.status(429).json({ error: "Rate limit exceeded. Please back off." });
  }
  next();
}

// JWT Authentication & Tenant Injection
export function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or malformed Authorization header" });
  }

  const token = authHeader.slice(7);
  try {
    const payload = verifyAccessToken(token);
    req.user = payload;
    req.tenantId = payload.tenant_id; // Never trust client-supplied tenant_id!
    next();
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Invalid token";
    return res.status(401).json({ error: "Invalid or expired token", details: message });
  }
}

// RBAC Role Gate
export function requireRole(allowedRoles: Array<"owner" | "admin" | "member" | "viewer">) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: "Unauthenticated" });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: "Forbidden: insufficient permissions",
        required: allowedRoles,
        actual: req.user.role,
      });
    }

    next();
  };
}
