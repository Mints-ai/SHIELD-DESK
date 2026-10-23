/**
 * ShieldDesk — Real Endpoint Enrollment Token Generator
 * 
 * Generates an authentic cryptographic enrollment token stored in PostgreSQL.
 * NO MOCK DATA is generated or accepted.
 * 
 * Usage:
 *   npx tsx scratch/generate_token.ts [hostname]
 */

import fs from "fs";
import path from "path";
import crypto from "crypto";

// 1. Ensure .env.local is loaded so real database credentials are active
const envPath = path.resolve(process.cwd(), ".env.local");
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, "utf-8");
  for (const line of envContent.split("\n")) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith("#") && trimmed.includes("=")) {
      const idx = trimmed.indexOf("=");
      const key = trimmed.slice(0, idx).trim();
      const val = trimmed.slice(idx + 1).trim();
      if (!process.env[key]) {
        process.env[key] = val;
      }
    }
  }
}

async function main() {
  const targetHost = process.argv[2] || "Kali-Linux";
  const controlUrl = process.env.CONTROL_PLANE_URL || "http://localhost:3000";

  console.log("==========================================================");
  console.log("      SHIELDDESK REAL ENROLLMENT TOKEN GENERATOR          ");
  console.log("==========================================================");
  console.log(`[*] Target Hostname:   ${targetHost}`);
  console.log(`[*] Control Plane URL: ${controlUrl}`);

  // Method 1: Generate directly via live Control Plane API (guarantees DB sync + hashchain audit)
  try {
    const apiRes = await fetch(`${controlUrl}/api/fleet/enrollment-tokens`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-admin",
      },
      body: JSON.stringify({
        label: `Production Agent: ${targetHost}`,
        expiresInHours: 24,
        maxUses: 1,
      }),
    });

    if (apiRes.ok) {
      const data = await apiRes.json();
      if (data.success && data.token) {
        printSuccess(data.token, data.tokenId, data.expiresAt, data.tenantId, targetHost);
        process.exit(0);
      }
    }
  } catch {
    // If local dev server is unreachable, fallback to direct PostgreSQL insertion (Method 2)
  }

  // Method 2: Direct PostgreSQL insertion into real database
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error("\n[!] FATAL: DATABASE_URL is not configured and Control Plane API is unreachable.");
    console.error("    Token generation aborted because NO MOCK DATA is allowed.");
    process.exit(1);
  }

  try {
    const { Pool } = await import("pg");
    const pool = new Pool({
      connectionString: databaseUrl,
      ssl: { rejectUnauthorized: false },
    });

    const rawSecret = crypto.randomBytes(24).toString("base64url");
    const rawToken = `sdt_${rawSecret}`;
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const tokenId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    const tenantId = "mints-global";
    const label = `Production Agent: ${targetHost}`;

    await pool.query(
      `INSERT INTO endpoint_enrollment_tokens (id, tenant_id, token_hash, label, expires_at, max_uses, used_count, created_by, created_at)
       VALUES ($1, $2, $3, $4, $5, 1, 0, $6, now());`,
      [tokenId, tenantId, tokenHash, label, expiresAt, "dev-admin"]
    );

    await pool.end();

    printSuccess(rawToken, tokenId, expiresAt, tenantId, targetHost);
    process.exit(0);
  } catch (dbErr) {
    console.error("\n[-] FATAL: Failed to persist authentic token into PostgreSQL database:", dbErr);
    process.exit(1);
  }
}

function printSuccess(token: string, tokenId: string, expiresAt: string, tenantId: string, host: string) {
  console.log("\n[+] GENUINE ENROLLMENT TOKEN GENERATED (PERSISTED IN DATABASE):");
  console.log(`    Token:      \x1b[32m${token}\x1b[0m`);
  console.log(`    Token ID:   ${tokenId}`);
  console.log(`    Expires At: ${expiresAt}`);
  console.log(`    Tenant ID:  ${tenantId}`);

  console.log("\n==========================================================");
  console.log("   READY-TO-RUN COMMAND FOR KALI LINUX (Copy & Paste):    ");
  console.log("==========================================================");
  console.log("\n# In VirtualBox NAT use 10.0.2.2; in Host-Only use 192.168.56.1:\n");
  console.log(
    `curl -sSL -o shielddesk-agent "http://10.0.2.2:3000/api/agent/binary/linux-amd64" && ` +
    `chmod +x shielddesk-agent && ` +
    `sudo ./shielddesk-agent -token ${token} -control-url "http://10.0.2.2:3000" -hostname "${host}"\n`
  );
}

main();
