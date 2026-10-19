import "./setup";
import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { Pool } from "pg";
import { NextRequest } from "next/server";
import { POST as signup } from "@/app/api/auth/signup/route";
import { getTenantSubscription, setTenantSubscriptionStatus, updateTenantSubscription } from "@/lib/billing/plans";

// This fake validates the SQL against the checked-in schema; no database or
// payment provider is contacted. It is not a replacement for PostgreSQL tests.
const ddl = readFileSync("db/schema.sql", "utf8").match(/CREATE TABLE IF NOT EXISTS tenant_subscriptions \(([\s\S]*?)\n\);/)![1];
const columns = new Set([...ddl.matchAll(/^\s+(\w+)\s+\w+/gm)].map((match) => match[1]));
type Row = Record<string, unknown>;

class SubscriptionDatabase {
  rows = new Map<string, Row>();
  users: unknown[][] = [];
  fail = false;

  async query(sql: string, params: unknown[] = []) {
    if (this.fail) throw new Error("database unavailable");
    if (/INSERT INTO users/i.test(sql)) this.users.push(params);
    if (!/\btenant_subscriptions\b/i.test(sql)) return { rows: [], rowCount: 0 };
    const select = sql.match(/SELECT\s+([\s\S]+?)\s+FROM/i);
    const insert = sql.match(/INSERT INTO tenant_subscriptions\s*\(([^)]+)\)\s*VALUES\s*\(([\s\S]*?)\)\s*ON CONFLICT/i);
    const referenced = (select?.[1] || insert?.[1] || "").split(",").map((name) => name.trim());
    for (const name of referenced) assert.ok(columns.has(name), `Unknown subscription column: ${name}`);
    if (select) {
      const row = this.rows.get(String(params[0]));
      return { rows: row ? [{ ...row }] : [], rowCount: row ? 1 : 0 };
    }
    assert.ok(insert, "Expected subscription INSERT");
    const resolveValue = (expression: string): unknown => {
      const value = expression.trim();
      if (/^\$\d+$/.test(value)) return params[Number(value.slice(1)) - 1];
      if (/^'[^']*'$/.test(value)) return value.slice(1, -1);
      if (/^NOW\(\)/i.test(value)) return "2030-01-01T00:00:00.000Z";
      throw new Error(`Unsupported test SQL value: ${value}`);
    };
    const values = insert[2].split(",");
    const row = Object.fromEntries(referenced.map((name, index) => [name, resolveValue(values[index])]));
    assert.ok(typeof row.id === "string" && row.id.length > 0 && row.id.length <= 64, "Subscription requires an explicit primary key");
    const tenantId = String(row.tenant_id);
    const existing = this.rows.get(tenantId);
    if (existing) {
      const assignments = sql.match(/DO UPDATE\s+SET\s+([\s\S]*)/i)?.[1];
      if (assignments) {
        for (const assignment of assignments.split(",")) {
          const [name, expression] = assignment.split("=").map((part) => part.trim());
          assert.ok(columns.has(name), `Unknown update column: ${name}`);
          existing[name] = resolveValue(expression);
        }
      }
    } else this.rows.set(tenantId, row);
    return { rows: [], rowCount: 1 };
  }
}

describe("Canonical subscription persistence contract", () => {
  const env: Record<string, string | undefined> = process.env;
  let previousEnv: string | undefined;
  let previousPool: Pool | undefined;
  let previousFetch: typeof fetch;
  let db: SubscriptionDatabase;

  beforeEach(() => {
    previousEnv = env.NODE_ENV;
    previousPool = global.__shieldDeskPgPool;
    previousFetch = global.fetch;
    env.NODE_ENV = "production";
    db = new SubscriptionDatabase();
    global.__shieldDeskPgPool = db as unknown as Pool;
    global.fetch = async () => { throw new Error("External network disabled in this test"); };
  });
  afterEach(() => {
    if (previousEnv === undefined) delete env.NODE_ENV;
    else env.NODE_ENV = previousEnv;
    global.__shieldDeskPgPool = previousPool;
    global.fetch = previousFetch;
  });

  it("creates a valid community subscription during production signup", async () => {
    const response = await signup(new NextRequest("http://localhost/api/auth/signup", {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": "192.0.2.190" },
      body: JSON.stringify({ email: "schema-test@example.invalid", password: "local-regression-only", organizationName: "Schema Test" }),
    }));
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(db.users.length, 1);
    assert.equal(db.rows.get(result.tenantId)?.tier, "community");
  });

  it("reloads the Stripe provider and subscription identifier from canonical columns", async () => {
    await updateTenantSubscription("schema-stripe", "professional", "stripe", "sub_schema_test");
    const result = await getTenantSubscription("schema-stripe");
    assert.equal(result.tier, "professional");
    assert.equal(result.paymentProvider, "stripe");
    assert.equal(result.subscriptionId, "sub_schema_test");
  });

  it("keeps the local row identity and billing period across Stripe lifecycle updates", async () => {
    await updateTenantSubscription("schema-lifecycle", "enterprise", "stripe", "sub_lifecycle");
    const id = db.rows.get("schema-lifecycle")?.id;
    await setTenantSubscriptionStatus("schema-lifecycle", "past_due", { currentPeriodEnd: "2031-02-03T00:00:00.000Z" });
    const result = await getTenantSubscription("schema-lifecycle");
    assert.equal(db.rows.get("schema-lifecycle")?.id, id);
    assert.equal(result.status, "past_due");
    assert.equal(result.currentPeriodEnd, "2031-02-03T00:00:00.000Z");
    assert.equal(result.subscriptionId, "sub_lifecycle");
  });

  it("does not misclassify manual and Razorpay identifiers as Stripe subscriptions", async () => {
    for (const provider of ["manual", "razorpay"] as const) {
      await updateTenantSubscription(`schema-${provider}`, "professional", provider, `${provider}_id`);
      assert.equal(db.rows.get(`schema-${provider}`)?.stripe_subscription_id, null);
      assert.notEqual((await getTenantSubscription(`schema-${provider}`)).paymentProvider, "stripe");
    }
  });

  it("fails closed on actual database errors in production", async () => {
    db.fail = true;
    await assert.rejects(getTenantSubscription("schema-offline"), /CRITICAL_DATABASE_UNAVAILABLE/);
    await assert.rejects(updateTenantSubscription("schema-offline", "professional", "stripe", "sub_offline"), /CRITICAL_DATABASE_UNAVAILABLE/);
  });
});
