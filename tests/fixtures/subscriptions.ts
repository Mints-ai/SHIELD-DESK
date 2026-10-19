import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { before, after } from "node:test";
import type { Pool } from "pg";
const ddl = readFileSync("db/schema.sql", "utf8").match(/CREATE TABLE IF NOT EXISTS tenant_subscriptions \(([\s\S]*?)\n\);/)![1];
const columns = new Set([...ddl.matchAll(/^\s+(\w+)\s+\w+/gm)].map((match) => match[1]));
type Row = Record<string, unknown>;

export class SubscriptionDatabase {
  rows = new Map<string, Row>();
  users: unknown[][] = [];
  fail = false;

  async end() {}

  async query(sql: string, params: unknown[] = []) {
    if (this.fail) throw new Error("database unavailable");
    if (/INSERT INTO users/i.test(sql)) this.users.push(params);
    if (!/\btenant_subscriptions\b/i.test(sql)) throw new Error("Subscription fixture does not implement this query");
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

export function useSubscriptionFixture() {
 let previous: Pool | undefined;
 before(() => {
  previous = global.__shieldDeskPgPool;
  const db = new SubscriptionDatabase();
  for (const [tenant_id,tier] of [["acme-tenant","professional"],["globex-tenant","community"]]) {
   db.rows.set(tenant_id,{id:"fixture-"+tenant_id,tenant_id,tier,status:"active",current_period_end:"2030-01-01T00:00:00.000Z",stripe_subscription_id:null});
  }
  global.__shieldDeskPgPool = db as unknown as Pool;
 });
 after(() => { global.__shieldDeskPgPool = previous; });
}
