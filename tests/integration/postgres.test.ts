import "../setup";
import { before, after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { Pool } from "pg";
import { RealAgentExecutor, recordCommandResult } from "@/lib/fleet/fleet";
import { getTenantSubscription, updateTenantSubscription, setTenantSubscriptionStatus } from "@/lib/billing/plans";

// Dedicated disposable database only. Never fall back to DATABASE_URL.
const connectionString = process.env.SHIELDDESK_INTEGRATION_DATABASE_URL;
assert.ok(connectionString, "Provide SHIELDDESK_INTEGRATION_DATABASE_URL for this separate integration suite");
const target = new URL(connectionString);
assert.ok(["127.0.0.1", "localhost"].includes(target.hostname), "Integration database must be local");
assert.equal(target.pathname, "/shielddesk_integration", "Integration database must be dedicated and disposable");
const pool = new Pool({ connectionString, max: 4 });
const schema = readFileSync("db/schema.sql", "utf8");
const migration = readFileSync("db/migrations/phase_o_command_completion.sql", "utf8");
const tenant = "postgres-integration-a";
const userId = "postgres-integration-admin";
const agentId = randomUUID(), incidentId = randomUUID(), planId = randomUUID(), taskId = randomUUID();
let previousPool: Pool | undefined;

describe("Real PostgreSQL integration (disposable database)", () => {
  before(async () => {
    previousPool = global.__shieldDeskPgPool;
    global.__shieldDeskPgPool = pool;
    await pool.query(schema);
  });
  after(async () => { global.__shieldDeskPgPool = previousPool; await pool.end(); });

  it("installs the authoritative schema idempotently", async () => {
    await pool.query(schema);
    const result = await pool.query("SELECT to_regclass('mitigation_tasks') AS tasks, to_regclass('tenant_subscriptions') AS subscriptions");
    assert.equal(result.rows[0].tasks, "mitigation_tasks");
    assert.equal(result.rows[0].subscriptions, "tenant_subscriptions");
  });

  it("upgrades legacy command/task constraints and can rerun the migration", async () => {
    await pool.query("ALTER TABLE mitigation_tasks DROP COLUMN execution_command_id");
    await pool.query("ALTER TABLE mitigation_tasks DROP CONSTRAINT mitigation_tasks_status_check");
    await pool.query("ALTER TABLE mitigation_tasks ADD CONSTRAINT mitigation_tasks_status_check CHECK (status IN ('pending','approved','rejected','in_progress','completed'))");
    await pool.query(migration);
    await pool.query(migration);
    const columns = await pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='mitigation_tasks' AND column_name='execution_command_id'");
    assert.equal(columns.rowCount, 1);
  });

  it("persists and reloads billing lifecycle state without mixing tenants", async () => {
    await updateTenantSubscription(tenant, "professional", "stripe", "sub_pg_test");
    await updateTenantSubscription("postgres-integration-b", "community");
    assert.equal((await getTenantSubscription(tenant)).tier, "professional");
    await setTenantSubscriptionStatus(tenant, "past_due", { currentPeriodEnd: "2031-02-03T00:00:00.000Z" });
    const subscription = await getTenantSubscription(tenant);
    assert.equal(subscription.status, "past_due");
    assert.equal(subscription.subscriptionId, "sub_pg_test");
    assert.equal(new Date(subscription.currentPeriodEnd).toISOString(), "2031-02-03T00:00:00.000Z");
    assert.equal((await getTenantSubscription("postgres-integration-b")).tier, "community");
  });

  it("binds a durable dispatch, settles success, and reopens a late failed task", async () => {
    await pool.query("INSERT INTO users(id,tenant_id,role) VALUES($1,$2,'system_admin')", [userId,tenant]);
    await pool.query("INSERT INTO incidents(id,incident_code,tenant_id,severity,status,title) VALUES($1,'INC-PG-TEST',$2,'high','open','Integration fixture')", [incidentId,tenant]);
    await pool.query("INSERT INTO mitigation_plans(id,incident_id,tenant_id,status) VALUES($1,$2,$3,'active')", [planId,incidentId,tenant]);
    await pool.query("INSERT INTO mitigation_tasks(id,plan_id,tenant_id,horizon,title,status) VALUES($1,$2,$3,'immediate','Integration task','approved')", [taskId,planId,tenant]);
    const inserted = await pool.query("INSERT INTO endpoint_agents(id,tenant_id,hostname,ip_address,os_type,status) VALUES($1,$2,'PG-TEST-ENDPOINT','192.0.2.11','linux','connected') RETURNING *", [agentId,tenant]);
    const commandId = randomUUID();
    const result = await new RealAgentExecutor().execute({agent:inserted.rows[0],caller:{id:userId,tenant_id:tenant,role:"system_admin"},command:"take_safety_snapshot",tier:"Tier 1",commandLogId:commandId,signature:"integration-fixture-signature",nonce:randomUUID(),taskId});
    assert.equal(result.state,"queued");
    const task = () => pool.query("SELECT status,execution_command_id FROM mitigation_tasks WHERE id=$1",[taskId]);
    assert.equal((await task()).rows[0].execution_command_id,commandId);
    assert.equal((await task()).rows[0].status,"in_progress");
    assert.equal((await recordCommandResult({commandId,agentId,status:"executed",output:"Fixture execution"})).success,true);
    assert.equal((await task()).rows[0].status,"completed");
    await recordCommandResult({commandId,agentId,status:"failed",output:"Fixture late failure"});
    assert.equal((await task()).rows[0].status,"failed");
    assert.equal((await pool.query("SELECT status FROM mitigation_plans WHERE id=$1",[planId])).rows[0].status,"active");
  });
});
