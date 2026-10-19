import "./setup";
import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import type { Pool } from "pg";
import { NextRequest } from "next/server";
import { PATCH as patchTask } from "@/app/api/tasks/[id]/route";
import { RealAgentExecutor, recordCommandResult, type CommandExecutionParams, type AgentCommandQueueRecord } from "@/lib/fleet/fleet";

type Task = { id: string; tenant_id: string; plan_id: string; status: string; execution_command_id?: string };
class LifecycleDatabase {
  tasks: Task[] = [{ id: "task-a", tenant_id: "mints-global", plan_id: "plan-a", status: "approved" }];
  commands = new Map<string, AgentCommandQueueRecord>();
  planStatus = "active";
  failQueue = false;
  async query(sql: string, p: unknown[] = []) {
    if (sql.includes("WITH bound_task")) {
      if (this.failQueue) throw new Error("queue storage unavailable");
      const task = this.tasks.find((t) => t.id === p[11] && t.tenant_id === p[2] && ["pending", "approved", "failed"].includes(t.status));
      if (!task) return { rows: [] };
      task.execution_command_id = String(p[0]);
      task.status = "in_progress";
      this.commands.set(String(p[0]), { id: String(p[0]), agent_id: String(p[1]), tenant_id: String(p[2]), command: String(p[3]), tier: "Tier 1", token_id: null, signature: "signed", status: "queued", created_at: new Date().toISOString() });
      return { rows: [{ id: p[0] }] };
    }
    if (sql.startsWith("SELECT id FROM endpoint_agents")) return { rows: [{ id: p[0] }] };
    if (sql.includes("SELECT id, agent_id, tenant_id, command FROM agent_commands")) return { rows: this.commands.has(String(p[0])) ? [this.commands.get(String(p[0]))] : [] };
    if (sql.includes("UPDATE agent_commands")) {
      const command = this.commands.get(String(p[3]));
      if (!command) return { rows: [] };
      command.status = p[0] as AgentCommandQueueRecord["status"];
      command.result = JSON.parse(String(p[1]));
      return { rows: [command] };
    }
    if (sql.includes("UPDATE mitigation_tasks SET status = $1")) {
      const task = this.tasks.find((t) => t.execution_command_id === p[1] && t.tenant_id === p[2] && (t.status === "in_progress" || (t.status === "completed" && p[0] === "failed")));
      if (!task) return { rows: [] };
      task.status = String(p[0]);
      return { rows: [task] };
    }
    if (sql.includes("UPDATE mitigation_plans p")) {
      if (p[0] === "active" || !this.tasks.some((t) => t.plan_id === p[1] && t.status !== "completed")) this.planStatus = String(p[0]);
    }
    if (sql.startsWith("SELECT * FROM mitigation_tasks")) return { rows: this.tasks.filter((t) => t.id === p[0]) };
    return { rows: [] };
  }
}

describe("Endpoint-confirmed task completion", () => {
  let savedPool: Pool | undefined;
  let db: LifecycleDatabase;
  const params = (command = "take_safety_snapshot"): CommandExecutionParams => ({
    agent: { id: "agent-a", hostname: "TEST-ENDPOINT", tenant_id: "mints-global", ip_address: "192.0.2.44", os_type: "linux", agent_version: "test", status: "connected", cpu_usage: 0, memory_usage: 0, eps: 0, kill_switch_active: false, safety_snapshot_id: null, last_heartbeat: new Date().toISOString(), created_at: new Date().toISOString() },
    caller: { id: "dev-admin", role: "system_admin", tenant_id: "mints-global" },
    command, commandLogId: "command-a", tier: "Tier 1", signature: "signed", nonce: "test-nonce", taskId: "task-a",
  });
  beforeEach(() => { savedPool = global.__shieldDeskPgPool; db = new LifecycleDatabase(); global.__shieldDeskPgPool = db as unknown as Pool; });
  afterEach(() => { global.__shieldDeskPgPool = savedPool; });

  it("queues even Tier 1 and containment commands without claiming execution", async () => {
    for (const command of ["take_safety_snapshot", "block_ip 192.0.2.44", "unblock_ip 192.0.2.44", "isolate_host"]) {
      db.tasks[0].status = "approved";
      const result = await new RealAgentExecutor().execute(params(command));
      assert.equal(result.state, "queued");
      assert.match(result.output, /Awaiting endpoint/);
      assert.equal(db.tasks[0].status, "in_progress");
      assert.equal(db.planStatus, "active");
    }
  });
  it("settles a task and its plan only after the endpoint reports success", async () => {
    await new RealAgentExecutor().execute(params());
    await recordCommandResult({ commandId: "command-a", agentId: "agent-a", status: "executing", output: "running" });
    assert.equal(db.tasks[0].status, "in_progress");
    await recordCommandResult({ commandId: "command-a", agentId: "agent-a", status: "executed", output: "snapshot saved", verified: true });
    assert.equal(db.tasks[0].status, "completed");
    assert.equal(db.planStatus, "completed");
  });
  it("does not complete a parent plan while another task is pending", async () => {
    db.tasks.push({ id: "task-b", tenant_id: "mints-global", plan_id: "plan-a", status: "pending" });
    await new RealAgentExecutor().execute(params());
    await recordCommandResult({ commandId: "command-a", agentId: "agent-a", status: "executed", output: "done" });
    assert.equal(db.tasks[0].status, "completed");
    assert.equal(db.planStatus, "active");
  });
  it("reopens a completed plan when its current dispatch later fails or rolls back", async () => {
    for (const status of ["failed", "rolled_back", "verification_failed"] as const) {
      db.tasks[0].status = "approved";
      await new RealAgentExecutor().execute(params());
      await recordCommandResult({ commandId: "command-a", agentId: "agent-a", status: "executed", output: "executed" });
      assert.equal(db.tasks[0].status, "completed");
      await recordCommandResult({ commandId: "command-a", agentId: "agent-a", status, output: "restore required" });
      assert.equal(db.tasks[0].status, "failed");
      assert.equal(db.planStatus, "active");
      await recordCommandResult({ commandId: "command-a", agentId: "agent-a", status: "executed", output: "stale success" });
      assert.equal(db.tasks[0].status, "failed");
    }
  });
  it("preserves containment failures and elevation errors instead of manufacturing success", async () => {
    for (const output of ["requires elevation", "refusing to block loopback interface", "unrecognized command action: unblock_ip", "firewall denied"]) {
      db.tasks[0].status = "approved";
      await new RealAgentExecutor().execute(params("block_ip 192.0.2.44"));
      await recordCommandResult({ commandId: "command-a", agentId: "agent-a", status: "failed", output });
      assert.equal(db.commands.get("command-a")?.status, "failed");
      assert.equal(db.commands.get("command-a")?.result?.output, output);
      assert.equal(db.tasks[0].status, "failed");
      assert.equal(db.planStatus, "active");
    }
  });
  it("rejects another agent's result and duplicate task dispatch", async () => {
    await new RealAgentExecutor().execute(params());
    assert.equal((await recordCommandResult({ commandId: "command-a", agentId: "other-agent", status: "executed", output: "spoofed" })).unauthorized, true);
    assert.equal(db.tasks[0].status, "in_progress");
    await assert.rejects(new RealAgentExecutor().execute(params()), /TASK_DISPATCH_CONFLICT/);
  });
  it("does not let an older dispatch finish a newer attempt", async () => {
    await new RealAgentExecutor().execute(params());
    db.tasks[0].execution_command_id = "newer-command";
    await recordCommandResult({ commandId: "command-a", agentId: "agent-a", status: "executed", output: "old result" });
    assert.equal(db.tasks[0].status, "in_progress");
    assert.equal(db.planStatus, "active");
  });
  it("does not acknowledge a dispatch that was not persisted", async () => {
    db.failQueue = true;
    await assert.rejects(new RealAgentExecutor().execute(params()), /queue storage unavailable/);
    assert.equal(db.tasks[0].status, "approved");
  });
  it("prevents manually marking an endpoint-bound task complete", async () => {
    await new RealAgentExecutor().execute(params());
    const response = await patchTask(new NextRequest("http://localhost/api/tasks/task-a", { method: "PATCH", headers: { "content-type": "application/json", "x-shielddesk-user": "dev-admin" }, body: JSON.stringify({ status: "completed" }) }), { params: Promise.resolve({ id: "task-a" }) });
    assert.equal(response.status, 409);
    assert.equal(db.tasks[0].status, "in_progress");
  });
});
