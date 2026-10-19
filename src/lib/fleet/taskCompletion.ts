import { query } from "@/lib/db";
import type { CommandExecutionState } from "./fleet";

/** Settle only the task bound to this dispatch, after an endpoint result. */
export async function settleCommandTask(command: {
  id: string;
  tenant_id: string;
  status: CommandExecutionState;
}): Promise<void> {
  const succeeded = command.status === "executed" || command.status === "verified";
  const failed = ["failed", "rolled_back", "cancelled", "expired", "delivery_failed", "execution_failed", "verification_failed"].includes(command.status);
  if (!succeeded && !failed) return;

  const result = await query<{ id: string; plan_id: string | null }>(
    `UPDATE mitigation_tasks SET status = $1
     WHERE execution_command_id = $2 AND tenant_id = $3 AND status = 'in_progress'
     RETURNING id, plan_id`,
    [succeeded ? "completed" : "failed", command.id, command.tenant_id]
  );
  for (const task of result.rows) {
    if (!task.plan_id) continue;
    await query(
      `UPDATE mitigation_plans p SET status = $1, updated_at = NOW()
       WHERE p.id = $2 AND p.tenant_id = $3
       AND ($1 = 'active' OR NOT EXISTS (
         SELECT 1 FROM mitigation_tasks t WHERE t.plan_id = p.id AND t.status != 'completed'
       ))`,
      [succeeded ? "completed" : "active", task.plan_id, command.tenant_id]
    );
  }
}
