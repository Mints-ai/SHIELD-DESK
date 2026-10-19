import { before, after } from "node:test";
import type { Pool } from "pg";

// Route-unit fixture, not a PostgreSQL integration test. Unsupported queries
// fail so unrelated services use their explicit offline paths.
export function useTaskFixture() {
 let previous: Pool | undefined;
 const tasks: Record<string, unknown>[] = [
  {id:"fixture-task-mints",tenant_id:"mints-global",title:"Fixture task",status:"pending"},
  {id:"fixture-task-other",tenant_id:"other-tenant",title:"Foreign fixture",status:"pending"},
 ];
 const plans = [{id:"fixture-plan-mints",tenant_id:"mints-global"},{id:"fixture-plan-other",tenant_id:"other-tenant"}];
 before(() => {
  previous=global.__shieldDeskPgPool;
  global.__shieldDeskPgPool={
   async query(sql:string, params:unknown[]=[]) {
    if (/FROM mitigation_tasks t/.test(sql)) {
     const tenantParam=/t\.tenant_id = \$(\d+)/.exec(sql);
     const rows=tasks.filter(t=>!tenantParam || t.tenant_id===params[Number(tenantParam[1])-1]);
     return {rows,rowCount:rows.length};
    }
    if (/FROM ranked_plans/.test(sql)) {
     const tenantParam=/p\.tenant_id = \$(\d+)/.exec(sql);
     const rows=plans.filter(p=>!tenantParam || p.tenant_id===params[Number(tenantParam[1])-1]);
     return {rows,rowCount:rows.length};
    }
    if (/SELECT id FROM mitigation_plans WHERE tenant_id/.test(sql)) return {rows:plans.filter(p=>p.tenant_id===params[0]),rowCount:1};
    if (/INSERT INTO mitigation_tasks/.test(sql)) {
     const [id,plan_id,tenant_id,horizon,title,description,tier,blast_radius,cve_id,assigned_to]=params;
     const row={id,plan_id,tenant_id,horizon,title,description,tier,status:"pending",blast_radius,cve_id,assigned_to};
     tasks.push(row);return {rows:[row],rowCount:1};
    }
    throw new Error("Task fixture does not implement this query");
   }, async end() {},
  } as unknown as Pool;
 });
 after(()=>{global.__shieldDeskPgPool=previous;});
}
