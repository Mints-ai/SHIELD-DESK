const { query } = require("../src/lib/db");
async function main() {
  const res = await query("SELECT id, hostname, core_telemetry FROM endpoint_agents WHERE id = $1", ["5a6ae808-7424-4b25-bf03-d337b052a016"]);
  console.log("Rows count:", res.rows.length);
  if (res.rows.length > 0) {
    console.log("core_telemetry type:", typeof res.rows[0].core_telemetry);
    console.log("core_telemetry value:", JSON.stringify(res.rows[0].core_telemetry));
  }
  process.exit(0);
}
main().catch(err => { console.error(err); process.exit(1); });
