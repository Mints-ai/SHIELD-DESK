import fs from "node:fs";
import path from "node:path";
import pg from "pg";

// 1. Read .env.local to get DATABASE_URL
let databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl && fs.existsSync(".env.local")) {
  const envContent = fs.readFileSync(".env.local", "utf8");
  for (const line of envContent.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.startsWith("DATABASE_URL=")) {
      databaseUrl = trimmed.substring("DATABASE_URL=".length).replace(/["']/g, "").trim();
      break;
    }
  }
}

if (!databaseUrl) {
  console.error("❌ No DATABASE_URL found in process.env or .env.local.");
  process.exit(1);
}

console.log("🔗 Connecting to Supabase database...");
const client = new pg.Client({
  connectionString: databaseUrl,
  connectionTimeoutMillis: 10000,
  ssl: databaseUrl.includes("localhost") ? false : { rejectUnauthorized: false },
});

async function main() {
  try {
    await client.connect();
    console.log("✅ Connected successfully to PostgreSQL database.");

    // Step 1: Run db/schema.sql
    console.log("📜 Executing db/schema.sql...");
    const schemaSql = fs.readFileSync(path.join(process.cwd(), "db", "schema.sql"), "utf8");
    await client.query(schemaSql);
    console.log("✅ db/schema.sql executed successfully.");

    // Step 2: Run db/migrations/launch_readiness_001.sql
    console.log("📜 Executing db/migrations/launch_readiness_001.sql...");
    const migrationSql = fs.readFileSync(
      path.join(process.cwd(), "db", "migrations", "launch_readiness_001.sql"),
      "utf8"
    );
    await client.query(migrationSql);
    console.log("✅ db/migrations/launch_readiness_001.sql executed successfully.");

    // Step 3: Run db/seed.sql
    console.log("🌱 Executing db/seed.sql...");
    const seedSql = fs.readFileSync(path.join(process.cwd(), "db", "seed.sql"), "utf8");
    await client.query(seedSql);
    console.log("✅ db/seed.sql executed successfully.");

    // Step 4: Verify tables
    console.log("🔍 Verifying created tables in public schema...");
    const res = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      ORDER BY table_name;
    `);

    console.log(`\n🎉 Found ${res.rows.length} tables in Supabase:`);
    for (const row of res.rows) {
      console.log(`  - ${row.table_name}`);
    }

    await client.end();
    console.log("\n🚀 Supabase database migration and seeding complete!");
  } catch (err) {
    console.error("❌ Migration error:", err.message);
    if (err.stack) console.error(err.stack);
    await client.end().catch(() => {});
    process.exit(1);
  }
}

main();
