const { Client } = require('pg');
const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: '.env.local' });

async function migrate() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  await client.connect();
  console.log('Connected to PostgreSQL (Supabase)...');

  const sql = fs.readFileSync(path.join(__dirname, '../db/migrations/phase_f_evidence_vault.sql'), 'utf-8');
  await client.query(sql);
  console.log('Migration Phase F applied successfully.');

  const res = await client.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public'");
  console.log(`Total public tables now in DB: ${res.rows.length}`);
  await client.end();
}

migrate().catch(err => {
  console.error(err);
  process.exit(1);
});
