const { Client } = require('pg');
const fs = require('fs');
require('dotenv').config({ path: '.env.local' });

async function run() {
  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();
  console.log('Connected to Supabase.');
  const sql = fs.readFileSync('db/migrations/phase_b_security_digital_twin.sql', 'utf8');
  await client.query(sql);
  console.log('Phase B migration applied successfully.');
  const tables = await client.query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename");
  console.log('Tables now (' + tables.rows.length + '):', tables.rows.map(r => r.tablename).join(', '));
  await client.end();
}
run().catch(e => { console.error('MIGRATION FAILED:', e.message); process.exit(1); });
