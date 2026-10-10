const { Client } = require('pg');
const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: '.env.local' });

async function migrate() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('DATABASE_URL not found in .env.local');
  }

  const client = new Client({
    connectionString,
    ssl: { rejectUnauthorized: false }
  });
  await client.connect();
  console.log('Connected to PostgreSQL (Supabase)...');

  const sql = fs.readFileSync(path.join(__dirname, '../db/migrations/phase_m_commercial_licensing_stripe.sql'), 'utf-8');
  await client.query(sql);
  console.log('✅ Migration Phase M (Commercial Licensing & Stripe) applied successfully.');

  const res = await client.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name");
  console.log(`Total public tables now in DB: ${res.rows.length}`);
  const newTables = [
    'billing_customers',
    'product_catalog_prices',
    'checkout_attempts',
    'tenant_subscriptions',
    'subscription_status_history',
    'invoices',
    'product_licenses',
    'license_activations',
    'stripe_webhook_events',
    'notification_outbox'
  ];
  const present = res.rows.map(r => r.table_name);
  for (const t of newTables) {
    console.log(`  - Table ${t}: ${present.includes(t) ? 'EXISTS' : 'MISSING'}`);
  }

  await client.end();
}

migrate().catch(err => {
  console.error('Migration failed:', err);
  process.exit(1);
});
