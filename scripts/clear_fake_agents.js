const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const FAKE_IDS = [
  'ea111111-1111-1111-1111-111111111111',
  'ea222222-2222-2222-2222-222222222222',
  'ea333333-3333-3333-3333-333333333333',
  'ea444444-4444-4444-4444-444444444444',
  'ea555555-5555-5555-5555-555555555555',
];

async function main() {
  try {
    // Remove fake command logs first (FK reference)
    const r1 = await pool.query(
      `DELETE FROM agent_command_logs WHERE agent_id = ANY($1::uuid[])`,
      [FAKE_IDS]
    );
    console.log('Removed fake command logs:', r1.rowCount);

    // Remove fake agents
    const r2 = await pool.query(
      `DELETE FROM endpoint_agents WHERE id = ANY($1::uuid[])`,
      [FAKE_IDS]
    );
    console.log('Removed fake agents from DB:', r2.rowCount);

    // Check what remains
    const r3 = await pool.query(
      `SELECT id, hostname, status FROM endpoint_agents ORDER BY created_at DESC`
    );
    console.log('Remaining real agents:', r3.rows.length);
    r3.rows.forEach(a => console.log(' -', a.hostname, '(', a.status, ')'));
  } catch (e) {
    console.error('Error:', e.message);
  } finally {
    await pool.end();
  }
}

main();
