// fetchVideos.js
import pkg from 'pg';

const { Pool } = pkg;

async function main() {
  const pool = new Pool({
    host: process.env.PGHOST,
    port: Number(process.env.PGPORT ?? 5432),
    user: process.env.PGUSER,
    password: process.env.PGPASSWORD,
    database: process.env.PGDATABASE,
    ssl: { rejectUnauthorized: false }, // required for RDS
  });

  try {
    const query = `
      SELECT id, user_id, filename, uploaded_at
      FROM videos
      ORDER BY uploaded_at DESC
      LIMIT 10;
    `;
    const { rows } = await pool.query(query);
    console.table(rows);
  } catch (err) {
    console.error('Failed to fetch videos:', err);
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
