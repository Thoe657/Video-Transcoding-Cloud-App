import pkg from "pg";
const { Pool } = pkg;

let pool;

export async function initDb(config) {
  pool = new Pool(config);
  await pool.query("SELECT 1");
  console.log("Database connected");
}

export async function query(text, params) {
  const client = await pool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
}
