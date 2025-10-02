// initDb.js
import { query } from "./db.js";

export async function initDb() {
  await query("DROP TABLE IF EXISTS transcodes;");
  await query("DROP TABLE IF EXISTS videos;");

  await query(`
    CREATE TABLE videos (
      id SERIAL PRIMARY KEY,
      user_id VARCHAR(100) NOT NULL,
      filename VARCHAR(255) NOT NULL,
      s3_key TEXT NOT NULL,
      uploaded_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await query(`
    CREATE TABLE transcodes (
      id SERIAL PRIMARY KEY,
      video_id INT REFERENCES videos(id) ON DELETE CASCADE,
      format VARCHAR(50) NOT NULL,
      resolution VARCHAR(50),
      output_s3_key TEXT NOT NULL,
      status VARCHAR(50) DEFAULT 'pending',
      completed_at TIMESTAMP
    );
  `);

  console.log("DB tables dropped and recreated ✅");
}
