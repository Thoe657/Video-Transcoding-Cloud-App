import { initDb, query } from "./db.js";
import { initS3 } from "./s3.js";
import { S3Client, ListObjectsV2Command, DeleteObjectsCommand } from "@aws-sdk/client-s3";

// Load secrets
const secrets = {
  PGHOST: process.env.PGHOST,
  PGUSER: process.env.PGUSER,
  PGPASSWORD: process.env.PGPASSWORD,
  PGDATABASE: process.env.PGDATABASE,
  PGPORT: process.env.PGPORT,
  S3_BUCKET: process.env.S3_BUCKET,
  AWS_REGION: "ap-southeast-2",
};

await initDb({
  host: secrets.PGHOST,
  user: secrets.PGUSER,
  password: secrets.PGPASSWORD,
  database: secrets.PGDATABASE,
  port: secrets.PGPORT,
});

initS3({ Bucket: secrets.S3_BUCKET, Region: secrets.AWS_REGION });

const s3 = new S3Client({ region: secrets.AWS_REGION });

async function clearPostgres() {
  console.log("Deleting all videos and transcodes from Postgres...");
  await query("DELETE FROM transcodes");
  await query("DELETE FROM videos");
  console.log("Postgres tables cleared.");
}

async function clearS3() {
  console.log("Deleting all files from S3 bucket...");
  const list = await s3.send(new ListObjectsV2Command({ Bucket: secrets.S3_BUCKET }));
  if (!list.Contents || list.Contents.length === 0) {
    console.log("No files found in S3 bucket.");
    return;
  }

  const keys = list.Contents.map(obj => ({ Key: obj.Key }));
  await s3.send(new DeleteObjectsCommand({
    Bucket: secrets.S3_BUCKET,
    Delete: { Objects: keys }
  }));

  console.log(`Deleted ${keys.length} files from S3.`);
}

async function main() {
  await clearPostgres();
  await clearS3();
  console.log("All cleared!");
}

main().catch(err => console.error(err));
