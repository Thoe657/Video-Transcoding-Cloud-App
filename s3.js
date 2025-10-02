import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

let s3;
let bucket;

export function initS3({ Bucket, Region }) {
  bucket = Bucket;
  s3 = new S3Client({ region: Region });
}

// Generate a pre-signed upload URL
export async function generatePresignedUploadKey({ userId, filename, contentType }) {
  if (!s3) throw new Error("S3 not initialized. Call initS3() first.");

  const key = `${userId}/${Date.now()}-${filename}`;
  const command = new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    ContentType: contentType
  });

  const url = await getSignedUrl(s3, command, { expiresIn: 3600 });
  return { url, key };
}

// Generate a pre-signed download URL
export async function generatePresignedDownloadKey({ userId, filename }) {
  if (!s3) throw new Error("S3 not initialized. Call initS3() first.");

  const command = new GetObjectCommand({
    Bucket: bucket,
    Key: filename
  });

  const url = await getSignedUrl(s3, command, { expiresIn: 3600 });
  return url;
}
