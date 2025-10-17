import { fileURLToPath } from "url";
import path from "path";
import ffmpeg from "fluent-ffmpeg";
import ffmpegInstaller from "@ffmpeg-installer/ffmpeg";
ffmpeg.setFfmpegPath(ffmpegInstaller.path);
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { Upload } from "@aws-sdk/lib-storage";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand, ChangeMessageVisibilityCommand } from "@aws-sdk/client-sqs";
import { SSMClient, GetParametersCommand } from "@aws-sdk/client-ssm";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

function getEnvValue(key) {
  const value = process.env[key];
  return typeof value === "string" ? value.trim() : "";
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const defaultAwsRegion = "ap-southeast-2";
const parameterPath = "/11977132/videoapp/param/";

const ssm = new SSMClient({ region: defaultAwsRegion });
const secretsManager = new SecretsManagerClient({ region: defaultAwsRegion });

function normaliseKeyFromPath(basePath, fullName) {
  const suffix = fullName.startsWith(basePath) ? fullName.slice(basePath.length) : fullName;
  return suffix.replace(/^\/+/, "").replace(/[^a-zA-Z0-9_]/g, "_").toUpperCase();
}

function chunkArray(items, size) {
  const result = [];
  for (let i = 0; i < items.length; i += size) {
    result.push(items.slice(i, i + size));
  }
  return result;
}

async function loadParametersFromStore(path, keys = []) {
  if (!path) return {};
  const parameters = {};
  const normalisedPath = path.endsWith("/") ? path : `${path}/`;
  const names = keys.length
    ? keys.map(key => `${normalisedPath}${key}`)
    : [];
  if (names.length === 0) return parameters;
  const chunks = chunkArray(names, 10);
  for (const group of chunks) {
    try {
      const command = new GetParametersCommand({ Names: group, WithDecryption: true });
      const response = await ssm.send(command);
      for (const param of response.Parameters || []) {
        const key = normaliseKeyFromPath(path, param.Name || "");
        if (key) parameters[key] = param.Value;
      }
      for (const invalid of response.InvalidParameters || []) {
        console.warn(`Parameter ${invalid} could not be retrieved`);
      }
    } catch (err) {
      console.warn(`Parameter batch fetch failed: ${err.name || err.code || "Error"} - ${err.message}`);
    }
  }
  return parameters;
}

function keyFromSecretId(secretId) {
  return secretId.split(":").pop().split("/").pop().replace(/[^a-zA-Z0-9_]/g, "_").toUpperCase();
}

async function loadSecretsFromManager(secretIds) {
  if (!secretIds.length) return {};
  const values = {};
  for (const secretId of secretIds) {
    try {
      const command = new GetSecretValueCommand({ SecretId: secretId });
      const response = await secretsManager.send(command);
      const payload = response.SecretString
        || (response.SecretBinary ? Buffer.from(response.SecretBinary, "base64").toString("utf-8") : null);
      if (!payload) continue;

      try {
        const parsed = JSON.parse(payload);
        if (parsed && typeof parsed === "object") {
          Object.assign(values, parsed);
          continue;
        }
      } catch (_) {
        // fall back
      }

      values[keyFromSecretId(secretId)] = payload;
    } catch (err) {
      console.warn(`Secrets Manager load skipped for ${secretId}: ${err.name || err.code || "Error"} - ${err.message}`);
    }
  }
  return values;
}

const parameterKeys = [
  "PGHOST",
  "PGDATABASE",
  "PGPORT",
  "S3_BUCKET",
  "QUEUE_URL",
  "SECRETS_ARN"
];

const parameterValues = await loadParametersFromStore(parameterPath, parameterKeys);
const secretArnSource = (() => {
  const raw = parameterValues.SECRETS_ARN;
  if (typeof raw === "string" && raw.trim()) {
    return raw.trim();
  }
  return getEnvValue("SECRETS_ARN");
})();
const secretIdList = secretArnSource
  .split(",")
  .map(id => id.trim())
  .filter(Boolean);
if (secretIdList.length === 0) {
  console.warn("No Secrets Manager ARN provided; ensure SECRETS_ARN is set in SSM or env.");
}
const secretValues = await loadSecretsFromManager(secretIdList);

const resolvedAwsRegion = "ap-southeast-2";
function getParamValue(key) {
  const param = parameterValues[key];
  if (param !== undefined && param !== null) {
    const trimmed = `${param}`.trim();
    if (trimmed) return trimmed;
  }
  return getEnvValue(key);
}

function getSecretValue(key) {
  const secret = secretValues[key];
  if (secret !== undefined && secret !== null) {
    const trimmed = `${secret}`.trim();
    if (trimmed) return trimmed;
  }
  return getEnvValue(key);
}

const config = {
  AWS_REGION: resolvedAwsRegion,
  S3_BUCKET: getParamValue("S3_BUCKET"),
  QUEUE_URL: getParamValue("QUEUE_URL"),
  PGHOST: getParamValue("PGHOST"),
  PGDATABASE: getParamValue("PGDATABASE"),
  PGPORT: getParamValue("PGPORT"),
  PGUSER: getSecretValue("PGUSER"),
  PGPASSWORD: getSecretValue("PGPASSWORD")
};

if (!config.AWS_REGION || !config.S3_BUCKET || !config.QUEUE_URL) {
  throw new Error("Missing required configuration for worker: AWS_REGION, S3_BUCKET, QUEUE_URL");
}

const s3 = new S3Client({ region: config.AWS_REGION });
const sqs = new SQSClient({ region: config.AWS_REGION });
const bucket = config.S3_BUCKET;

async function processMessage(message) {
  if (!message || !message.Body) return false;
  let payload;
  try {
    payload = JSON.parse(message.Body);
  } catch (err) {
    console.error("Invalid message JSON", err);
    return true; // drop invalid message
  }

  const { userId, videoKey, format = "avi" } = payload || {};
  if (!userId || !videoKey) {
    console.warn("Skipping message, missing userId or videoKey");
    return true;
  }

  try {
    const inputUrl = await getSignedUrl(
      s3,
      new GetObjectCommand({ Bucket: bucket, Key: videoKey }),
      { expiresIn: 3600 }
    );

    const baseName = path.basename(videoKey, path.extname(videoKey));
    const ownerId = (videoKey.split("/")[0] || userId).trim();
    const outputKey = `transcodes/${ownerId}/${baseName}.${format}`;
    const outputContentType = format === "avi" ? "video/x-msvideo" : `video/${format}`;

    return await new Promise((resolve) => {
      const cmd = ffmpeg()
        .input(inputUrl)
        .videoCodec("libxvid")
        .audioCodec("libmp3lame")
        .format(format)
        .on("start", c => console.log("Worker FFmpeg:", c))
        .on("stderr", line => console.log("Worker FFmpeg stderr:", line.toString()))
        .on("error", err => {
          console.error("Worker FFmpeg error:", err);
          resolve(false);
        });

      const stream = cmd.pipe();
      const upload = new Upload({
        client: s3,
        params: { Bucket: bucket, Key: outputKey, Body: stream, ContentType: outputContentType }
      });

      upload.done()
        .then(() => {
          console.log("Transcode complete:", outputKey);
          resolve(true);
        })
        .catch(err => {
          console.error("Upload failed:", err);
          resolve(false);
        });
    });
  } catch (err) {
    console.error("Worker processing error:", err);
    return false;
  }
}

async function pollLoop() {
  console.log("Worker started. Polling queue:", config.QUEUE_URL);
  for (;;) {
    try {
      const resp = await sqs.send(new ReceiveMessageCommand({
        QueueUrl: config.QUEUE_URL,
        MaxNumberOfMessages: 1,
        WaitTimeSeconds: 20,
        VisibilityTimeout: 300
      }));

      const messages = resp.Messages || [];
      if (messages.length === 0) continue;

      for (const m of messages) {
        const ok = await processMessage(m);
        if (ok) {
          try {
            await sqs.send(new DeleteMessageCommand({
              QueueUrl: config.QUEUE_URL,
              ReceiptHandle: m.ReceiptHandle
            }));
          } catch (err) {
            console.error("Failed to delete message:", err);
          }
        } else {
          try {
            await sqs.send(new ChangeMessageVisibilityCommand({
              QueueUrl: config.QUEUE_URL,
              ReceiptHandle: m.ReceiptHandle,
              VisibilityTimeout: 0
            }));
          } catch (err) {
            console.error("Failed to requeue message:", err);
          }
        }
      }
    } catch (err) {
      console.error("Polling error:", err);
      await new Promise(r => setTimeout(r, 2000));
    }
  }
}

pollLoop().catch(err => {
  console.error("Worker fatal error:", err);
  process.exit(1);
});
