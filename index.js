import express from "express";
import { fileURLToPath } from "url";
import path from "path";
import { S3Client, GetObjectCommand, ListObjectsV2Command } from "@aws-sdk/client-s3";
import { Upload } from "@aws-sdk/lib-storage";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import ffmpeg from "fluent-ffmpeg";
import ffmpegInstaller from "@ffmpeg-installer/ffmpeg";
ffmpeg.setFfmpegPath(ffmpegInstaller.path);
import pLimit from "p-limit";
import { initDb as connectDb, query } from "./db.js";
import { initS3, generatePresignedUploadKey, generatePresignedDownloadKey } from "./s3.js";
import {
  registerUser,
  confirmUser,
  loginUser,
  initCognito,
  associateSoftwareToken,
  verifySoftwareToken,
  setSoftwareTokenMfaPreference,
  respondToSoftwareTokenChallenge,
  isUserMfaEnabled
} from "./auth.js";
import { createRemoteJWKSet, jwtVerify, decodeJwt } from "jose";
import QRCode from "qrcode";
import { SSMClient, GetParametersCommand, DescribeParametersCommand } from "@aws-sdk/client-ssm";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
//non-sensitive required env variables
const defaultAwsRegion = "ap-southeast-2";
const parameterPath =  "/11977132/videoapp/param/";
const secretIdList = ("arn:aws:secretsmanager:ap-southeast-2:901444280953:secret:n11977132-videoapp-secrets-gD6xGE")
  .split(",")
  .map(id => id.trim())
  .filter(Boolean);
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

async function listParameterNames(path) {
  const names = new Set();
  if (!path) return names;
  try {
    let nextToken;
    do {
      const command = new DescribeParametersCommand({
        ParameterFilters: [{
          Key: "Path",
          Values: [path],
          Option: "Recursive"
        }],
        NextToken: nextToken
      });
      const response = await ssm.send(command);
      for (const param of response.Parameters || []) {
        if (param?.Name) names.add(param.Name);
      }
      nextToken = response.NextToken;
    } while (nextToken);
  } catch (err) {
    console.warn(`Parameter Store describe skipped: ${err.name || err.code || "Error"} - ${err.message}`);
  }
  return names;
}

async function loadParametersFromStore(path) {
  if (!path) return {};
  const parameters = {};
  const names = Array.from(await listParameterNames(path));
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
        // payload was not JSON, fall back to treating as a plain string
      }

      values[keyFromSecretId(secretId)] = payload;
    } catch (err) {
      console.warn(`Secrets Manager load skipped for ${secretId}: ${err.name || err.code || "Error"} - ${err.message}`);
    }
  }
  return values;
}

const parameterValues = await loadParametersFromStore(parameterPath);
const secretValues = await loadSecretsFromManager(secretIdList);
const resolvedAwsRegion = "ap-southeast-2";
const secrets = {
  PGHOST: (parameterValues.PGHOST).trim(),
  PGUSER: secretValues.PGUSER,
  PGPASSWORD: secretValues.PGPASSWORD,
  PGDATABASE: parameterValues.PGDATABASE,
  PGPORT: parameterValues.PGPORT,
  S3_BUCKET: (parameterValues.S3_BUCKET).trim(),
  AWS_REGION: resolvedAwsRegion,
  COGNITO_USER_POOL_ID: parameterValues.COGNITO_USER_POOL_ID,
  COGNITO_CLIENT_ID: parameterValues.COGNITO_CLIENT_ID,
  COGNITO_CLIENT_SECRET: secretValues.COGNITO_CLIENT_SECRET,
  JWT_SECRET: secretValues.JWT_SECRET,
  PORT: Number(parameterValues.PORT) || 3000
};

const dbConfig = {
  host: secrets.PGHOST,
  user: secrets.PGUSER,
  password: secrets.PGPASSWORD,
  database: secrets.PGDATABASE,
  port: Number(secrets.PGPORT) || undefined
};



await connectDb(dbConfig);
initS3({ Bucket: secrets.S3_BUCKET, Region: secrets.AWS_REGION });
initCognito({
  clientId: secrets.COGNITO_CLIENT_ID,
  clientSecret: secrets.COGNITO_CLIENT_SECRET,
  region: secrets.AWS_REGION,
  userPoolId: secrets.COGNITO_USER_POOL_ID
});

const CONCURRENT_TRANSCODES = 2;
const transcodeLimit = pLimit(CONCURRENT_TRANSCODES);
const s3 = new S3Client({ region: secrets.AWS_REGION });
const bucket = secrets.S3_BUCKET;
const MFA_ISSUER = parameterValues.MFA_ISSUER || process.env.MFA_ISSUER || "VideoApp";

const app = express();
app.use(express.json());

const JWKS_URL = secrets.COGNITO_USER_POOL_ID && secrets.AWS_REGION
  ? `https://cognito-idp.${secrets.AWS_REGION}.amazonaws.com/${secrets.COGNITO_USER_POOL_ID}/.well-known/jwks.json`
  : null;

if (!JWKS_URL) {
  throw new Error("Missing AWS region or Cognito user pool ID for JWKS lookup");
}

const JWKS = createRemoteJWKSet(new URL(JWKS_URL));

async function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Missing Authorization header" });
  const token = authHeader.replace("Bearer ", "");
  try {
    const { payload } = await jwtVerify(token, JWKS, { audience: secrets.COGNITO_CLIENT_ID });
    const username = payload["cognito:username"];
    const role = getRoleFromGroups(payload["cognito:groups"]);
    req.user = { username, role };
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

function buildOtpauthUrl(secretCode, username) {
  if (!secretCode || !username) return null;
  const issuer = encodeURIComponent(MFA_ISSUER);
  const accountName = encodeURIComponent(username);
  const secret = encodeURIComponent(secretCode);
  return `otpauth://totp/${issuer}:${accountName}?secret=${secret}&issuer=${issuer}`;
}

async function buildMfaSecretArtifacts(secretCode, username) {
  if (!secretCode || !username) return null;

  const otpauthUrl = buildOtpauthUrl(secretCode, username);
  if (!otpauthUrl) {
    return { secretCode, otpauthUrl: "", qrCodeDataUrl: "" };
  }
  let qrCodeDataUrl = "";

  try {
    qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);
  } catch (err) {
    console.error("Failed to generate MFA QR code", err);
  }

  return { secretCode, otpauthUrl, qrCodeDataUrl };
}

function normalizeGroups(groups) {
  if (!groups) return [];
  if (Array.isArray(groups)) return groups;
  if (typeof groups === "string") {
    try {
      const parsed = JSON.parse(groups);
      if (Array.isArray(parsed)) return parsed;
    } catch (_) {
      return groups.split(",").map(g => g.trim()).filter(Boolean);
    }
    return [groups];
  }
  return [];
}

function getRoleFromGroups(groups) {
  const normalized = normalizeGroups(groups).map(g => g.toLowerCase());
  return normalized.includes("administrator") ? "admin" : "user";
}

function extractRoleFromToken(idToken) {
  try {
    const payload = decodeJwt(idToken);
    return getRoleFromGroups(payload["cognito:groups"]);
  } catch (err) {
    console.warn("Could not decode role from token", err);
    return "user";
  }
}

app.post("/register", async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email) {
    return res.status(400).json({ error: "username, password, email required" });
  }
  try {
    const result = await registerUser(username, password, email);
    res.json({ message: "Registration successful. Check email to confirm.", userSub: result.UserSub });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/verify", async (req, res) => {
  const { username, code } = req.body;
  if (!username || !code) {
    return res.status(400).json({ error: "username & code required" });
  }
  try {
    await confirmUser(username, code);
    res.json({ message: "User confirmed!" });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await loginUser(username, password);

    if (result.authenticationResult) {
      const { IdToken, AccessToken, RefreshToken } = result.authenticationResult;
      const role = extractRoleFromToken(IdToken);
      const mfaEnabled = await isUserMfaEnabled(username);
      return res.json({
        idToken: IdToken,
        accessToken: AccessToken,
        refreshToken: RefreshToken,
        role,
        mfaEnabled
      });
    }

    if (result.challengeName) {
      const challengeRole = getRoleFromGroups(result.challengeParameters?.groups || result.challengeParameters?.["cognito:groups"]);
      return res.json({
        challenge: result.challengeName,
        session: result.session,
        challengeParameters: result.challengeParameters || {},
        role: challengeRole,
        mfaEnabled: false
      });
    }

    res.status(401).json({ error: "Authentication failed" });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

app.post("/mfa/associate", auth, async (req, res) => {
  const { accessToken: accessTokenFromBody } = req.body || {};
  if (!accessTokenFromBody) {
    return res.status(400).json({ error: "accessToken required" });
  }

  try {
    const response = await associateSoftwareToken({ accessToken: accessTokenFromBody });
    const secretArtifacts = await buildMfaSecretArtifacts(response.SecretCode, req.user.username);
    if (!secretArtifacts) {
      return res.status(400).json({ error: "Failed to generate MFA secret" });
    }

    res.json(secretArtifacts);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/mfa/verify", auth, async (req, res) => {
  const { accessToken: accessTokenFromBody, code } = req.body || {};
  if (!accessTokenFromBody || !code) {
    return res.status(400).json({ error: "accessToken and code required" });
  }

  try {
    const verification = await verifySoftwareToken({ accessToken: accessTokenFromBody, code });
    if (!verification || verification.Status !== "SUCCESS") {
      return res.status(400).json({ error: "Invalid verification code" });
    }

    await setSoftwareTokenMfaPreference(accessTokenFromBody, true);
    res.json({ message: "MFA enabled. Use your authenticator code on next login." });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/mfa/associate-session", async (req, res) => {
  const { session, username } = req.body || {};
  if (!session || !username) {
    return res.status(400).json({ error: "session and username required" });
  }

  try {
    const response = await associateSoftwareToken({ session });
    const secretArtifacts = await buildMfaSecretArtifacts(response.SecretCode, username);
    if (!secretArtifacts) {
      return res.status(400).json({ error: "Failed to generate MFA secret" });
    }

    res.json({ ...secretArtifacts, session: response.Session || session });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/mfa/verify-session", async (req, res) => {
  const { session, code, username } = req.body || {};
  if (!session || !code || !username) {
    return res.status(400).json({ error: "session, code, and username required" });
  }

  try {
    const verification = await verifySoftwareToken({ session, code });
    if (!verification || verification.Status !== "SUCCESS") {
      return res.status(400).json({ error: "Invalid verification code" });
    }

    const nextSession = verification.Session || session;
    const challengeResponse = await respondToSoftwareTokenChallenge({
      username,
      session: nextSession,
      code,
      challengeName: "MFA_SETUP"
    });

    if (challengeResponse?.AuthenticationResult) {
      const { IdToken, AccessToken, RefreshToken } = challengeResponse.AuthenticationResult;
      const role = extractRoleFromToken(IdToken);
      const mfaEnabled = await isUserMfaEnabled(username);
      return res.json({
        idToken: IdToken,
        accessToken: AccessToken,
        refreshToken: RefreshToken,
        role,
        mfaEnabled
      });
    }

    if (challengeResponse?.ChallengeName) {
      const challengeRole = getRoleFromGroups(challengeResponse.ChallengeParameters?.["cognito:groups"]);
      return res.json({
        challenge: challengeResponse.ChallengeName,
        session: challengeResponse.Session || nextSession,
        challengeParameters: challengeResponse.ChallengeParameters || {},
        role: challengeRole,
        mfaEnabled: false
      });
    }

    res.status(400).json({ error: "Unexpected response from Cognito" });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/mfa/challenge", async (req, res) => {
  const { username, session, code, challengeName } = req.body;
  if (!username || !session || !code) {
    return res.status(400).json({ error: "username, session, code required" });
  }

  try {
    const response = await respondToSoftwareTokenChallenge({
      username,
      session,
      code,
      challengeName: challengeName || "SOFTWARE_TOKEN_MFA"
    });

    if (response.AuthenticationResult) {
      const { IdToken, AccessToken, RefreshToken } = response.AuthenticationResult;
      const role = extractRoleFromToken(IdToken);
      const mfaEnabled = await isUserMfaEnabled(username);
      return res.json({
        idToken: IdToken,
        accessToken: AccessToken,
        refreshToken: RefreshToken,
        role,
        mfaEnabled
      });
    }

    if (response.ChallengeName) {
      const challengeRole = getRoleFromGroups(response.ChallengeParameters?.["cognito:groups"]);
      return res.json({
        challenge: response.ChallengeName,
        session: response.Session,
        challengeParameters: response.ChallengeParameters || {},
        role: challengeRole,
        mfaEnabled: false
      });
    }

    res.status(401).json({ error: "MFA challenge failed" });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

app.post("/upload", auth, async (req, res) => {
  const { filename, contentType } = req.body;
  if (!filename || !contentType) {
    return res.status(400).json({ error: "filename and contentType required" });
  }

  try {
    const { url, key } = await generatePresignedUploadKey({
      userId: req.user.username,
      filename,
      contentType
    });

    await query(
      "INSERT INTO videos (user_id, filename, s3_key) VALUES ($1, $2, $3)",
      [req.user.username, filename, key]
    );

    res.json({ uploadUrl: url, key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/uploads", auth, async (req, res) => {
  try {
    let videos;
    if (req.user.role === "admin") {
      videos = await query("SELECT id, filename, user_id FROM videos ORDER BY id DESC");
    } else {
      videos = await query(
        "SELECT id, filename, user_id FROM videos WHERE user_id = $1 ORDER BY id DESC",
        [req.user.username]
      );
    }

    res.json({ uploads: videos.rows, role: req.user.role });
    return;
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/transcode", auth, async (req, res) => {
  try {
    const { videoId, videoKey: directVideoKey, format = "avi" } = req.body;

    let videoKey = directVideoKey;
    if (!videoKey && videoId) {
      const result = await query(
        "SELECT s3_key FROM videos WHERE id = $1 AND user_id = $2",
        [videoId, req.user.username]
      );
      if (result.rowCount === 0) {
        return res.status(404).json({ error: "Video not found" });
      }
      videoKey = result.rows[0].s3_key;
    }

    if (!videoKey) {
      return res.status(400).json({ error: "videoId or videoKey required" });
    }

    if (format !== "avi") {
      return res.status(400).json({ error: "Only avi output is supported at this time" });
    }

    const inputUrl = await getSignedUrl(
      s3,
      new GetObjectCommand({ Bucket: bucket, Key: videoKey }),
      { expiresIn: 3600 }
    );

    const ffmpegCommand = ffmpeg()
      .input(inputUrl)
      .videoCodec("libxvid")
      .audioCodec("libmp3lame")
      .format(format)
      .on("start", commandLine => console.log("FFmpeg command:", commandLine))
      .on("stderr", line => console.log("FFmpeg stderr:", line.toString()))
      .on("error", err => console.error("FFmpeg error:", err));

    const ffmpegStream = ffmpegCommand.pipe();

    const baseName = path.basename(videoKey, path.extname(videoKey));
    const ownerId = (videoKey.split("/")[0] || req.user.username).trim();
    const outputKey = `transcodes/${ownerId}/${baseName}.${format}`;
    const outputContentType = format === "avi" ? "video/x-msvideo" : `video/${format}`;

    const upload = new Upload({
      client: s3,
      params: {
        Bucket: bucket,
        Key: outputKey,
        Body: ffmpegStream,
        ContentType: outputContentType
      }
    });

    await transcodeLimit(() => upload.done());

    res.json({ message: "Transcode complete", key: outputKey });
  } catch (err) {
    console.error("Transcode failed:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/files", auth, async (req, res) => {
  try {
    const prefix = req.user.role === "admin" ? "transcodes/" : `transcodes/${req.user.username}/`;
    const result = await s3.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: prefix }));
    const files = await Promise.all((result.Contents || []).map(async obj => {
      if (!obj.Key) return null;
      const parts = obj.Key.split("/");
      if (parts.length < 3) return null;
      const ownerIdFromKey = parts[1] || req.user.username;
      const owner = req.user.role === "admin" ? ownerIdFromKey : req.user.username;
      const url = await generatePresignedDownloadKey({ userId: owner, filename: obj.Key });
      return {
        filename: parts[parts.length - 1],
        owner,
        key: obj.Key,
        downloadUrl: url,
        completedAt: obj.LastModified ? obj.LastModified.toISOString() : null
      };
    }));
    res.json({ files: files.filter(Boolean), role: req.user.role });
  } catch (err) {
    console.error("Error listing files:", err);
    res.status(500).json({ error: "Could not list files" });
  }
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(secrets.PORT, () => {
  console.log(`API listening on PORT:${secrets.PORT}`);
});
