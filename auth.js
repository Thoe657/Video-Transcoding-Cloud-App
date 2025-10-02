import crypto from "crypto";
import { 
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
  AssociateSoftwareTokenCommand,
  VerifySoftwareTokenCommand,
  RespondToAuthChallengeCommand,
  SetUserMFAPreferenceCommand,
  AdminAddUserToGroupCommand,
  AdminGetUserCommand
} from "@aws-sdk/client-cognito-identity-provider";

const DEFAULT_USER_GROUP = "User";
let cognitoClient;
let clientId;
let clientSecret;
let userPoolId;
let jwtSecret;

// Optional init for backward compatibility
export function initCognito({
  clientId: cId,
  clientSecret: cSecret,
  jwtSecret: secret,
  region,
  userPoolId: poolId
}) {
  cognitoClient = new CognitoIdentityProviderClient({
    region: region || "ap-southeast-2"
  });
  clientId = cId || process.env.COGNITO_CLIENT_ID;
  clientSecret = cSecret || process.env.COGNITO_CLIENT_SECRET;
  jwtSecret = secret || process.env.JWT_SECRET;
  userPoolId = poolId || process.env.COGNITO_USER_POOL_ID;
}

// Helper to calculate SECRET_HASH
function calculateSecretHash(username) {
  return crypto.createHmac("SHA256", clientSecret)
    .update(username + clientId)
    .digest("base64");
}

// Register a new user
export async function registerUser(username, password, email) {
  const secretHash = calculateSecretHash(username);

  const command = new SignUpCommand({
    ClientId: clientId,
    Username: username,
    Password: password,
    SecretHash: secretHash,
    UserAttributes: [{ Name: "email", Value: email }]
  });

  const response = await cognitoClient.send(command);
  await addUserToDefaultGroup(username);

  return response;
}

async function addUserToDefaultGroup(username) {
  if (!cognitoClient || !userPoolId || !DEFAULT_USER_GROUP) return;

  const command = new AdminAddUserToGroupCommand({
    UserPoolId: userPoolId,
    Username: username,
    GroupName: DEFAULT_USER_GROUP
  });

  try {
    await cognitoClient.send(command);
  } catch (err) {
    console.warn("Failed to add user " + username + " to default group " + DEFAULT_USER_GROUP, err);
  }
}
// Confirm user registration
export async function confirmUser(username, code) {
  const secretHash = calculateSecretHash(username);

  const command = new ConfirmSignUpCommand({
    ClientId: clientId,
    Username: username,
    ConfirmationCode: code,
    SecretHash: secretHash
  });

  return cognitoClient.send(command);
}

// Login a user
export async function loginUser(username, password) {
  const secretHash = calculateSecretHash(username);

  const command = new InitiateAuthCommand({
    AuthFlow: "USER_PASSWORD_AUTH",
    ClientId: clientId,
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password,
      SECRET_HASH: secretHash
    }
  });

  const response = await cognitoClient.send(command);
  if (response.ChallengeName) {
    return {
      challengeName: response.ChallengeName,
      session: response.Session,
      challengeParameters: response.ChallengeParameters || {}
    };
  }

  return { authenticationResult: response.AuthenticationResult };
}

export async function associateSoftwareToken({ accessToken, session }) {
  const input = {};
  if (accessToken) input.AccessToken = accessToken;
  if (session) input.Session = session;
  const command = new AssociateSoftwareTokenCommand(input);
  return cognitoClient.send(command);
}

export async function verifySoftwareToken({ accessToken, session, code, friendlyDeviceName }) {
  const input = { UserCode: code };
  if (accessToken) input.AccessToken = accessToken;
  if (session) input.Session = session;
  if (friendlyDeviceName) input.FriendlyDeviceName = friendlyDeviceName;
  const command = new VerifySoftwareTokenCommand(input);
  return cognitoClient.send(command);
}

export async function setSoftwareTokenMfaPreference(accessToken, enabled = true) {
  const command = new SetUserMFAPreferenceCommand({
    AccessToken: accessToken,
    SoftwareTokenMfaSettings: {
      Enabled: enabled,
      PreferredMfa: enabled
    }
  });
  return cognitoClient.send(command);
}

export async function respondToSoftwareTokenChallenge({ username, session, code, challengeName }) {
  const secretHash = calculateSecretHash(username);
  const command = new RespondToAuthChallengeCommand({
    ClientId: clientId,
    ChallengeName: challengeName,
    Session: session,
    ChallengeResponses: {
      USERNAME: username,
      SECRET_HASH: secretHash,
      SOFTWARE_TOKEN_MFA_CODE: code
    }
  });
  return cognitoClient.send(command);
}

export async function isUserMfaEnabled(username) {
  if (!cognitoClient || !userPoolId || !username) return false;

  try {
    const command = new AdminGetUserCommand({
      UserPoolId: userPoolId,
      Username: username
    });
    const response = await cognitoClient.send(command);
    const preferred = (response.PreferredMfaSetting || "").toUpperCase();
    const settings = Array.isArray(response.UserMFASettingList) ? response.UserMFASettingList : [];
    if (preferred === "SOFTWARE_TOKEN_MFA") return true;
    return settings.includes("SOFTWARE_TOKEN_MFA");
  } catch (err) {
    console.warn("Failed to fetch MFA status for " + username, err);
    return false;
  }
}

// Export jwtSecret for middleware usage
export { jwtSecret };



