import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

let secretsCache = null;

export async function getSecrets(secretName = "n11977132-videoapp-secrets") {
  if (secretsCache) return secretsCache;

  const client = new SecretsManagerClient({
    region: "ap-southeast-2"
  });
    const command = new GetSecretValueCommand({ SecretId: secretName });
    const data = await client.send(command);

    if (data && data.SecretString) {
      secretsCache = JSON.parse(data.SecretString);
    } else {
      throw new Error("No SecretString found");
    }

  return secretsCache;
}
