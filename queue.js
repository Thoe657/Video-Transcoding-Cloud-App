import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";

let sqs;
let queueUrl;

export function initQueue({ region, queueUrl: url }) {
  if (!region || !url) throw new Error("initQueue requires region and queueUrl");
  sqs = new SQSClient({ region });
  queueUrl = url;
}

export async function enqueueTranscode({ userId, videoKey, format = "avi" }) {
  if (!sqs || !queueUrl) throw new Error("Queue not initialized. Call initQueue() first.");
  if (!userId || !videoKey) throw new Error("enqueueTranscode requires userId and videoKey");

  const body = JSON.stringify({ userId, videoKey, format });
  const command = new SendMessageCommand({ QueueUrl: queueUrl, MessageBody: body });
  await sqs.send(command);
  return { status: "queued" };
}

