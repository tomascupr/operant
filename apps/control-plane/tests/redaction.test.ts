import assert from "node:assert/strict";
import test from "node:test";
import { redactRecordForPersistence } from "../src/redaction.js";

test("redacts token-shaped strings and sensitive metadata keys", () => {
  const redacted = redactRecordForPersistence({
    message: "called Slack with xoxb-secret-token and OpenAI sk-secret-key and Pipedream ctok_secret-token",
    connect: "https://pipedream.com/_static/connect.html?token=ctok_secret-token&app=gmail",
    apiKey: "plain-api-key",
    nested: {
      authorization: "Bearer xapp-secret-app-token",
      keepSecretRefId: "workspaces/1/slack/botToken",
    },
    array: ["github_pat_secret", { password: "plain-password" }],
  });

  const serialized = JSON.stringify(redacted);
  assert.equal(serialized.includes("xoxb-secret-token"), false);
  assert.equal(serialized.includes("sk-secret-key"), false);
  assert.equal(serialized.includes("xapp-secret-app-token"), false);
  assert.equal(serialized.includes("github_pat_secret"), false);
  assert.equal(serialized.includes("ctok_secret-token"), false);
  assert.equal(serialized.includes("connect.html?token="), false);
  assert.equal(serialized.includes("plain-api-key"), false);
  assert.equal(serialized.includes("plain-password"), false);
  assert.equal((redacted.nested as Record<string, unknown>).keepSecretRefId, "workspaces/1/slack/botToken");
});
