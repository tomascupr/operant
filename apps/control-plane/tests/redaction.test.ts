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

test("redacts AWS access keys even when glued to trailing word characters", () => {
  const redacted = redactRecordForPersistence({
    standalone: "AKIAIOSFODNN7EXAMPLE",
    glued: "AKIAIOSFODNN7EXAMPLE12345",
  });
  const serialized = JSON.stringify(redacted);
  assert.equal(serialized.includes("AKIAIOSFODNN7EXAMPLE"), false);
});

test("redacts set-cookie and plural credentials keys, not just exact matches", () => {
  const redacted = redactRecordForPersistence({
    "set-cookie": "session=plain-cookie-value",
    cookies: "another=plain-cookie",
    credentials: "plain-credentials-value",
  }) as Record<string, unknown>;
  assert.equal(redacted["set-cookie"], "[REDACTED]");
  assert.equal(redacted.cookies, "[REDACTED]");
  assert.equal(redacted.credentials, "[REDACTED]");
});
