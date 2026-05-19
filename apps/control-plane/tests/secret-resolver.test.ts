import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { spawn } from "node:child_process";
import path from "node:path";
import test from "node:test";

function runResolver(input: unknown, url: string, token: string): Promise<any> {
  const script = path.resolve(process.cwd(), "../../deploy/openclaw/operant-secret-resolver.mjs");
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script], {
      env: {
        ...process.env,
        OPERANT_CONTROL_PLANE_URL: url,
        OPERANT_INTERNAL_TOKEN: token,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`resolver exited ${code}: ${stderr}`));
        return;
      }
      resolve(JSON.parse(stdout));
    });
    child.stdin.end(JSON.stringify(input));
  });
}

test("OpenClaw exec SecretRef resolver returns batch values", async () => {
  const token = "test-token";
  const server = createServer((req, res) => {
    assert.equal(req.headers.authorization, `Bearer ${token}`);
    assert.equal(req.url, "/internal/openclaw/secrets/workspaces%2Fw1%2Fslack%2FbotToken");
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ value: "xoxb-secret" }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  try {
    const output = await runResolver(
      { protocolVersion: 1, provider: "operant", ids: ["workspaces/w1/slack/botToken"] },
      `http://127.0.0.1:${address.port}`,
      token,
    );
    assert.deepEqual(output, {
      protocolVersion: 1,
      values: { "workspaces/w1/slack/botToken": "xoxb-secret" },
    });
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
