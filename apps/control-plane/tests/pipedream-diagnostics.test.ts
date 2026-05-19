import assert from "node:assert/strict";
import test from "node:test";
import {
  buildPipedreamEnvDiagnostics,
  checkPipedreamOAuthHandshake,
  summarizeOperantPluginDiagnostic,
} from "../src/server.js";

const completeEnv = {
  OPERANT_MCP_SOURCE_PIPEDREAM_URL: "https://remote.mcp.pipedream.net/v3",
  PIPEDREAM_PROJECT_CLIENT_ID: "client-id",
  PIPEDREAM_PROJECT_CLIENT_SECRET: "client-secret",
  PIPEDREAM_PROJECT_ID: "proj_123",
  PIPEDREAM_ENVIRONMENT: "development",
};

test("pipedream env diagnostics expose presence booleans only", () => {
  const diagnostics = buildPipedreamEnvDiagnostics({
    ...completeEnv,
    PIPEDREAM_PROJECT_CLIENT_SECRET: "super-secret-value",
  });

  assert.deepEqual(diagnostics, [
    { name: "OPERANT_MCP_SOURCE_PIPEDREAM_URL", present: true },
    { name: "PIPEDREAM_PROJECT_CLIENT_ID", present: true },
    { name: "PIPEDREAM_PROJECT_CLIENT_SECRET", present: true },
    { name: "PIPEDREAM_PROJECT_ID", present: true },
    { name: "PIPEDREAM_ENVIRONMENT", present: true },
  ]);
  assert.equal(JSON.stringify(diagnostics).includes("super-secret-value"), false);
});

test("summarizes the Operant plugin from OpenClaw plugin list output", () => {
  assert.deepEqual(
    summarizeOperantPluginDiagnostic({ plugins: [{ id: "operant", status: "enabled" }] }),
    { ok: true, status: "enabled", id: "operant" },
  );
  assert.deepEqual(
    summarizeOperantPluginDiagnostic({ plugins: [{ id: "operant", status: "disabled" }] }),
    { ok: false, status: "disabled", id: "operant" },
  );
  assert.deepEqual(
    summarizeOperantPluginDiagnostic({ plugins: [{ id: "slack", status: "enabled" }] }),
    { ok: false, status: "missing", id: "operant" },
  );
});

test("pipedream oauth diagnostic classifies token mint results without exposing tokens", async () => {
  const ok = await checkPipedreamOAuthHandshake(completeEnv, async () =>
    new Response(JSON.stringify({ access_token: "pd-token" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }));
  assert.deepEqual(ok, { ok: true, status: "ok", httpStatus: 200 });

  const unauthorized = await checkPipedreamOAuthHandshake(completeEnv, async () =>
    new Response(JSON.stringify({ access_token: "should-not-leak" }), { status: 401 }));
  assert.deepEqual(unauthorized, { ok: false, status: "unauthorized", httpStatus: 401 });
  assert.equal(JSON.stringify(unauthorized).includes("should-not-leak"), false);
});

test("pipedream oauth diagnostic skips the network when wiring env is incomplete", async () => {
  let called = false;
  const result = await checkPipedreamOAuthHandshake({}, async () => {
    called = true;
    return new Response("{}");
  });

  assert.deepEqual(result, { ok: false, status: "not_configured" });
  assert.equal(called, false);
});
