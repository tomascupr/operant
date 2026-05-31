import assert from "node:assert/strict";
import test from "node:test";
import {
  cronAddArgs,
  cronControlArgs,
  cronListArgs,
  extractCronJobId,
  extractOpenClawCronObservations,
  extractOpenClawSessionsObservations,
  extractOpenClawStatusObservations,
  extractOpenClawTaskObservations,
  extractOpenClawUsageCostObservations,
  isOpenClawCheckName,
  openClawCheckCommandArgs,
  openClawGatewayCommandArgs,
  openClawCheckNames,
  parseJsonFromOutput,
  scrubOpenClawOutput,
} from "../src/openclaw-ops.js";

test("lists supported OpenClaw checks", () => {
  assert.deepEqual(openClawCheckNames(), [
    "config-validate",
    "security-audit",
    "channels-status",
    "secrets-reload",
    "approvals-get",
    "cron-status",
    "tasks-list",
    "usage-cost",
    "status",
    "doctor",
  ]);
  assert.equal(isOpenClawCheckName("usage-cost"), true);
  assert.equal(isOpenClawCheckName("doctor"), true);
  assert.equal(isOpenClawCheckName("unknown"), false);
});

test("adds explicit gateway credentials only for gateway-scoped checks", () => {
  const params = {
    gatewayToken: "gateway-token-test",
    extraEnv: { OPENCLAW_GATEWAY_URL: "ws://openclaw-gateway:18789" },
  };
  assert.deepEqual(openClawCheckCommandArgs("secrets-reload", params), [
    "secrets",
    "reload",
    "--json",
    "--url",
    "ws://openclaw-gateway:18789",
    "--token",
    "gateway-token-test",
  ]);
  assert.deepEqual(openClawCheckCommandArgs("usage-cost", params), [
    "gateway",
    "usage-cost",
    "--json",
    "--url",
    "ws://openclaw-gateway:18789",
    "--token",
    "gateway-token-test",
  ]);
  assert.deepEqual(openClawGatewayCommandArgs(["gateway", "usage-cost", "--json"], params), [
    "gateway",
    "usage-cost",
    "--json",
    "--url",
    "ws://openclaw-gateway:18789",
    "--token",
    "gateway-token-test",
  ]);
  assert.deepEqual(openClawCheckCommandArgs("status", params), ["status", "--all", "--json"]);
  assert.deepEqual(openClawCheckCommandArgs("doctor", params), ["doctor", "--deep", "--non-interactive"]);
});

test("parses JSON even when command emits leading text", () => {
  assert.deepEqual(parseJsonFromOutput("gateway warning\n{\"valid\":true}"), { valid: true });
});

test("returns null for non-JSON output", () => {
  assert.equal(parseJsonFromOutput("doctor output only"), null);
});

test("extracts sessions and usage from OpenClaw status output", () => {
  const observed = extractOpenClawStatusObservations({
    sessions: {
      count: 2,
      recent: [{
        agentId: "main",
        key: "agent:main:slack:channel:C1",
        kind: "channel",
        sessionId: "s1",
        updatedAt: 1778748300164,
        inputTokens: 12,
        outputTokens: 34,
        cacheRead: 56,
        cacheWrite: 78,
        totalTokens: 180,
        model: "gpt-5",
        runtime: "OpenClaw",
        flags: ["id:s1"],
      }],
    },
    tasks: { total: 3, active: 1 },
  });

  assert.equal(observed.rawSessionCount, 2);
  assert.equal(observed.sessions.length, 1);
  assert.equal(observed.sessions[0].key, "agent:main:slack:channel:C1");
  assert.equal(observed.sessions[0].usage?.inputTokens, 12);
  assert.equal(observed.sessions[0].usage?.metadata.totalTokens, 180);
  assert.deepEqual(observed.taskSummary, { total: 3, active: 1 });
});

test("extracts sessions and usage from OpenClaw sessions output", () => {
  const observed = extractOpenClawSessionsObservations({
    count: 1,
    sessions: [{
      key: "agent:main:slack:channel:C1:thread:123.456",
      updatedAt: 1778748300164,
      sessionId: "s1",
      inputTokens: 12,
      outputTokens: 34,
      totalTokens: 46,
      totalTokensFresh: true,
      model: "gpt-5",
      modelProvider: "openai",
      agentId: "main",
      agentRuntime: { id: "pi", source: "provider" },
      kind: "group",
      contextTokens: 400000,
    }],
  });

  assert.equal(observed.length, 1);
  assert.equal(observed[0].key, "agent:main:slack:channel:C1:thread:123.456");
  assert.equal(observed[0].runId, "openclaw-session:s1");
  assert.equal(observed[0].usage?.provider, "openai");
  assert.equal(observed[0].usage?.model, "gpt-5");
  assert.equal(observed[0].usage?.metadata.totalTokens, 46);
});

test("extracts jobs from OpenClaw task output", () => {
  const observed = extractOpenClawTaskObservations({
    tasks: [{
      taskId: "task-1",
      runId: "run-1",
      childSessionKey: "agent:main:slack:channel:C1",
      status: "succeeded",
      runtime: "cron",
      startedAt: 1778748300013,
      endedAt: 1778748315891,
      terminalSummary: "done",
    }],
  });

  assert.equal(observed.length, 1);
  assert.equal(observed[0].runId, "run-1");
  assert.equal(observed[0].sessionKey, "agent:main:slack:channel:C1");
  assert.equal(observed[0].status, "succeeded");
  assert.equal(observed[0].metadata.terminalSummary, "done");
});

test("extracts daily usage-cost snapshots from OpenClaw gateway output", () => {
  const observed = extractOpenClawUsageCostObservations({
    updatedAt: 1778791973964,
    days: 31,
    daily: [{
      date: "2026-05-14",
      input: 12,
      output: 34,
      cacheRead: 56,
      cacheWrite: 78,
      totalTokens: 180,
      totalCost: 0.123456,
      inputCost: 0.001,
      outputCost: 0.002,
      cacheReadCost: 0.003,
      cacheWriteCost: 0.004,
      missingCostEntries: 0,
    }],
    totals: { totalTokens: 180, totalCost: 0.123456 },
    cacheStatus: { status: "fresh" },
  });

  assert.equal(observed.snapshots.length, 1);
  assert.equal(observed.snapshots[0].day, "2026-05-14");
  assert.equal(observed.snapshots[0].estimatedCostUsd, 0.123456);
  assert.equal(observed.snapshots[0].metadata.source, "openclaw.usage-cost");
  assert.equal(observed.snapshots[0].metadata.totalTokens, 180);
  assert.deepEqual(observed.totals, { totalTokens: 180, totalCost: 0.123456 });
  assert.deepEqual(observed.cacheStatus, { status: "fresh" });
});

test("cron-status check now requests JSON and is gateway-scoped", () => {
  const params = {
    gatewayToken: "gateway-token-test",
    extraEnv: { OPENCLAW_GATEWAY_URL: "ws://openclaw-gateway:18789" },
  };
  assert.deepEqual(openClawCheckCommandArgs("cron-status", params), [
    "cron",
    "status",
    "--json",
    "--url",
    "ws://openclaw-gateway:18789",
    "--token",
    "gateway-token-test",
  ]);
});

test("builds cron add args for a cron-expression workflow", () => {
  assert.deepEqual(
    cronAddArgs({
      name: "daily-standup",
      scheduleKind: "cron",
      scheduleExpression: "0 9 * * 1-5",
      timezone: "Europe/Prague",
      channel: "C123",
      message: "Post the standup",
      tools: ["read", "exec"],
    }),
    [
      "cron", "add", "--json",
      "--name", "daily-standup",
      "--cron", "0 9 * * 1-5",
      "--tz", "Europe/Prague",
      "--message", "Post the standup",
      "--channel", "C123",
      "--announce",
      "--tools", "read,exec",
    ],
  );
});

test("builds cron add args for an interval workflow, disabled, no tools", () => {
  assert.deepEqual(
    cronAddArgs({
      name: "hourly-scan",
      scheduleKind: "every",
      scheduleExpression: "1h",
      channel: "last",
      message: "Run the scan",
      disabled: true,
    }),
    [
      "cron", "add", "--json",
      "--name", "hourly-scan",
      "--every", "1h",
      "--message", "Run the scan",
      "--channel", "last",
      "--announce",
      "--disabled",
    ],
  );
});

test("scrubOpenClawOutput strips the live gateway token and token-shaped secrets", () => {
  const prev = process.env.OPENCLAW_GATEWAY_TOKEN;
  process.env.OPENCLAW_GATEWAY_TOKEN = "super-secret-gateway-token-value";
  try {
    const out = scrubOpenClawOutput("connect failed using --token super-secret-gateway-token-value and bot xoxb-9-abc");
    assert.ok(!out.includes("super-secret-gateway-token-value"), "live gateway token must be scrubbed");
    assert.ok(!out.includes("xoxb-9-abc"), "token-shaped secrets must be scrubbed");
    assert.match(out, /\[REDACTED\]/);
  } finally {
    if (prev === undefined) delete process.env.OPENCLAW_GATEWAY_TOKEN;
    else process.env.OPENCLAW_GATEWAY_TOKEN = prev;
  }
});

test("builds cron control args (enable/disable/rm address by id)", () => {
  assert.deepEqual(cronControlArgs("enable", "job-1"), ["cron", "enable", "job-1"]);
  assert.deepEqual(cronControlArgs("disable", "job-1"), ["cron", "disable", "job-1"]);
  assert.deepEqual(cronControlArgs("rm", "job-1"), ["cron", "rm", "--json", "job-1"]);
  assert.deepEqual(cronListArgs(), ["cron", "list", "--all", "--json"]);
});

test("extracts cron job observations and the created job id", () => {
  const observed = extractOpenClawCronObservations({
    jobs: [
      { id: "job-1", name: "daily-standup", enabled: true, cron: "0 9 * * 1-5" },
      { id: "job-2", name: "hourly-scan", disabled: true },
      { name: "name-only" }, // no id -> falls back to name so reconciliation stays consistent
      { description: "no id, no name -> skipped" },
    ],
    total: 4,
  });
  assert.equal(observed.length, 3);
  assert.equal(observed[0].id, "job-1");
  assert.equal(observed[0].enabled, true);
  assert.equal(observed[0].metadata.source, "openclaw.cron");
  assert.equal(observed[1].id, "job-2");
  assert.equal(observed[1].enabled, false);
  assert.equal(observed[2].id, "name-only");
  assert.equal(observed[2].enabled, null);

  assert.equal(extractCronJobId({ id: "job-9" }), "job-9");
  assert.equal(extractCronJobId({ job: { id: "job-10" } }), "job-10");
  assert.equal(extractCronJobId({ nothing: true }), null);
});
