import { spawn } from "node:child_process";
import { redactForPersistence } from "./redaction.js";

export type OpenClawCheckName =
  | "config-validate"
  | "security-audit"
  | "channels-status"
  | "secrets-reload"
  | "approvals-get"
  | "cron-status"
  | "tasks-list"
  | "usage-cost"
  | "status"
  | "doctor";

export type OpenClawCheckResult = {
  check: OpenClawCheckName;
  command: string[];
  exitCode: number | null;
  timedOut: boolean;
  stdout: string;
  stderr: string;
  json: unknown | null;
};

export type OpenClawCommandResult = Omit<OpenClawCheckResult, "check">;

export type OpenClawObservedSession = {
  key: string;
  lastEventAt: Date | null;
  metadata: Record<string, unknown>;
  runId: string | null;
  usage: {
    provider: string | null;
    model: string | null;
    inputTokens: number;
    outputTokens: number;
    toolName: string | null;
    metadata: Record<string, unknown>;
  } | null;
};

export type OpenClawObservedTask = {
  runId: string;
  sessionKey: string | null;
  status: string;
  startedAt: Date | null;
  finishedAt: Date | null;
  metadata: Record<string, unknown>;
};

export type OpenClawUsageCostSnapshot = {
  day: string;
  estimatedCostUsd: number;
  metadata: Record<string, unknown>;
};

export type OpenClawObservedCron = {
  id: string;
  name: string | null;
  enabled: boolean | null;
  metadata: Record<string, unknown>;
};

// Inputs for materializing a governed scheduled workflow into an OpenClaw cron job.
export type CronJobSpec = {
  name: string;
  scheduleKind: "cron" | "every";
  scheduleExpression: string;
  timezone?: string | null;
  channel: string;
  message: string;
  tools?: string[];
  disabled?: boolean;
};

const COMMANDS: Record<OpenClawCheckName, string[]> = {
  "config-validate": ["config", "validate", "--json"],
  "security-audit": ["security", "audit", "--json"],
  "channels-status": ["channels", "status", "--probe", "--json"],
  "secrets-reload": ["secrets", "reload", "--json"],
  "approvals-get": ["approvals", "get", "--json", "--gateway"],
  "cron-status": ["cron", "status", "--json"],
  "tasks-list": ["tasks", "list", "--json"],
  "usage-cost": ["gateway", "usage-cost", "--json"],
  status: ["status", "--all", "--json"],
  doctor: ["doctor", "--deep", "--non-interactive"],
};

const explicitGatewayArgChecks = new Set<OpenClawCheckName>(["secrets-reload", "approvals-get", "cron-status", "usage-cost"]);

export function openClawCheckNames(): OpenClawCheckName[] {
  return Object.keys(COMMANDS) as OpenClawCheckName[];
}

export function isOpenClawCheckName(value: string): value is OpenClawCheckName {
  return Object.prototype.hasOwnProperty.call(COMMANDS, value);
}

export function openClawGatewayCommandArgs(args: string[], params: {
  gatewayToken?: string;
  extraEnv?: NodeJS.ProcessEnv;
} = {}): string[] {
  const gatewayUrl = params.extraEnv?.OPENCLAW_GATEWAY_URL ?? process.env.OPENCLAW_GATEWAY_URL;
  return [
    ...args,
    ...(gatewayUrl ? ["--url", gatewayUrl] : []),
    ...(params.gatewayToken ? ["--token", params.gatewayToken] : []),
  ];
}

export function openClawCheckCommandArgs(check: OpenClawCheckName, params: {
  gatewayToken?: string;
  extraEnv?: NodeJS.ProcessEnv;
} = {}): string[] {
  const args = [...COMMANDS[check]];
  return explicitGatewayArgChecks.has(check) ? openClawGatewayCommandArgs(args, params) : args;
}

// Build `openclaw cron add` args for a governed workflow. The agent's final text is
// fallback-delivered to the target channel via --announce so a scheduled run actually
// posts. Gateway --url/--token are appended separately by the caller.
export function cronAddArgs(spec: CronJobSpec): string[] {
  const schedule = spec.scheduleKind === "cron" ? ["--cron", spec.scheduleExpression] : ["--every", spec.scheduleExpression];
  return [
    "cron",
    "add",
    "--json",
    "--name",
    spec.name,
    ...schedule,
    ...(spec.scheduleKind === "cron" && spec.timezone ? ["--tz", spec.timezone] : []),
    "--message",
    spec.message,
    "--channel",
    spec.channel,
    "--announce",
    ...(spec.tools && spec.tools.length > 0 ? ["--tools", spec.tools.join(",")] : []),
    ...(spec.disabled ? ["--disabled"] : []),
  ];
}

// `openclaw cron <enable|disable|rm|get> <id>`. rm supports --json; the others don't.
export function cronControlArgs(action: "enable" | "disable" | "rm" | "get", id: string): string[] {
  return action === "rm" ? ["cron", "rm", "--json", id] : ["cron", action, id];
}

export function cronListArgs(): string[] {
  return ["cron", "list", "--all", "--json"];
}

// Scrub CLI output before it is persisted or returned to a client. The gateway token
// is passed to the spawned process via env (and --token argv), so a failing CLI could
// echo it into stderr. redactForPersistence only catches known token *shapes*, so we
// also replace the live gateway/internal secret values verbatim.
export function scrubOpenClawOutput(text: string): string {
  let out = text;
  for (const secret of [process.env.OPENCLAW_GATEWAY_TOKEN, process.env.OPERANT_INTERNAL_TOKEN]) {
    if (secret && secret.length >= 8) out = out.split(secret).join("[REDACTED]");
  }
  return redactForPersistence(out) as string;
}

function displayCommand(command: string[]): string[] {
  return command.map((part, index) => (
    index > 0 && (command[index - 1] === "--token" || command[index - 1] === "--password") ? "[REDACTED]" : part
  ));
}

export function parseJsonFromOutput(output: string): unknown | null {
  const trimmed = output.trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    const candidates = [trimmed.indexOf("{"), trimmed.indexOf("[")]
      .filter((index) => index >= 0)
      .sort((a, b) => a - b);
    for (const start of candidates) {
      try {
        return JSON.parse(trimmed.slice(start));
      } catch {
        continue;
      }
    }
    return null;
  }
}

function toRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function numeric(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function dateFromEpochMs(value: unknown): Date | null {
  const millis = numeric(value);
  if (!millis) return null;
  const date = new Date(millis);
  return Number.isFinite(date.getTime()) ? date : null;
}

export function extractOpenClawStatusObservations(json: unknown): {
  sessions: OpenClawObservedSession[];
  rawSessionCount: number;
  taskSummary: Record<string, unknown> | null;
} {
  const root = toRecord(json);
  const sessionsNode = toRecord(root?.sessions);
  const recent = Array.isArray(sessionsNode?.recent) ? sessionsNode.recent : [];
  const sessions: OpenClawObservedSession[] = [];
  for (const item of recent) {
    const row = toRecord(item);
    const key = stringValue(row?.key) ?? stringValue(row?.sessionId);
    if (!row || !key) continue;
    const inputTokens = numeric(row.inputTokens) ?? 0;
    const outputTokens = numeric(row.outputTokens) ?? 0;
    const cacheReadTokens = numeric(row.cacheRead) ?? 0;
    const cacheWriteTokens = numeric(row.cacheWrite) ?? 0;
    const totalTokens = numeric(row.totalTokens) ?? inputTokens + outputTokens + cacheReadTokens + cacheWriteTokens;
    const usage = totalTokens > 0 ? {
      provider: null,
      model: stringValue(row.model),
      inputTokens,
      outputTokens,
      toolName: stringValue(row.kind) ?? stringValue(row.runtime),
      metadata: {
        source: "openclaw.status",
        openclawSessionKey: key,
        openclawSessionId: stringValue(row.sessionId),
        updatedAt: numeric(row.updatedAt),
        cacheReadTokens,
        cacheWriteTokens,
        totalTokens,
        totalTokensFresh: row.totalTokensFresh ?? null,
      },
    } : null;
    sessions.push({
      key,
      lastEventAt: dateFromEpochMs(row.updatedAt),
      runId: stringValue(row.sessionId) ? `openclaw-session:${stringValue(row.sessionId)}` : `openclaw-session:${key}`,
      metadata: {
        source: "openclaw.status",
        agentId: stringValue(row.agentId),
        kind: stringValue(row.kind),
        openclawSessionId: stringValue(row.sessionId),
        model: stringValue(row.model),
        runtime: stringValue(row.runtime),
        flags: Array.isArray(row.flags) ? row.flags : [],
        inputTokens,
        outputTokens,
        cacheReadTokens,
        cacheWriteTokens,
        totalTokens,
        percentUsed: row.percentUsed ?? null,
        updatedAt: numeric(row.updatedAt),
      },
      usage,
    });
  }
  return {
    sessions,
    rawSessionCount: numeric(sessionsNode?.count) ?? sessions.length,
    taskSummary: toRecord(root?.tasks),
  };
}

export function extractOpenClawSessionsObservations(json: unknown): OpenClawObservedSession[] {
  const root = toRecord(json);
  const rows = Array.isArray(root?.sessions) ? root.sessions : [];
  const sessions: OpenClawObservedSession[] = [];
  for (const item of rows) {
    const row = toRecord(item);
    const key = stringValue(row?.key);
    if (!row || !key) continue;
    const inputTokens = numeric(row.inputTokens) ?? 0;
    const outputTokens = numeric(row.outputTokens) ?? 0;
    const totalTokens = numeric(row.totalTokens) ?? inputTokens + outputTokens;
    const sessionId = stringValue(row.sessionId);
    const updatedAt = numeric(row.updatedAt);
    const usage = totalTokens > 0 ? {
      provider: stringValue(row.modelProvider),
      model: stringValue(row.model),
      inputTokens,
      outputTokens,
      toolName: stringValue(row.kind) ?? "session",
      metadata: {
        source: "openclaw.sessions",
        openclawSessionKey: key,
        openclawSessionId: sessionId,
        updatedAt,
        totalTokens,
        totalTokensFresh: row.totalTokensFresh ?? null,
        contextTokens: numeric(row.contextTokens),
      },
    } : null;
    sessions.push({
      key,
      lastEventAt: dateFromEpochMs(updatedAt),
      runId: sessionId ? `openclaw-session:${sessionId}` : `openclaw-session:${key}`,
      metadata: {
        source: "openclaw.sessions",
        agentId: stringValue(row.agentId),
        kind: stringValue(row.kind),
        openclawSessionId: sessionId,
        model: stringValue(row.model),
        modelProvider: stringValue(row.modelProvider),
        runtime: toRecord(row.agentRuntime)?.id ?? null,
        inputTokens,
        outputTokens,
        totalTokens,
        totalTokensFresh: row.totalTokensFresh ?? null,
        contextTokens: numeric(row.contextTokens),
        updatedAt,
      },
      usage,
    });
  }
  return sessions;
}

export function extractOpenClawTaskObservations(json: unknown): OpenClawObservedTask[] {
  const root = toRecord(json);
  const tasks = Array.isArray(root?.tasks) ? root.tasks : [];
  const observed: OpenClawObservedTask[] = [];
  for (const item of tasks) {
    const row = toRecord(item);
    const runId = stringValue(row?.runId) ?? stringValue(row?.taskId);
    if (!row || !runId) continue;
    observed.push({
      runId,
      sessionKey: stringValue(row.childSessionKey) ?? stringValue(row.requesterSessionKey),
      status: stringValue(row.status) ?? "observed",
      startedAt: dateFromEpochMs(row.startedAt) ?? dateFromEpochMs(row.createdAt),
      finishedAt: dateFromEpochMs(row.endedAt),
      metadata: {
        source: "openclaw.tasks",
        taskId: stringValue(row.taskId),
        runtime: stringValue(row.runtime),
        sourceId: stringValue(row.sourceId),
        ownerKey: stringValue(row.ownerKey),
        scopeKind: stringValue(row.scopeKind),
        label: stringValue(row.label),
        task: stringValue(row.task),
        deliveryStatus: stringValue(row.deliveryStatus),
        notifyPolicy: stringValue(row.notifyPolicy),
        lastEventAt: numeric(row.lastEventAt),
        terminalSummary: stringValue(row.terminalSummary),
      },
    });
  }
  return observed;
}

// Parse `openclaw cron list --all --json` ({ jobs: [...] }) into a normalized view used
// to reconcile materialized scheduled workflows. Field names are matched defensively
// because the cron job shape carries more than we govern; the raw job is preserved as
// metadata. enabled is null when neither an enabled nor disabled flag is present.
export function extractOpenClawCronObservations(json: unknown): OpenClawObservedCron[] {
  const root = toRecord(json);
  const jobs = Array.isArray(root?.jobs) ? root.jobs : Array.isArray(json) ? json : [];
  const observed: OpenClawObservedCron[] = [];
  for (const item of jobs) {
    const row = toRecord(item);
    const id = stringValue(row?.id) ?? stringValue(row?.jobId) ?? stringValue(row?.name);
    if (!row || !id) continue;
    const enabled = typeof row.enabled === "boolean"
      ? row.enabled
      : typeof row.disabled === "boolean"
        ? !row.disabled
        : null;
    observed.push({
      id,
      name: stringValue(row.name),
      enabled,
      metadata: { source: "openclaw.cron", ...row },
    });
  }
  return observed;
}

// Pull the gateway-assigned job id out of a `cron add --json` result.
export function extractCronJobId(json: unknown): string | null {
  const root = toRecord(json);
  if (!root) return null;
  const job = toRecord(root.job);
  return stringValue(root.id) ?? stringValue(root.jobId) ?? stringValue(job?.id) ?? stringValue(job?.jobId) ?? stringValue(root.name);
}

export function extractOpenClawUsageCostObservations(json: unknown): {
  snapshots: OpenClawUsageCostSnapshot[];
  totals: Record<string, unknown> | null;
  cacheStatus: Record<string, unknown> | null;
} {
  const root = toRecord(json);
  const daily = Array.isArray(root?.daily) ? root.daily : [];
  const snapshots: OpenClawUsageCostSnapshot[] = [];
  for (const item of daily) {
    const row = toRecord(item);
    const day = stringValue(row?.date);
    const totalCost = numeric(row?.totalCost);
    if (!row || !day || !/^\d{4}-\d{2}-\d{2}$/.test(day) || totalCost === null) continue;
    snapshots.push({
      day,
      estimatedCostUsd: totalCost,
      metadata: {
        source: "openclaw.usage-cost",
        day,
        days: numeric(root?.days),
        updatedAt: numeric(root?.updatedAt),
        inputTokens: numeric(row.input) ?? 0,
        outputTokens: numeric(row.output) ?? 0,
        cacheReadTokens: numeric(row.cacheRead) ?? 0,
        cacheWriteTokens: numeric(row.cacheWrite) ?? 0,
        totalTokens: numeric(row.totalTokens) ?? 0,
        inputCost: numeric(row.inputCost),
        outputCost: numeric(row.outputCost),
        cacheReadCost: numeric(row.cacheReadCost),
        cacheWriteCost: numeric(row.cacheWriteCost),
        missingCostEntries: numeric(row.missingCostEntries) ?? 0,
      },
    });
  }
  return {
    snapshots,
    totals: toRecord(root?.totals),
    cacheStatus: toRecord(root?.cacheStatus),
  };
}

export function runOpenClawCommand(args: string[], params: {
  configPath?: string;
  gatewayToken?: string;
  timeoutMs?: number;
  extraEnv?: NodeJS.ProcessEnv;
} = {}): Promise<OpenClawCommandResult> {
  const cli = process.env.OPENCLAW_CLI_COMMAND || "openclaw";
  const command = displayCommand([cli, ...args]);
  const env = {
    ...process.env,
    ...params.extraEnv,
    ...(params.configPath ? { OPENCLAW_CONFIG_PATH: params.configPath } : {}),
    ...(params.gatewayToken ? { OPENCLAW_GATEWAY_TOKEN: params.gatewayToken } : {}),
  };
  const timeoutMs = params.timeoutMs ?? 20_000;

  return new Promise((resolve) => {
    const child = spawn(cli, args, { env });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (error) => {
      clearTimeout(timeout);
      resolve({
        command,
        exitCode: 127,
        timedOut,
        stdout: scrubOpenClawOutput(stdout),
        stderr: scrubOpenClawOutput(`${stderr}${error instanceof Error ? error.message : String(error)}`),
        json: null,
      });
    });
    child.on("close", (exitCode) => {
      clearTimeout(timeout);
      // Parse JSON from the raw stdout, then scrub the string fields. The gateway token
      // can leak into stdout/stderr on failure, so the runner owns redaction for every
      // caller; json stays the parsed structured data (no consumer re-parses the string).
      const json = parseJsonFromOutput(stdout);
      resolve({
        command,
        exitCode,
        timedOut,
        stdout: scrubOpenClawOutput(stdout),
        stderr: scrubOpenClawOutput(stderr),
        json,
      });
    });
  });
}

export function runOpenClawCheck(params: {
  check: OpenClawCheckName;
  configPath?: string;
  gatewayToken?: string;
  timeoutMs?: number;
  extraEnv?: NodeJS.ProcessEnv;
}): Promise<OpenClawCheckResult> {
  return runOpenClawCommand(openClawCheckCommandArgs(params.check, params), params).then((result) => ({
    check: params.check,
    command: result.command,
    exitCode: result.exitCode,
    timedOut: result.timedOut,
    stdout: result.stdout,
    stderr: result.stderr,
    json: result.json,
  }));
}
