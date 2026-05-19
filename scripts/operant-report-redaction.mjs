import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";

export const defaultSensitiveEnvNames = [
  "OPERANT_ADMIN_LOGIN_TOKEN",
  "OPERANT_INTERNAL_TOKEN",
  "OPERANT_SECRET_KEY",
  "POSTGRES_PASSWORD",
  "DATABASE_URL",
  "OPENCLAW_GATEWAY_TOKEN",
  "SLACK_APP_TOKEN",
  "OPERANT_LIVE_SLACK_APP_TOKEN",
  "SLACK_BOT_TOKEN",
  "OPERANT_LIVE_SLACK_BOT_TOKEN",
  "SLACK_CONFIG_TOKEN",
  "SLACK_CONFIGURATION_TOKEN",
  "OPERANT_LIVE_SLACK_CONFIG_TOKEN",
  "SLACK_USER_TOKEN",
  "OPERANT_LIVE_SLACK_USER_TOKEN",
  "OPERANT_LIVE_DENIED_USER_TOKEN",
  "MODEL_API_KEY",
  "OPERANT_LIVE_MODEL_API_KEY",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
];

export const secretLikePattern = /\b(?:xox[a-z]-[A-Za-z0-9._-]+|xapp-[A-Za-z0-9._-]+|sk-(?:ant-)?[A-Za-z0-9._-]+|operant_(?:admin|internal|pg)_[A-Za-z0-9_-]+|openclaw_gateway_[A-Za-z0-9_-]+)\b/g;

function pushSensitiveValue(values, value) {
  if (value && String(value).length >= 8) values.push(String(value));
}

function integrationCredentialEnvNames(source) {
  const names = [];
  for (const spec of String(source?.OPERANT_LIVE_INTEGRATION_CREDENTIALS || "").split(",")) {
    const trimmed = spec.trim();
    if (!trimmed) continue;
    const separator = trimmed.indexOf("=");
    if (separator === -1) continue;
    const envName = trimmed.slice(separator + 1).trim();
    if (envName) names.push(envName);
  }
  return names;
}

export function integrationCredentialSensitiveValues(sources = [process.env]) {
  const envSources = Array.isArray(sources) ? sources.filter(Boolean) : [sources].filter(Boolean);
  const values = [];
  const envNames = new Set();

  for (const source of envSources) {
    for (const envName of integrationCredentialEnvNames(source)) envNames.add(envName);
    const json = source.OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON;
    if (!json) continue;
    try {
      const parsed = JSON.parse(json);
      if (!Array.isArray(parsed)) continue;
      for (const item of parsed) {
        if (!item || typeof item !== "object") continue;
        pushSensitiveValue(values, item.secretValue);
        if (item.secretValueEnv) envNames.add(String(item.secretValueEnv));
      }
    } catch {
      // Redaction must remain best-effort and non-throwing for malformed env.
    }
  }

  for (const envName of envNames) {
    for (const source of envSources) pushSensitiveValue(values, source[envName]);
  }
  return values;
}

export function sensitiveEnvValues(sources = [process.env], names = defaultSensitiveEnvNames) {
  const envSources = Array.isArray(sources) ? sources : [sources];
  const values = [];
  for (const source of envSources) {
    if (!source) continue;
    for (const name of names) {
      pushSensitiveValue(values, source[name]);
    }
  }
  values.push(...integrationCredentialSensitiveValues(envSources));
  return Array.from(new Set(values)).sort((left, right) => right.length - left.length);
}

export function redactString(value, sensitiveValues = sensitiveEnvValues()) {
  let redacted = value;
  for (const secret of sensitiveValues) redacted = redacted.replaceAll(secret, "[redacted]");
  return redacted.replace(secretLikePattern, "[redacted]");
}

export function redactSecretMaterial(value, sensitiveValues = sensitiveEnvValues()) {
  if (typeof value === "string") return redactString(value, sensitiveValues);
  if (Array.isArray(value)) return value.map((item) => redactSecretMaterial(item, sensitiveValues));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, redactSecretMaterial(item, sensitiveValues)]));
  }
  return value;
}

export function assertNoSecretMaterial(report, sensitiveValues = sensitiveEnvValues()) {
  const body = JSON.stringify(report);
  const leaked = sensitiveValues.filter((secret) => body.includes(secret));
  const tokenMatch = body.match(secretLikePattern);
  if (leaked.length > 0 || tokenMatch) {
    throw new Error(`Report still contains ${leaked.length + (tokenMatch ? tokenMatch.length : 0)} token-like secret value(s)`);
  }
}

function archiveTimestamp(value) {
  return String(value || new Date().toISOString()).replace(/[:.]/g, "-").replace(/[^0-9A-Za-z_-]/g, "_");
}

export async function archiveExistingJsonReport(reportPath, sensitiveValues = sensitiveEnvValues(), archiveDirectory = path.join(path.dirname(reportPath), "report-archive")) {
  let existingBody;
  let existingStat;
  try {
    [existingBody, existingStat] = await Promise.all([readFile(reportPath, "utf8"), stat(reportPath)]);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }

  let existingReport;
  try {
    existingReport = JSON.parse(existingBody);
  } catch {
    return null;
  }

  const redactedExistingReport = redactSecretMaterial(existingReport, sensitiveValues);
  assertNoSecretMaterial(redactedExistingReport, sensitiveValues);
  const extension = path.extname(reportPath) || ".json";
  const baseName = path.basename(reportPath, extension);
  const generatedAt = existingReport.generatedAt || existingStat.mtime.toISOString();
  const archivePath = path.join(archiveDirectory, `${baseName}.${archiveTimestamp(generatedAt)}.${process.pid}${extension}`);
  await mkdir(archiveDirectory, { recursive: true });
  await writeFile(archivePath, `${JSON.stringify(redactedExistingReport, null, 2)}\n`);
  return archivePath;
}

export async function writeRedactedJsonReport(reportPath, report, sensitiveValues = sensitiveEnvValues(), options = {}) {
  const redactedReport = redactSecretMaterial(report, sensitiveValues);
  assertNoSecretMaterial(redactedReport, sensitiveValues);
  await mkdir(path.dirname(reportPath), { recursive: true });
  const archivedPath = options.archiveExisting
    ? await archiveExistingJsonReport(reportPath, sensitiveValues, options.archiveDirectory)
    : null;
  await writeFile(reportPath, `${JSON.stringify(redactedReport, null, 2)}\n`);
  return { report: redactedReport, archivedPath };
}
