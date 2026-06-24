#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  missingScopes,
  parseSlackBotScopesFromManifest,
  parseSlackUserScopesFromManifest,
  recommendedOpenClawBotScopes,
  requiredLiveBotScopes,
  requiredVerifierUserScopes,
} from "./slack-scope-contract.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const checks = [
  {
    file: "deploy/slack/manifest.yaml",
    patterns: [
      ["Slack manifest metadata", /_metadata:[\s\S]*major_version:\s*1/],
      ["Slack socket mode enabled", /socket_mode_enabled:\s*true/],
      ["Slack interactivity enabled", /interactivity:[\s\S]*is_enabled:\s*true/],
      ["Slack home tab enabled", /home_tab_enabled:\s*true/],
      ["Slack messages tab enabled", /messages_tab_enabled:\s*true/],
      ["Slack messages tab writable", /messages_tab_read_only_enabled:\s*false/],
      ["Slack app home event", /-\s*app_home_opened/],
      ["Slack app mention event", /-\s*app_mention/],
      ["Slack channel rename event", /-\s*channel_rename/],
      ["Slack channel membership events", /-\s*member_joined_channel[\s\S]*-\s*member_left_channel/],
      ["Slack IM messages event", /-\s*message\.im/],
      ["Slack channel messages event", /-\s*message\.channels/],
      ["Slack private channel messages event", /-\s*message\.groups/],
      ["Slack MPIM messages event", /-\s*message\.mpim/],
      ["Slack reaction events", /-\s*reaction_added[\s\S]*-\s*reaction_removed/],
      ["Slack pin events", /-\s*pin_added[\s\S]*-\s*pin_removed/],
      ["Slack verifier user scope", /user:[\s\S]*-\s*chat:write[\s\S]*bot:/],
      ["Slack app mentions scope", /-\s*app_mentions:read/],
      ["Slack assistant scope", /-\s*assistant:write/],
      ["Slack chat write scope", /-\s*chat:write/],
      ["Slack commands scope", /-\s*commands/],
      ["Slack channel scopes", /-\s*channels:history[\s\S]*-\s*channels:join[\s\S]*-\s*channels:read/],
      ["Slack private channel scopes", /-\s*groups:history[\s\S]*-\s*groups:read/],
      ["Slack IM scopes", /-\s*im:history[\s\S]*-\s*im:read[\s\S]*-\s*im:write/],
      ["Slack MPIM scopes", /-\s*mpim:history[\s\S]*-\s*mpim:read[\s\S]*-\s*mpim:write/],
      ["Slack file scopes", /-\s*files:read[\s\S]*-\s*files:write/],
      ["Slack reaction scopes", /-\s*reactions:read[\s\S]*-\s*reactions:write/],
      ["Slack pin scopes", /-\s*pins:read[\s\S]*-\s*pins:write/],
      ["Slack user lookup scopes", /-\s*usergroups:read[\s\S]*-\s*users:read/],
    ],
  },
  {
    file: "deploy/slack/README.md",
    patterns: [
      ["Slack live env template", /live\.env\.example/],
      ["Slack app-level token note", /connections:write/],
      ["Slack bot token note", /xoxb-\.\.\./],
      ["Slack app token note", /xapp-\.\.\./],
      ["Slack SecretRefs note", /SecretRefs/],
      ["Socket Mode has no Request URL", /Do not enter an Event Subscriptions \*\*Request URL\*\*[\s\S]*Socket Mode[\s\S]*WebSocket[\s\S]*App Manifest/],
      ["Slack installed manifest probe docs", /app_configurations:read[\s\S]*slack:manifest-probe[\s\S]*apps\.manifest\.export/],
    ],
  },
  {
    file: "deploy/slack/live.env.example",
    patterns: [
      ["Slack live admin user", /OPERANT_LIVE_ADMIN_SLACK_USER_ID=U\.\.\./],
      ["Slack channel", /SLACK_CHANNEL_ID=C\.\.\./],
      ["Slack app token", /SLACK_APP_TOKEN=<slack-app-token>/],
      ["Slack bot token", /SLACK_BOT_TOKEN=<slack-bot-token>/],
      ["Slack user token", /SLACK_USER_TOKEN=<xoxp-or-xoxc-allowed-human-user-oauth-token>/],
      ["Slack config token", /SLACK_CONFIG_TOKEN=<xoxp-or-xoxe-slack-configuration-token>/],
      ["Slack DM channel", /OPERANT_LIVE_DM_CHANNEL_ID=D\.\.\./],
      ["Slack denied user token", /OPERANT_LIVE_DENIED_USER_TOKEN=<xoxp-or-xoxc-denied-human-user-oauth-token>/],
      ["One-human denied policy guidance", /[Dd]enied-policy proof is one-human by default[\s\S]*one-human temporary-deny proof/],
      ["Slack membership verifier method", /conversations\.members/],
      ["Model key", /OPENAI_API_KEY=<model-api-key>/],
      ["Approval prompt", /OPERANT_LIVE_APPROVAL_PROMPT=/],
    ],
  },
  {
    file: "deploy/teams/manifest.json",
    patterns: [
      ["Teams bot scopes", /"scopes":\s*\[\s*"personal",\s*"team",\s*"groupchat"\s*\]/],
      ["Teams supports files flag", /"supportsFiles":\s*true/],
      ["Teams channel read RSC", /"ChannelMessage\.Read\.Group"/],
      ["Teams channel send RSC", /"ChannelMessage\.Send\.Group"/],
      ["Teams member read RSC", /"Member\.Read\.Group"/],
      ["Teams owner read RSC", /"Owner\.Read\.Group"/],
      ["Teams channel settings RSC", /"ChannelSettings\.Read\.Group"/],
      ["Teams team settings RSC", /"TeamSettings\.Read\.Group"/],
      ["Teams chat message RSC", /"ChatMessage\.Read\.Chat"/],
    ],
  },
  {
    file: "deploy/teams/README.md",
    patterns: [
      ["Teams OpenClaw reuse note", /OpenClaw's `msteams` channel/],
      ["Teams Azure endpoint", /Messaging endpoint[\s\S]*\/api\/messages/],
      ["Teams tunnel operator note", /Operant does not bundle a tunnel provider/],
      ["Teams live env template", /live\.env\.example/],
    ],
  },
  {
    file: "deploy/teams/live.env.example",
    patterns: [
      ["Teams app id", /TEAMS_APP_ID=00000000-0000-0000-0000-000000000000/],
      ["Teams app password", /TEAMS_APP_PASSWORD=<teams-bot-client-secret>/],
      ["Teams tenant id", /TEAMS_TENANT_ID=00000000-0000-0000-0000-000000000000/],
      ["Teams public endpoint", /MSTEAMS_PUBLIC_MESSAGING_ENDPOINT=https:\/\/.+\/api\/messages/],
      ["Teams allowed user", /OPERANT_LIVE_TEAMS_ALLOWED_AAD_USER_ID=/],
      ["Teams approval prompt", /OPERANT_LIVE_TEAMS_APPROVAL_PROMPT=/],
    ],
  },
  {
    file: "deploy/helm/operant/Chart.yaml",
    patterns: [
      ["Helm chart apiVersion", /apiVersion:\s*v2/],
      ["Helm chart name", /name:\s*operant/],
    ],
  },
  {
    file: "deploy/helm/operant/values.yaml",
    patterns: [
      ["replica count fixed to one", /replicaCount:\s*1/],
      ["control-plane image values", /controlPlane:[\s\S]*repository:\s*ghcr\.io\/tomascupr\/operant\/control-plane/],
      ["OpenClaw image values", /openclaw:[\s\S]*repository:\s*ghcr\.io\/openclaw\/openclaw/],
      ["OpenClaw service disabled by default", /openclaw:[\s\S]*service:[\s\S]*enabled:\s*false[\s\S]*publicPort:\s*18789/],
      ["storage values", /openclawStateSize:\s*20Gi[\s\S]*openclawConfigSize:\s*1Gi/],
      ["admin login token value", /operantAdminLoginToken:\s*""/],
    ],
  },
  {
    file: "deploy/helm/operant/values.schema.json",
    patterns: [
      ["replica count schema minimum one", /"replicaCount"[\s\S]*"minimum":\s*1/],
      ["replica count schema maximum one", /"replicaCount"[\s\S]*"maximum":\s*1/],
      ["trust-boundary schema description", /company\/workspace\/trust boundary/],
    ],
  },
  {
    file: "deploy/helm/operant/templates/statefulset.yaml",
    patterns: [
      ["StatefulSet kind", /kind:\s*StatefulSet/],
      ["headless governing service", /serviceName:\s*\{\{ include "operant\.fullname" \. \}\}-headless/],
      ["control-plane container", /name:\s*control-plane/],
      ["OpenClaw gateway container", /name:\s*openclaw-gateway/],
      ["OpenClaw allow unconfigured", /--allow-unconfigured/],
      ["OpenClaw session store bootstrap", /mkdir -p \/home\/node\/\.openclaw\/agents\/main\/sessions/],
      ["local gateway URL", /OPENCLAW_GATEWAY_URL[\s\S]*http:\/\/127\.0\.0\.1:\{\{ \.Values\.openclaw\.port \}\}/],
      ["admin login token env", /OPERANT_ADMIN_LOGIN_TOKEN[\s\S]*secretKeyRef:[\s\S]*key:\s*OPERANT_ADMIN_LOGIN_TOKEN/],
      ["user-owned resolver wrapper command", /OPENCLAW_SECRET_RESOLVER_COMMAND[\s\S]*\/operant\/openclaw\/operant-secret-resolver/],
      ["shared OpenClaw config PVC", /name:\s*openclaw-config[\s\S]*mountPath:\s*\/operant\/openclaw/],
      ["OpenClaw state PVC", /name:\s*openclaw-state[\s\S]*mountPath:\s*\/home\/node\/\.openclaw/],
      ["control-plane uses separate writable OpenClaw client state", /name:\s*control-plane[\s\S]*OPENCLAW_STATE_DIR[\s\S]*\/home\/node\/\.openclaw-client/],
      ["resolver mount", /operant-secret-resolver\.mjs/],
      ["volumeClaimTemplates", /volumeClaimTemplates:/],
    ],
  },
  {
    file: "deploy/helm/operant/templates/services.yaml",
    patterns: [
      ["headless StatefulSet service", /name:\s*\{\{ include "operant\.fullname" \. \}\}-headless[\s\S]*clusterIP:\s*None/],
      ["control-plane service", /kind:\s*Service[\s\S]*control-plane/],
      ["OpenClaw service opt-in guard", /\{\{- if \.Values\.openclaw\.service\.enabled \}\}[\s\S]*name:\s*\{\{ include "operant\.fullname" \. \}\}-openclaw/],
      ["OpenClaw service opt-in port", /port:\s*\{\{ \.Values\.openclaw\.service\.publicPort \}\}/],
    ],
  },
  {
    file: "deploy/helm/operant/templates/secret.yaml",
    patterns: [
      ["database URL required for created secret", /DATABASE_URL:\s*\{\{ required "database\.url is required when secrets\.create=true and database\.existingSecret\.name is empty" \.Values\.database\.url \| quote \}\}/],
      ["admin login token secret", /OPERANT_ADMIN_LOGIN_TOKEN:[\s\S]*secrets\.operantAdminLoginToken/],
    ],
  },
  {
    file: "deploy/helm/operant/templates/resolver-configmap.yaml",
    patterns: [
      ["resolver ConfigMap", /kind:\s*ConfigMap/],
      ["resolver file embedding", /\.Files\.Get "files\/operant-secret-resolver\.mjs"/],
    ],
  },
  {
    file: "deploy/helm/operant/files/operant-secret-resolver.mjs",
    patterns: [
      ["resolver calls Operant", /\/internal\/openclaw\/secrets/],
      ["resolver uses bearer token", /Authorization:\s*`Bearer \$\{token\}`/],
    ],
  },
  {
    file: "deploy/fly/README.md",
    patterns: [
      ["Fly one trust boundary", /One OpenClaw gateway Machine per trust boundary/],
      ["Fly secrets", /fly secrets set/],
      ["Fly config sync caveat", /config-sync/],
    ],
  },
];

const failures = [];

function expect(condition, detail) {
  if (!condition) failures.push(detail);
}

function at(root, pathParts) {
  let cursor = root;
  for (const part of pathParts) {
    if (!cursor || typeof cursor !== "object" || !(part in cursor)) return undefined;
    cursor = cursor[part];
  }
  return cursor;
}

function parseSimpleYamlScalar(rawValue) {
  const value = rawValue.trim();
  if (value === "") return undefined;
  if (value === "{}") return {};
  if (value === "[]") return [];
  if (value === "true") return true;
  if (value === "false") return false;
  if (/^-?\d+$/.test(value)) return Number(value);
  if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}

function parseSimpleYamlMap(source, file) {
  const root = {};
  const stack = [{ indent: -1, value: root }];
  for (const [index, line] of source.split(/\r?\n/).entries()) {
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    if (line.includes("\t")) throw new Error(`${file}:${index + 1}: tabs are not supported in Helm values`);
    const match = /^(\s*)([A-Za-z0-9_-]+):(?:\s*(.*))?$/.exec(line);
    if (!match) throw new Error(`${file}:${index + 1}: unsupported YAML shape`);
    const indent = match[1].length;
    const key = match[2];
    const scalar = parseSimpleYamlScalar(match[3] ?? "");
    while (indent <= stack[stack.length - 1].indent) stack.pop();
    const parent = stack[stack.length - 1].value;
    if (!parent || typeof parent !== "object" || Array.isArray(parent)) {
      throw new Error(`${file}:${index + 1}: parent is not a map`);
    }
    if (scalar === undefined) {
      parent[key] = {};
      stack.push({ indent, value: parent[key] });
    } else {
      parent[key] = scalar;
    }
  }
  return root;
}

function typeMatches(value, expectedType) {
  if (expectedType === "integer") return Number.isInteger(value);
  if (expectedType === "array") return Array.isArray(value);
  if (expectedType === "object") return value && typeof value === "object" && !Array.isArray(value);
  return typeof value === expectedType;
}

function validateSchemaSubset(value, schema, pathLabel, file) {
  if (!schema || typeof schema !== "object") return;
  if (schema.type && !typeMatches(value, schema.type)) {
    failures.push(`${file}: ${pathLabel} should be ${schema.type}`);
    return;
  }
  if (schema.enum && !schema.enum.includes(value)) failures.push(`${file}: ${pathLabel} should be one of ${schema.enum.join(", ")}`);
  if (typeof schema.minLength === "number" && typeof value === "string" && value.length < schema.minLength) {
    failures.push(`${file}: ${pathLabel} should have length >= ${schema.minLength}`);
  }
  if (typeof schema.minimum === "number" && typeof value === "number" && value < schema.minimum) {
    failures.push(`${file}: ${pathLabel} should be >= ${schema.minimum}`);
  }
  if (typeof schema.maximum === "number" && typeof value === "number" && value > schema.maximum) {
    failures.push(`${file}: ${pathLabel} should be <= ${schema.maximum}`);
  }
  if (schema.pattern && typeof value === "string" && !(new RegExp(schema.pattern).test(value))) {
    failures.push(`${file}: ${pathLabel} should match ${schema.pattern}`);
  }
  if (schema.type !== "object") return;
  const required = Array.isArray(schema.required) ? schema.required : [];
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) failures.push(`${file}: ${pathLabel}.${key} is required by schema`);
  }
  const properties = schema.properties || {};
  if (schema.additionalProperties === false) {
    for (const key of Object.keys(value)) {
      if (!Object.prototype.hasOwnProperty.call(properties, key)) failures.push(`${file}: ${pathLabel}.${key} is not allowed by schema`);
    }
  }
  for (const [key, childSchema] of Object.entries(properties)) {
    if (Object.prototype.hasOwnProperty.call(value, key)) validateSchemaSubset(value[key], childSchema, `${pathLabel}.${key}`, file);
  }
}

async function verifyHelmValuesSchema() {
  const file = "deploy/helm/operant/values.schema.json";
  let schema;
  try {
    schema = JSON.parse(await readFile(path.join(repoRoot, file), "utf8"));
  } catch (error) {
    failures.push(`${file}: invalid JSON (${error.message})`);
    return;
  }
  const requiredTopLevel = [
    "replicaCount",
    "imagePullPolicy",
    "controlPlane",
    "openclaw",
    "database",
    "redis",
    "secrets",
    "workspace",
    "storage",
    "service",
    "ingress",
    "nodeSelector",
    "tolerations",
    "affinity",
  ];
  expect(schema.type === "object", `${file}: root schema must be an object`);
  expect(schema.additionalProperties === false, `${file}: root additionalProperties must be false`);
  for (const key of requiredTopLevel) {
    expect(schema.required?.includes(key), `${file}: missing required top-level value ${key}`);
    expect(Boolean(schema.properties?.[key]), `${file}: missing top-level property schema for ${key}`);
  }
  expect(at(schema, ["properties", "replicaCount", "minimum"]) === 1, `${file}: replicaCount must have minimum 1`);
  expect(at(schema, ["properties", "replicaCount", "maximum"]) === 1, `${file}: replicaCount must have maximum 1`);
  expect(at(schema, ["properties", "controlPlane", "additionalProperties"]) === false, `${file}: controlPlane must reject unknown keys`);
  expect(at(schema, ["properties", "openclaw", "additionalProperties"]) === false, `${file}: openclaw must reject unknown keys`);
  expect(at(schema, ["properties", "secrets", "additionalProperties"]) === false, `${file}: secrets must reject unknown keys`);
  for (const pathParts of [
    ["properties", "controlPlane", "properties", "port"],
    ["properties", "controlPlane", "properties", "publicPort"],
    ["properties", "openclaw", "properties", "port"],
    ["properties", "openclaw", "properties", "service", "properties", "publicPort"],
  ]) {
    const node = at(schema, pathParts);
    expect(node?.type === "integer" && node.minimum === 1 && node.maximum === 65535, `${file}: ${pathParts.join(".")} must constrain TCP port range`);
  }
  expect(at(schema, ["properties", "storage", "properties", "openclawStateSize", "pattern"]) === "^[1-9][0-9]*(Mi|Gi|Ti)$", `${file}: openclawStateSize must constrain Kubernetes quantity`);
  expect(at(schema, ["properties", "storage", "properties", "openclawConfigSize", "pattern"]) === "^[1-9][0-9]*(Mi|Gi|Ti)$", `${file}: openclawConfigSize must constrain Kubernetes quantity`);
  expect(at(schema, ["properties", "service", "properties", "type", "enum"])?.includes("ClusterIP"), `${file}: service.type enum must include ClusterIP`);
  expect(at(schema, ["properties", "service", "properties", "type", "enum"])?.includes("LoadBalancer"), `${file}: service.type enum must include LoadBalancer`);
  expect(at(schema, ["properties", "imagePullPolicy", "enum"])?.includes("IfNotPresent"), `${file}: imagePullPolicy enum must include IfNotPresent`);
  return schema;
}

async function verifyHelmDefaultValues(schema) {
  if (!schema) return;
  const file = "deploy/helm/operant/values.yaml";
  try {
    const values = parseSimpleYamlMap(await readFile(path.join(repoRoot, file), "utf8"), file);
    validateSchemaSubset(values, schema, "values", file);
  } catch (error) {
    failures.push(`${file}: ${error.message}`);
  }
}

async function verifySlackScopeContract() {
  const file = "deploy/slack/manifest.yaml";
  let source = "";
  let botScopes = [];
  let userScopes = [];
  try {
    source = await readFile(path.join(repoRoot, file), "utf8");
    botScopes = parseSlackBotScopesFromManifest(source);
    userScopes = parseSlackUserScopesFromManifest(source);
  } catch (error) {
    failures.push(`${file}: could not parse Slack scopes (${error.message})`);
    return;
  }
  const missingUserScopes = missingScopes(userScopes, requiredVerifierUserScopes);
  if (missingUserScopes.length > 0) {
    failures.push(`${file}: missing verifier user scopes from shared contract: ${missingUserScopes.join(", ")}`);
  }
  const missingStrictScopes = missingScopes(botScopes, requiredLiveBotScopes);
  if (missingStrictScopes.length > 0) {
    failures.push(`${file}: missing strict live-acceptance bot scopes from shared contract: ${missingStrictScopes.join(", ")}`);
  }
  const missingRecommendedScopes = missingScopes(botScopes, recommendedOpenClawBotScopes);
  if (missingRecommendedScopes.length > 0) {
    failures.push(`${file}: missing recommended OpenClaw bot scopes from shared contract: ${missingRecommendedScopes.join(", ")}`);
  }
  const duplicateBotScopes = botScopes.filter((scope, index) => botScopes.indexOf(scope) !== index);
  if (duplicateBotScopes.length > 0) {
    failures.push(`${file}: duplicate bot scopes: ${[...new Set(duplicateBotScopes)].join(", ")}`);
  }
  const duplicateUserScopes = userScopes.filter((scope, index) => userScopes.indexOf(scope) !== index);
  if (duplicateUserScopes.length > 0) {
    failures.push(`${file}: duplicate user scopes: ${[...new Set(duplicateUserScopes)].join(", ")}`);
  }
}

async function verifyTeamsIcons() {
  for (const [file, width, height] of [
    ["deploy/teams/color.png", 192, 192],
    ["deploy/teams/outline.png", 32, 32],
  ]) {
    let png;
    try {
      png = await readFile(path.join(repoRoot, file));
    } catch (error) {
      failures.push(`${file}: missing (${error.message})`);
      continue;
    }
    const signature = png.subarray(0, 8).toString("hex");
    if (signature !== "89504e470d0a1a0a") {
      failures.push(`${file}: not a PNG`);
      continue;
    }
    const actualWidth = png.readUInt32BE(16);
    const actualHeight = png.readUInt32BE(20);
    if (actualWidth !== width || actualHeight !== height) {
      failures.push(`${file}: expected ${width}x${height}, got ${actualWidth}x${actualHeight}`);
    }
  }
}

for (const check of checks) {
  const target = path.join(repoRoot, check.file);
  let source = "";
  try {
    source = await readFile(target, "utf8");
  } catch (error) {
    failures.push(`${check.file}: missing (${error.message})`);
    continue;
  }
  for (const [label, pattern] of check.patterns) {
    if (!pattern.test(source)) failures.push(`${check.file}: ${label}`);
  }
}

const helmValuesSchema = await verifyHelmValuesSchema();
await verifyHelmDefaultValues(helmValuesSchema);
await verifySlackScopeContract();
await verifyTeamsIcons();

const canonicalResolver = await readFile(path.join(repoRoot, "deploy/openclaw/operant-secret-resolver.mjs"), "utf8");
const chartResolver = await readFile(path.join(repoRoot, "deploy/helm/operant/files/operant-secret-resolver.mjs"), "utf8");
if (canonicalResolver !== chartResolver) {
  failures.push("deploy/helm/operant/files/operant-secret-resolver.mjs: differs from deploy/openclaw/operant-secret-resolver.mjs");
}

if (failures.length > 0) {
  process.stderr.write("Deployment artifact check failed:\n");
  for (const failure of failures) process.stderr.write(`- ${failure}\n`);
  process.exit(1);
}

process.stdout.write("Deployment artifact check passed.\n");
