#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function argValue(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index === -1) return fallback;
  return process.argv[index + 1] || fallback;
}

const requiredChecks = [
  ["interpolated Compose project name", /^name:\s*\$\{OPERANT_COMPOSE_PROJECT_NAME:-operant\}/m],
  ["service postgres", /^  postgres:\n/m],
  ["service redis", /^  redis:\n/m],
  ["service policy-audit", /^  policy-audit:\n/m],
  ["service openclaw-gateway", /^  openclaw-gateway:\n/m],
  ["postgres healthcheck", /pg_isready -U operant -d operant/],
  ["postgres requires generated password", /POSTGRES_PASSWORD:\s*\$\{POSTGRES_PASSWORD:\?set POSTGRES_PASSWORD in \.env\}/],
  ["redis queue profile", /profiles:\s*\["queue"\]/],
  ["policy-audit Dockerfile", /dockerfile: apps\/control-plane\/Dockerfile/],
  ["policy-audit OpenClaw build arg", /OPENCLAW_VERSION:\s*\$\{OPENCLAW_VERSION:-[^}]+\}/],
  ["policy-audit requires DATABASE_URL", /DATABASE_URL:\s*\$\{DATABASE_URL:\?set DATABASE_URL in \.env\}/],
  ["policy-audit requires OPERANT_SECRET_KEY", /OPERANT_SECRET_KEY:\s*\$\{OPERANT_SECRET_KEY:\?set OPERANT_SECRET_KEY in \.env\}/],
  ["policy-audit requires OPERANT_INTERNAL_TOKEN", /OPERANT_INTERNAL_TOKEN:\s*\$\{OPERANT_INTERNAL_TOKEN:\?set OPERANT_INTERNAL_TOKEN in \.env\}/],
  ["policy-audit requires OPERANT_ADMIN_LOGIN_TOKEN", /OPERANT_ADMIN_LOGIN_TOKEN:\s*\$\{OPERANT_ADMIN_LOGIN_TOKEN:\?set OPERANT_ADMIN_LOGIN_TOKEN in \.env\}/],
  ["policy-audit receives OpenClaw gateway token", /policy-audit:[\s\S]*OPENCLAW_GATEWAY_TOKEN:\s*\$\{OPENCLAW_GATEWAY_TOKEN:\?set OPENCLAW_GATEWAY_TOKEN in \.env\}/],
  ["policy-audit explicitly allows private Compose ws gateway", /policy-audit:[\s\S]*OPENCLAW_ALLOW_INSECURE_PRIVATE_WS:\s*"1"/],
  ["policy-audit writes generated OpenClaw config", /OPENCLAW_CONFIG_PATH:\s*\/operant\/openclaw\/openclaw\.json/],
  ["base Compose disables Docker sandbox until overlay opts in", /OPERANT_OPENCLAW_SANDBOX_MODE:\s*\$\{OPERANT_OPENCLAW_SANDBOX_MODE:-off\}/],
  ["policy-audit uses separate writable OpenClaw client state", /policy-audit:[\s\S]*OPENCLAW_STATE_DIR:\s*\/home\/node\/\.openclaw-client/],
  ["policy-audit observes gateway OpenClaw state", /policy-audit:[\s\S]*OPENCLAW_OBSERVATION_STATE_DIR:\s*\/home\/node\/\.openclaw-gateway-state[\s\S]*operant-openclaw-state:\/home\/node\/\.openclaw-gateway-state/],
  ["policy-audit uses user-owned resolver wrapper", /OPENCLAW_SECRET_RESOLVER_COMMAND:\s*\/operant\/openclaw\/operant-secret-resolver/],
  ["policy-audit uses resolver script", /OPENCLAW_SECRET_RESOLVER_SCRIPT:\s*\/operant\/openclaw\/operant-secret-resolver\.mjs/],
  ["policy-audit waits for Postgres health", /policy-audit:[\s\S]*depends_on:[\s\S]*postgres:[\s\S]*condition: service_healthy/],
  ["policy-audit exposes dashboard on configurable localhost bind", /ports:[\s\S]*-\s*"\$\{OPERANT_HTTP_BIND:-127\.0\.0\.1\}:\$\{OPERANT_HTTP_PORT:-8080\}:8080"/],
  ["policy-audit healthcheck", /fetch\('http:\/\/127\.0\.0\.1:8080\/healthz'\)/],
  ["OpenClaw gateway image", /image:\s*operant-openclaw-gateway:\$\{OPENCLAW_VERSION:-[^}]+\}/],
  ["OpenClaw gateway Dockerfile", /dockerfile:\s*deploy\/openclaw\/Dockerfile\.gateway/],
  ["OpenClaw gateway build arg", /openclaw-gateway:[\s\S]*OPENCLAW_VERSION:\s*\$\{OPENCLAW_VERSION:-[^}]+\}/],
  ["OpenClaw requires gateway token", /OPENCLAW_GATEWAY_TOKEN:\s*\$\{OPENCLAW_GATEWAY_TOKEN:\?set OPENCLAW_GATEWAY_TOKEN in \.env\}/],
  ["OpenClaw points to policy-audit", /OPERANT_CONTROL_PLANE_URL:\s*http:\/\/policy-audit:8080/],
  ["OpenClaw receives internal token", /OPERANT_INTERNAL_TOKEN:\s*\$\{OPERANT_INTERNAL_TOKEN:\?set OPERANT_INTERNAL_TOKEN in \.env\}/],
  ["OpenClaw waits for policy-audit health", /openclaw-gateway:[\s\S]*depends_on:[\s\S]*policy-audit:[\s\S]*condition: service_healthy/],
  ["OpenClaw state volume", /operant-openclaw-state:\/home\/node\/\.openclaw/],
  ["OpenClaw reads generated config read-only", /operant-openclaw-config:\/operant\/openclaw:ro/],
  ["resolver script mounted read-only", /\.\/deploy\/openclaw\/operant-secret-resolver\.mjs:\/operant\/openclaw\/operant-secret-resolver\.mjs:ro/],
  ["OpenClaw session store bootstrap", /mkdir -p \/home\/node\/\.openclaw\/agents\/main\/sessions/],
  ["OpenClaw state dir private permissions", /chmod 700 \/home\/node\/\.openclaw/],
  ["OpenClaw Slack plugin bootstrap", /operant-ensure-slack-plugin/],
  ["OpenClaw gateway command", /exec openclaw gateway run --allow-unconfigured --port 18789 --bind lan --auth token/],
  ["Postgres localhost host bind and port", /-\s*"\$\{POSTGRES_HOST_BIND:-127\.0\.0\.1\}:\$\{POSTGRES_HOST_PORT:-5432\}:5432"/],
  ["OpenClaw gateway localhost host bind and port", /-\s*"\$\{OPENCLAW_GATEWAY_HOST_BIND:-127\.0\.0\.1\}:\$\{OPENCLAW_GATEWAY_HOST_PORT:-18789\}:18789"/],
  ["volume operant-postgres", /^  operant-postgres:\n/m],
  ["volume operant-redis", /^  operant-redis:\n/m],
  ["volume operant-openclaw-state", /^  operant-openclaw-state:\n/m],
  ["volume operant-openclaw-config", /^  operant-openclaw-config:\n/m],
];

const dockerfileChecks = [
  ["control-plane copies pnpm lockfile", /^COPY package\.json pnpm-workspace\.yaml pnpm-lock\.yaml \.\/$/m],
  ["control-plane installs dependencies with frozen lockfile", /^RUN pnpm install --filter @operant\/control-plane --frozen-lockfile$/m],
  ["control-plane production dependency stage", /^FROM node:24-alpine AS prod-deps$/m],
  ["control-plane installs production dependencies with frozen lockfile", /^RUN pnpm install --filter @operant\/control-plane --prod --frozen-lockfile$/m],
  ["control-plane runner copies package manifest for ESM", /^COPY --from=build --chown=node:node \/app\/apps\/control-plane\/package\.json \/app\/apps\/control-plane\/package\.json$/m],
  ["control-plane prepares private OpenClaw volume paths for node user", /^RUN mkdir -p \/operant\/openclaw \/home\/node\/\.openclaw \/home\/node\/\.openclaw-client\/agents\/main\/sessions \/home\/node\/\.openclaw-gateway-state \\\n  && chown -R node:node \/app \/operant \/home\/node\/\.openclaw \/home\/node\/\.openclaw-client \/home\/node\/\.openclaw-gateway-state \\\n  && chmod 700 \/home\/node\/\.openclaw \/home\/node\/\.openclaw-client \/home\/node\/\.openclaw-gateway-state$/m],
  ["control-plane copies runtime files as node user", /^COPY --from=build --chown=node:node \/app\/apps\/control-plane\/dist \/app\/apps\/control-plane\/dist$/m],
  ["control-plane runs as non-root node user", /^USER node$/m],
  ["control-plane OpenClaw version arg", /ARG OPENCLAW_VERSION=[^\n]+/],
  ["control-plane installs OpenClaw CLI", /npm install -g openclaw@\$\{OPENCLAW_VERSION\}/],
];

const dockerfileRejectChecks = [
  ["control-plane does not disable frozen lockfile installs", /--frozen-lockfile=false/],
];

const gatewayDockerfileChecks = [
  ["gateway image extends pinned OpenClaw image", /FROM ghcr\.io\/openclaw\/openclaw:\$\{OPENCLAW_VERSION\}/],
  ["gateway image redeclares OpenClaw version arg", /ARG OPENCLAW_VERSION=2026\.5\.\d+/],
  ["gateway image prepares Slack plugin package dir", /mkdir -p \/usr\/local\/share\/operant\/openclaw\/plugins/],
  ["gateway image copies Slack plugin bootstrap", /COPY deploy\/openclaw\/ensure-slack-plugin\.sh \/usr\/local\/bin\/operant-ensure-slack-plugin/],
  ["gateway image packs OpenClaw Slack plugin", /npm pack --pack-destination \/usr\/local\/share\/operant\/openclaw\/plugins @openclaw\/slack@\$\{OPENCLAW_VERSION\}/],
  ["gateway image returns to node user", /^USER node$/m],
];

const composeRejectChecks = [
  ["Compose does not ship default Postgres password", /POSTGRES_PASSWORD:\s*operant/],
  ["Compose does not ship default DATABASE_URL credentials", /postgres:\/\/operant:operant@postgres:5432\/operant/],
  ["base Compose does not mount Docker socket", /\/var\/run\/docker\.sock/],
];

const sandboxOverlayChecks = [
  ["dedicated trust-boundary warning", /dedicated single-trust-boundary Docker host/],
  ["policy-audit opts generated config into Docker sandbox", /policy-audit:[\s\S]*OPERANT_OPENCLAW_SANDBOX_MODE:\s*docker/],
  ["gateway sandbox image tag", /image:\s*operant-openclaw-sandbox:\$\{OPENCLAW_VERSION:-[^}]+\}/],
  ["gateway sandbox Dockerfile", /dockerfile:\s*deploy\/openclaw\/Dockerfile\.sandbox/],
  ["gateway sandbox OpenClaw build arg", /OPENCLAW_VERSION:\s*\$\{OPENCLAW_VERSION:-[^}]+\}/],
  ["gateway sandbox Docker CLI build arg", /DOCKER_CLI_VERSION:\s*\$\{DOCKER_CLI_VERSION:-[^}]+\}/],
  ["gateway sandbox Docker socket group", /group_add:[\s\S]*\$\{OPENCLAW_DOCKER_GID:-991\}/],
  ["service openclaw-gateway", /^  openclaw-gateway:\n/m],
  ["Docker socket host env", /DOCKER_HOST:\s*unix:\/\/\/var\/run\/docker\.sock/],
  ["configurable Docker socket mount", /\$\{OPENCLAW_DOCKER_SOCKET:-\/var\/run\/docker\.sock\}:\/var\/run\/docker\.sock/],
  ["OpenClaw runtime sandbox image inspect", /docker image inspect openclaw-sandbox:bookworm-slim/],
  ["OpenClaw runtime sandbox image build", /docker build -t openclaw-sandbox:bookworm-slim -f \/usr\/local\/share\/operant\/openclaw\/Dockerfile\.sandbox-runtime \/usr\/local\/share\/operant\/openclaw/],
  ["sandbox overlay state dir private permissions", /chmod 700 \/home\/node\/\.openclaw/],
  ["sandbox overlay Slack plugin bootstrap", /operant-ensure-slack-plugin/],
];

const sandboxDockerfileChecks = [
  ["sandbox image extends pinned OpenClaw image", /FROM ghcr\.io\/openclaw\/openclaw:\$\{OPENCLAW_VERSION\}/],
  ["sandbox image redeclares OpenClaw version arg", /ARG OPENCLAW_VERSION=2026\.5\.\d+/],
  ["sandbox image pins Docker CLI version", /ARG DOCKER_CLI_VERSION=29\.4\.3/],
  ["sandbox image downloads static Docker CLI", /download\.docker\.com\/linux\/static\/stable\/\$\{docker_arch\}\/docker-\$\{DOCKER_CLI_VERSION\}\.tgz/],
  ["sandbox image installs Docker CLI binary", /install -m 0755 \/tmp\/docker\/docker \/usr\/local\/bin\/docker/],
  ["sandbox image includes runtime Dockerfile", /COPY deploy\/openclaw\/Dockerfile\.sandbox-runtime \/usr\/local\/share\/operant\/openclaw\/Dockerfile\.sandbox-runtime/],
  ["sandbox image copies Slack plugin bootstrap", /COPY deploy\/openclaw\/ensure-slack-plugin\.sh \/usr\/local\/bin\/operant-ensure-slack-plugin/],
  ["sandbox image packs OpenClaw Slack plugin", /npm pack --pack-destination \/usr\/local\/share\/operant\/openclaw\/plugins @openclaw\/slack@\$\{OPENCLAW_VERSION\}/],
  ["sandbox image removes apt lists", /rm -rf[\s\S]*\/var\/lib\/apt\/lists\/\*/],
  ["sandbox image returns to node user", /^USER node$/m],
];

const sandboxRuntimeDockerfileChecks = [
  ["runtime sandbox extends Debian slim", /FROM debian:bookworm-slim/],
  ["runtime sandbox installs OpenClaw documented tools", /apt-get install -y --no-install-recommends[\s\S]*bash[\s\S]*ca-certificates[\s\S]*curl[\s\S]*git[\s\S]*jq[\s\S]*python3[\s\S]*ripgrep/],
  ["runtime sandbox removes apt lists", /rm -rf \/var\/lib\/apt\/lists\/\*/],
  ["runtime sandbox creates sandbox user", /useradd --create-home --shell \/bin\/bash sandbox/],
  ["runtime sandbox runs as sandbox user", /^USER sandbox$/m],
  ["runtime sandbox stable workdir", /^WORKDIR \/home\/sandbox$/m],
  ["runtime sandbox idle command", /CMD \["sleep", "infinity"\]/],
];

function serviceBlock(source, serviceName) {
  const header = new RegExp(`^  ${serviceName}:\\n`, "m");
  const match = header.exec(source);
  if (!match) return "";
  const start = match.index;
  const bodyStart = start + match[0].length;
  const rest = source.slice(bodyStart);
  const next = /^  [A-Za-z0-9_-]+:\n|^volumes:/m.exec(rest);
  return next ? source.slice(start, bodyStart + next.index) : source.slice(start);
}

export function verifyComposeTopology(source) {
  const failures = [];
  for (const [label, pattern] of requiredChecks) {
    if (!pattern.test(source)) failures.push(label);
  }
  for (const [label, pattern] of composeRejectChecks) {
    if (pattern.test(source)) failures.push(label);
  }
  const redisBlock = serviceBlock(source, "redis");
  const redisChecks = [
    ["redis uses pinned alpine image", /image:\s*redis:7-alpine/],
    ["redis appendonly persistence", /command:\s*\["redis-server", "--appendonly", "yes"\]/],
    ["redis persists under data volume", /-\s*operant-redis:\/data/],
    ["redis healthcheck uses ping", /redis-cli", "ping"/],
  ];
  for (const [label, pattern] of redisChecks) {
    if (!pattern.test(redisBlock)) failures.push(label);
  }
  if (/^\s{4}ports:/m.test(redisBlock)) failures.push("redis must not publish host ports");
  return failures;
}

export async function verifyComposeFile(filePath = path.join(repoRoot, "docker-compose.yml")) {
  const source = await readFile(filePath, "utf8");
  const failures = verifyComposeTopology(source);
  const sandboxOverlay = await readFile(path.join(repoRoot, "docker-compose.sandbox.yml"), "utf8");
  for (const [label, pattern] of sandboxOverlayChecks) {
    if (!pattern.test(sandboxOverlay)) failures.push(`sandbox overlay: ${label}`);
  }
  const sandboxDockerfile = await readFile(path.join(repoRoot, "deploy/openclaw/Dockerfile.sandbox"), "utf8");
  for (const [label, pattern] of sandboxDockerfileChecks) {
    if (!pattern.test(sandboxDockerfile)) failures.push(`sandbox Dockerfile: ${label}`);
  }
  const gatewayDockerfile = await readFile(path.join(repoRoot, "deploy/openclaw/Dockerfile.gateway"), "utf8");
  for (const [label, pattern] of gatewayDockerfileChecks) {
    if (!pattern.test(gatewayDockerfile)) failures.push(`gateway Dockerfile: ${label}`);
  }
  const sandboxRuntimeDockerfile = await readFile(path.join(repoRoot, "deploy/openclaw/Dockerfile.sandbox-runtime"), "utf8");
  for (const [label, pattern] of sandboxRuntimeDockerfileChecks) {
    if (!pattern.test(sandboxRuntimeDockerfile)) failures.push(`sandbox runtime Dockerfile: ${label}`);
  }
  const dockerfile = await readFile(path.join(repoRoot, "apps/control-plane/Dockerfile"), "utf8");
  for (const [label, pattern] of dockerfileChecks) {
    if (!pattern.test(dockerfile)) failures.push(label);
  }
  for (const [label, pattern] of dockerfileRejectChecks) {
    if (pattern.test(dockerfile)) failures.push(label);
  }
  return failures;
}

async function main() {
  const filePath = path.resolve(repoRoot, argValue("--file", "docker-compose.yml"));
  const failures = await verifyComposeFile(filePath);
  if (failures.length > 0) {
    process.stderr.write(`Compose topology check failed for ${filePath}:\n`);
    for (const failure of failures) process.stderr.write(`- ${failure}\n`);
    process.exit(1);
  }
  process.stdout.write(`Compose topology check passed for ${filePath}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
