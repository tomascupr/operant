#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outputPath = path.resolve(repoRoot, argValue("--output", process.env.OPERANT_FINAL_REPORT || ".operant/final-report.md"));
const composeReportPath = path.resolve(repoRoot, argValue("--compose-report", process.env.OPERANT_COMPOSE_E2E_REPORT || ".operant/compose-e2e-report.json"));
const composeAutoReportPath = path.resolve(
  repoRoot,
  argValue("--compose-auto-report", process.env.OPERANT_COMPOSE_E2E_AUTO_REPORT || ".operant/compose-e2e-auto-report.json"),
);
const composeSmokeReportPath = path.resolve(
  repoRoot,
  argValue("--compose-smoke-report", process.env.OPERANT_COMPOSE_SMOKE_REPORT || ".operant/compose-smoke-report.json"),
);
const sandboxSmokeReportPath = path.resolve(
  repoRoot,
  argValue("--sandbox-smoke-report", process.env.OPERANT_COMPOSE_SANDBOX_SMOKE_REPORT || ".operant/compose-sandbox-smoke-report.json"),
);
const localAcceptanceReportPath = path.resolve(
  repoRoot,
  argValue("--local-acceptance-report", process.env.OPERANT_LOCAL_ACCEPTANCE_REPORT || ".operant/local-acceptance-report.json"),
);
const slackDmProbeReportPath = path.resolve(
  repoRoot,
  argValue("--slack-dm-probe-report", process.env.OPERANT_SLACK_DM_PROBE_REPORT || ".operant/slack-dm-probe-report.json"),
);
function argValue(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index === -1) return fallback;
  return process.argv[index + 1] || fallback;
}

function runAudit() {
  const result = spawnSync("node", ["scripts/operant-completion-audit.mjs", "--json", "--allow-blocked"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  let audit;
  try {
    audit = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`completion audit JSON parse failed after exit ${result.status}: ${error.message}; ${result.stderr || result.stdout}`);
  }
  if (!audit || !audit.totals || !Array.isArray(audit.checks)) {
    throw new Error(`completion audit returned unexpected JSON after exit ${result.status}`);
  }
  audit.auditCommandStatus = result.status ?? 0;
  if (result.stderr) audit.auditCommandStderr = result.stderr.trim();
  return audit;
}

async function readJsonIfExists(file) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    return { error: error.message };
  }
}

function section(title) {
  return `\n## ${title}\n\n`;
}

function bullet(label, value) {
  return `- ${label}: ${value}\n`;
}

function checksByStatus(audit, status) {
  return audit.checks.filter((check) => check.status === status || (!check.ok && status === "fail" && check.status !== "blocked"));
}

function renderChecks(title, checks) {
  if (checks.length === 0) return `${section(title)}None.\n`;
  return `${section(title)}${checks.map((check) => `- [${check.group}] ${check.requirement}: ${check.evidence}`).join("\n")}\n`;
}

function renderLiveCompletionHandoff(audit, blocked, failed) {
  const lines = [section("Live Completion Handoff")];
  if (audit.complete) {
    lines.push("No completion blocker remains. Strict Slack DM, denied-policy, approval, and post-restart live evidence is retained as an optional customer-run proof for teams that want to attach fresh workspace evidence.\n\n");
  } else {
    lines.push("To clear the remaining live blockers, put real values in a private env file or shell. Do not commit these values.\n\n");
  }
  const gaps = [...failed, ...blocked];
  if (gaps.length > 0) {
    lines.push("Current gaps:\n");
    for (const check of gaps) {
      const status = check.status === "blocked" ? "BLOCKED" : "FAIL";
      lines.push(`- ${status} [${check.group}] ${check.requirement}: ${check.evidence}\n`);
    }
    lines.push("\n");
  }
  lines.push("Required private inputs:\n\n");
  lines.push("Template: `deploy/slack/live.env.example`\n\n");
  lines.push("```bash\n");
  lines.push("# Normally supplied by the generated Compose env passed with --env.\n");
  lines.push("# OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_...\n");
  lines.push("OPERANT_LIVE_ADMIN_SLACK_USER_ID=U...\n");
  lines.push("OPERANT_LIVE_SLACK_TEAM_ID=T... # optional team assertion\n");
  lines.push("SLACK_CHANNEL_ID=C...\n");
  lines.push("OPERANT_LIVE_BOT_USER_ID=U... # optional bot identity assertion\n");
  lines.push("SLACK_APP_TOKEN=<slack-app-token>\n");
  lines.push("SLACK_BOT_TOKEN=<slack-bot-token>\n");
  lines.push("SLACK_USER_TOKEN=<xoxp-or-xoxc-allowed-human-user-oauth-token>\n");
  lines.push("OPERANT_LIVE_DM_CHANNEL_ID=D...\n");
  lines.push("# Optional two-human denied-policy proof only:\n");
  lines.push("# OPERANT_LIVE_DENIED_USER_ID=U...\n");
  lines.push("# OPERANT_LIVE_DENIED_USER_TOKEN=<xoxp-or-xoxc-denied-human-user-oauth-token>\n");
  lines.push("# Manual human-post alternative to the allowed user-token line:\n");
  lines.push("# OPERANT_LIVE_MANUAL_SLACK_POSTS=1\n");
  lines.push("# OPERANT_LIVE_MANUAL_SLACK_NUDGE=1 # optional bot copy/paste reminders\n");
  lines.push("# OPERANT_LIVE_ALLOWED_USER_ID=U...\n");
  lines.push("# OPERANT_LIVE_DENIED_USE_ALLOWED_USER=1 # explicit one-human strict mode; default when no distinct denied user is configured\n");
  lines.push("OPENAI_API_KEY=<model-api-key>\n");
  lines.push("ANTHROPIC_API_KEY=<anthropic-model-api-key> # when MODEL_PROVIDER=anthropic\n");
  lines.push("OPERANT_LIVE_MODEL_PROVIDER=openai\n");
  lines.push("OPERANT_LIVE_MODEL_NAME=gpt-5\n");
  lines.push("OPERANT_LIVE_ALLOWED_DM_USER_IDS=U... # optional policy seed additions\n");
  lines.push("OPERANT_LIVE_ALLOWED_CHANNEL_IDS=C... # optional policy seed additions\n");
  lines.push("OPERANT_LIVE_APPROVER_SLACK_USER_IDS=U... # optional policy seed additions\n");
  lines.push("OPERANT_LIVE_APPROVAL_PROMPT='Use the exec tool to run exactly: echo operant-approval'\n");
  lines.push("OPERANT_LIVE_INTEGRATION_CREDENTIALS=github/api-token=GITHUB_TOKEN # optional integration seed checks\n");
  lines.push("OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON='[{\"kind\":\"linear\",\"key\":\"api-token\",\"label\":\"Linear API token\",\"secretValueEnv\":\"LINEAR_API_KEY\"}]' # optional structured integration seed checks\n");
  lines.push("```\n\n");
  lines.push("Accepted aliases include `OPERANT_LIVE_SLACK_CHANNEL_ID`, `OPERANT_LIVE_SLACK_APP_TOKEN`, `OPERANT_LIVE_SLACK_BOT_TOKEN`, `OPERANT_LIVE_SLACK_USER_TOKEN`, `OPERANT_LIVE_MODEL_API_KEY`, `MODEL_API_KEY`, and `ANTHROPIC_API_KEY`.\n\n");
  lines.push("The Slack app-level token is separate from the bot token because Slack `apps.connections.open` requires an app-level token with `connections:write` and returns the temporary Socket Mode WebSocket URL. OpenClaw uses that Socket Mode connection for Slack events and interactive payloads; the bot token can read/post as the bot but cannot replace the app-level token for ingress.\n\n");
  lines.push("Before debugging OpenClaw, isolate Slack delivery with `pnpm slack:socket-probe -- --env .env.acme.live --manual-user-id U... --nudge` or the equivalent private env file. If Slack returns `[WARN] Socket Mode is not turned on.`, enable Socket Mode for the same Slack app ID as the bot token, save the app, and reinstall or re-authorize it. If the probe receives `hello` but no human mention event, repair Event Subscriptions or the app install before running strict Compose E2E.\n\n");
  lines.push("If public-channel mentions work but DM acceptance is still blocked, isolate the allowed-user DM with `pnpm slack:dm-probe -- --env .env.acme --live-env .env.acme.live --manual-user-id U... --nudge`. The probe writes `.operant/slack-dm-probe-report.json`, verifies the configured DM via Slack `conversations.open`, and confirms whether the bot can read human messages there before the long strict Compose run.\n\n");
  lines.push("If Slack says bot DMs are not enabled, verify the installed app manifest with `pnpm slack:manifest-probe -- --env .env.acme.live` after adding `SLACK_CONFIG_TOKEN` with `app_configurations:read`. App/bot tokens cannot export manifests. The probe checks Socket Mode, writable App Home Messages, required bot events, and minimum bot scopes, then writes `.operant/slack-manifest-probe-report.json`.\n\n");
  lines.push("The optional identity assertions are checked against Slack `auth.test`; the optional policy seed variables are asserted in the generated OpenClaw Slack config; strict Compose always retains the admin Slack user as an approval approver and adds any `OPERANT_LIVE_APPROVER_SLACK_USER_IDS` values; integration credential entries are saved through `/api/integrations/credentials`, checked for metadata-only responses, and resolved through the internal SecretRef endpoint when `OPERANT_INTERNAL_TOKEN` is available. JSON integration credential seeds accept `secretValueEnv` or `secretValue`; prefer `secretValueEnv`, and generated reports redact both referenced env values and inline JSON secret values before writing evidence.\n\n");
  lines.push("Temporary user tokens must be human user tokens, not the bot token. They are human user OAuth tokens, typically starting with `xoxp-` or `xoxc-`; they must not be Slack user IDs such as `U...`, bot tokens such as `xoxb-...`, or placeholder template values. The Slack app manifest declares the verifier's User Token Scope `chat:write`; if the app was configured manually, add that scope before authorizing user tokens. The verifier uses the allowed token for `auth.test` and `chat.postMessage` in the test channel and the existing DM configured as `OPERANT_LIVE_DM_CHANNEL_ID`, which must be the bot DM for that same allowed human user. If a user-token probe shows Slack stores those posts with `bot_id` or `app_id`, strict acceptance must use manual mode with real Slack-client human messages; Slack may display a human name while still making the message app-authored, and OpenClaw ignores that shape to avoid bot loops. If the allowed user is not the admin user, replace any admin-bot DM ID with the allowed-user-to-bot DM ID. The denied-policy proof is one-human by default: the verifier temporarily denies the allowed test user, proves no Slack reply, then restores policy before the approval probe. A distinct denied-user token or ID is optional for two-human testing only. The bot token must be the installed Slack app bot token; live preflight and live E2E require its `auth.test` identity to include `bot_id`, then use it for `conversations.info`, `conversations.members`, and `conversations.replies` checks for the configured channel, DM, membership, and threads.\n\n");
  lines.push("Use `pnpm slack:user-token -- --env .env.acme.live --target SLACK_USER_TOKEN --callback-url '<callback-url>'` for the allowed human token. Add `--denied` only when you intentionally want the optional two-human denied-policy proof. The helper reads `SLACK_CLIENT_ID` and `SLACK_CLIENT_SECRET`, exchanges the Slack OAuth code, verifies the returned access token with `auth.test`, and saves the selected env var without printing token values.\n\n");
  lines.push("After saving the allowed user token, run `pnpm slack:user-token-probe -- --env .env.acme --live-env .env.acme.live`. The probe posts one diagnostic message, reads it back with the bot token, deletes it by default, and writes `.operant/slack-user-token-post-probe-report.json`. If it reports app-authored output, use manual mode for strict live acceptance because OpenClaw ignores bot/app-authored Slack messages to prevent loops.\n\n");
  lines.push("Manual mode can use `OPERANT_LIVE_MANUAL_SLACK_NUDGE=1` or `--manual-slack-nudge` to make the bot post copy/paste reminders in Slack. Those reminders are operator guidance only; strict acceptance still waits for messages authored by the configured human Slack users. The manual `pnpm live:e2e:manual` and `pnpm compose:e2e:manual` aliases set fifteen-minute waits for human Slack posts and approval completion; if you override them with a shorter `--timeout-ms`, post before the Slack prompt expiry because later messages are intentionally ignored.\n\n");
  lines.push("The denied-policy proof is a Slack admission-policy check: a channel member denied by Operant policy should receive no Operant thread reply. It is separate from control-plane RBAC and from tool policies, which can allow, deny, or require approval for specific tool/action pairs after a Slack request is admitted. The default proof is one-human temporary deny. For an optional colleague-backed proof, ask the colleague to join the test channel, copy their Slack member ID, and type only the denied-user prompt when the verifier prints it. Set `OPERANT_LIVE_DENIED_USER_ID=U_COLLEAGUE_ID` or pass `--denied-user-id U_COLLEAGUE_ID`. The colleague's message must be a normal top-level Slack-client message; the correct outcome is no Operant thread reply, proving policy suppression rather than channel membership failure.\n\n");
  lines.push("The strict audit only accepts `.operant/live-e2e-report.json` and `.operant/live-e2e-post-restart-report.json` when each report includes result-level Slack identity evidence: `result.channelId` and `result.slackTeamId` must match the top-level report channel/team, and `result.botUserId` must match the top-level bot identity. Each report must also include `result.channelMembership.method=\"conversations.members\"`, a `channelMembership.channelId` matching the report's Slack channel, and `channelMembership.requiredUserIds` containing the allowed test-user Slack ID plus either the distinct denied test-user Slack ID or the same allowed user when `result.deniedProbe.mode=\"same-user-temporary-deny\"`.\n\n");
  lines.push("If strict OpenClaw operator checks report `pairing required` or `device is not approved`, review `openclaw devices list`, approve the exact request ID with `openclaw devices approve <requestId>`, and rerun live acceptance. Do not use `openclaw devices approve --latest` as the final approval step; expected scopes include `operator.read`, `operator.approvals`, and `operator.talk.secrets`, and `operator.admin` satisfies them.\n\n");
  lines.push("Strict completion sequence:\n\n");
  lines.push("```bash\n");
  lines.push("# Optional when live values are merged into the Compose env:\n");
  lines.push("pnpm live:preflight -- --env .env.acme\n");
  lines.push("\n");
  lines.push("# Preferred private live-env overlay flow:\n");
  lines.push("pnpm slack:socket-probe -- --env .env.acme.live --manual-user-id U... --nudge\n");
  lines.push("pnpm slack:manifest-probe -- --env .env.acme.live\n");
  lines.push("pnpm slack:user-token-probe -- --env .env.acme --live-env .env.acme.live\n");
  lines.push("pnpm slack:dm-probe -- --env .env.acme --live-env .env.acme.live --manual-user-id U... --nudge\n");
  lines.push("OPERANT_LIVE_MANUAL_SLACK_POSTS=0 OPERANT_LIVE_MANUAL_SLACK_NUDGE=0 pnpm compose:e2e -- --env .env.acme --live-env .env.acme.live --report .operant/compose-e2e-auto-report.json --allow-blocked --down --down-volumes\n");
  lines.push("pnpm live:preflight -- --env .env.acme --live-env .env.acme.live\n");
  lines.push("pnpm live:e2e -- --env .env.acme --live-env .env.acme.live --require-operant-records --require-dm --require-denied-user --require-slack-approval --require-slack-approval-completion\n");
  lines.push("\n");
  lines.push("# Optional when live values are merged into the Compose env:\n");
  lines.push("pnpm compose:e2e -- --env .env.acme\n");
  lines.push("\n");
  lines.push("# Preferred private live-env overlay flow:\n");
  lines.push("pnpm compose:e2e -- --env .env.acme --live-env .env.acme.live\n");
  lines.push("pnpm audit:completion\n");
  lines.push("pnpm report:final\n");
  lines.push("```\n\n");
  lines.push("The default completion audit treats this strict live sequence as optional and documented. To make it mandatory for a customer acceptance run, set `OPERANT_REQUIRE_STRICT_LIVE=1` and run `pnpm audit:completion` after the strict Compose report is refreshed. Use `--allow-blocked` only for local evidence collection before live credentials are available.\n");
  lines.push("\nCurrent local handoff bundle:\n");
  lines.push("- `.operant/live-acceptance.env` is a private placeholder overlay for real Slack app/workspace/model credentials.\n");
  lines.push("- `.operant/live-acceptance-handoff.md` lists the exact accepted live env aliases and expected helper progression.\n");
  lines.push("- `.operant/verify-handoff.sh` validates the placeholder bundle before real tokens are added.\n");
  lines.push(
    "- `.operant/run-live-acceptance.sh --preflight-only` reports process-env live/model override names and placeholder state only, never values, and validates live inputs before Docker reachability.\n",
  );
  lines.push("- Root aliases are backed by tracked helper code and are available as `pnpm handoff:readiness`, `pnpm handoff:verify`, `pnpm live:acceptance:preflight`, and `pnpm live:acceptance`; when the local `.operant` helper bundle exists, they delegate to it.\n");
  return lines.join("");
}

function renderSlackDmProbeReport(report) {
  const lines = [section("Slack DM Probe Evidence")];
  lines.push(bullet("Report", path.relative(repoRoot, slackDmProbeReportPath)));
  if (report.error) {
    lines.push(`Missing or unreadable: ${report.error}\n`);
    lines.push("Run `pnpm slack:dm-probe -- --env .env.acme --live-env .env.acme.live --manual-user-id U... --nudge` to refresh this artifact.\n");
    return lines.join("");
  }
  lines.push(bullet("Generated", report.generatedAt || "unknown"));
  lines.push(bullet("Passed", report.ok === true ? "yes" : "no"));
  lines.push(bullet("Bot user", report.botUserId || "unknown"));
  lines.push(bullet("Manual user", report.manualUserId || "unknown"));
  lines.push(bullet("DM channel", report.dmChannelId || "unknown"));
  lines.push(bullet("Observed messages", Number.isFinite(Number(report.observedMessages)) ? Number(report.observedMessages) : "unknown"));
  lines.push(bullet("Nudge posted", report.nudge?.ts ? `yes (${report.nudge.ts})` : "no"));
  if (report.matchedTs) lines.push(bullet("Matched DM timestamp", report.matchedTs));
  if (report.error) lines.push(bullet("Error", report.error));
  lines.push("This targeted probe verifies the configured bot DM belongs to the expected allowed human with Slack `conversations.open`, then waits for a human-authored exact DM message. It does not replace the strict Compose E2E gate.\n");
  return lines.join("");
}

function renderAuditChecklist(audit) {
  const lines = [section("Audit Checklist")];
  for (const check of audit.checks) {
    const marker = check.ok ? "PASS" : check.status === "blocked" ? "BLOCKED" : "FAIL";
    lines.push(`- ${marker} [${check.group}] ${check.requirement}: ${check.evidence}\n`);
  }
  return lines.join("");
}

function renderObjectiveSuccessCriteria(audit) {
  const lines = [section("Objective Success Criteria Matrix")];
  const groups = new Map();
  for (const check of audit.checks) {
    if (!groups.has(check.group)) groups.set(check.group, { pass: 0, fail: 0, blocked: 0 });
    const g = groups.get(check.group);
    if (check.ok) g.pass += 1;
    else if (check.status === "blocked") g.blocked += 1;
    else g.fail += 1;
  }
  for (const [group, totals] of groups) {
    lines.push(bullet(group, `${totals.pass} passed, ${totals.fail} failed, ${totals.blocked} blocked`));
  }
  lines.push("\n");
  return lines.join("");
}

function renderComposeReport(report) {
  if (report.error) {
    return `${section("Compose E2E Evidence")}Missing or unreadable: ${report.error}\n`;
  }
  const lines = [section("Compose E2E Evidence")];
  lines.push(bullet("Report", path.relative(repoRoot, composeReportPath)));
  lines.push(bullet("Generated", report.generatedAt || "unknown"));
  if (report.envPath) lines.push(bullet("Compose env", path.relative(repoRoot, path.resolve(repoRoot, report.envPath))));
  if (report.liveEnvPath) lines.push(bullet("Live env", path.relative(repoRoot, path.resolve(repoRoot, report.liveEnvPath))));
  lines.push(bullet("Strict final gate", report.strictFinalGate === true ? "yes" : "no"));
  lines.push(bullet("Ready for completion audit", report.readyForCompletionAudit === true ? "yes" : "no"));
  lines.push(bullet("Passed", report.passed === true ? "yes" : "no"));
  if (report.runtime) {
    lines.push(bullet("Runtime", `${report.runtime.node || "unknown"} ${report.runtime.platform || "unknown"}/${report.runtime.arch || "unknown"}`));
  }
  if (report.totals) {
    lines.push(bullet("Step totals", `${report.totals.passed || 0} passed, ${report.totals.skipped || 0} skipped, ${report.totals.blocked || 0} blocked, ${report.totals.failed || 0} failed`));
  }
  if (report.liveReports) {
    lines.push("\nLive Slack/OpenClaw reports:\n");
    for (const [label, descriptor] of Object.entries(report.liveReports)) {
      const parts = [
        descriptor?.path || "missing",
        descriptor?.required ? "required" : "optional",
      ];
      if (descriptor?.generatedAt) parts.push(`generatedAt=${descriptor.generatedAt}`);
      if (descriptor?.sha256) parts.push(`sha256=${descriptor.sha256}`);
      lines.push(`- ${label}: ${parts.join("; ")}\n`);
    }
  }
  if (Array.isArray(report.missingRequiredSteps) && report.missingRequiredSteps.length > 0) {
    lines.push("\nMissing required strict-gate steps:\n");
    for (const step of report.missingRequiredSteps) lines.push(`- ${step}\n`);
  }
  if (Array.isArray(report.evidenceInputs) && report.evidenceInputs.length > 0) {
    lines.push("\nEvidence input fingerprints:\n");
    for (const input of report.evidenceInputs) lines.push(`- ${input.file}: ${input.sha256}\n`);
  }
  return lines.join("");
}

function renderComposeAutoReport(report) {
  const lines = [section("Automated Slack User-Token Probe Evidence")];
  lines.push(bullet("Report", path.relative(repoRoot, composeAutoReportPath)));
  if (report.error) {
    lines.push(`Automated strict probe not available: ${report.error}\n`);
    lines.push("Run `OPERANT_LIVE_MANUAL_SLACK_POSTS=0 OPERANT_LIVE_MANUAL_SLACK_NUDGE=0 pnpm compose:e2e -- --env .env.acme --live-env .env.acme.live --report .operant/compose-e2e-auto-report.json --allow-blocked --down --down-volumes` to refresh this artifact without overwriting the manual strict report.\n");
    return lines.join("");
  }
  lines.push(bullet("Generated", report.generatedAt || "unknown"));
  if (report.envPath) lines.push(bullet("Compose env", path.relative(repoRoot, path.resolve(repoRoot, report.envPath))));
  if (report.liveEnvPath) lines.push(bullet("Live env", path.relative(repoRoot, path.resolve(repoRoot, report.liveEnvPath))));
  lines.push(bullet("Manual Slack mode", report.options?.manualSlackPosts === true ? "yes" : "no"));
  lines.push(bullet("Passed", report.passed === true ? "yes" : "no"));
  if (report.totals) {
    lines.push(bullet("Step totals", `${report.totals.passed || 0} passed, ${report.totals.skipped || 0} skipped, ${report.totals.blocked || 0} blocked, ${report.totals.failed || 0} failed`));
  }
  const blockedSteps = Array.isArray(report.steps) ? report.steps.filter((step) => step.status === "blocked") : [];
  if (blockedSteps.length > 0) {
    lines.push("\nBlocked automated probe steps:\n");
    for (const step of blockedSteps) lines.push(`- ${step.name}: ${step.detail || "blocked"}\n`);
  }
  lines.push("This non-gating probe is useful when the manual strict report is blocked. It forces automated Slack posting mode and shows whether temporary allowed/denied human Slack user tokens are present before a full strict run. It is not accepted as a substitute for `.operant/compose-e2e-report.json`.\n");
  return lines.join("");
}

function renderComposeSmokeReport(report) {
  const lines = [section("Non-Live Compose Smoke Evidence")];
  lines.push(bullet("Report", path.relative(repoRoot, composeSmokeReportPath)));
  if (report.error) {
    lines.push(`Base non-live Compose smoke not available: ${report.error}\n`);
    lines.push("Run `pnpm compose:smoke -- --env .env.acme --profile queue --down --down-volumes` to refresh this artifact.\n");
    return lines.join("");
  }
  lines.push(bullet("Generated", report.generatedAt || "unknown"));
  const smokePassed = report.smokePassed ?? report.runtimePassed ?? (report.totals && Number(report.totals.failed || 0) === 0 && Number(report.totals.blocked || 0) === 0);
  lines.push(bullet("Smoke passed", smokePassed ? "yes" : "no"));
  if (report.totals) {
    lines.push(bullet("Step totals", `${report.totals.passed || 0} passed, ${report.totals.skipped || 0} skipped, ${report.totals.blocked || 0} blocked, ${report.totals.failed || 0} failed`));
  }
  if (Array.isArray(report.composeFiles) && report.composeFiles.length > 0) {
    lines.push(bullet("Compose files", report.composeFiles.join(", ")));
  }
  const config = Array.isArray(report.steps) ? report.steps.find((step) => step.name === "credential/config verification") : null;
  const status = Array.isArray(report.steps) ? report.steps.find((step) => step.name === "OpenClaw status") : null;
  const primaryModel = config?.evidence?.primaryModel;
  const sessionDefaultModel = status?.evidence?.sessionDefaultModel;
  if (primaryModel || sessionDefaultModel) {
    lines.push(bullet("Model evidence", `primary ${primaryModel || "unknown"}; session default ${sessionDefaultModel || "unknown"}`));
  }
  const doctor = Array.isArray(report.steps) ? report.steps.find((step) => step.name === "OpenClaw doctor") : null;
  if (doctor) lines.push(bullet("OpenClaw doctor", `${doctor.status}${doctor.detail ? `; ${doctor.detail}` : ""}`));
  lines.push("This artifact skips live Slack by design but exercises Compose startup, restart, SecretRefs, model handoff, OpenClaw status/security/doctor, deployed control-plane OpenClaw check routes, paired-gateway skip evidence for secrets/usage operations, and optional Redis when the queue profile is enabled.\n");
  return lines.join("");
}

function renderSandboxSmokeReport(report) {
  const lines = [section("Sandbox Compose Smoke Evidence")];
  lines.push(bullet("Report", path.relative(repoRoot, sandboxSmokeReportPath)));
  if (report.error) {
    lines.push(`Optional Docker-socket sandbox smoke not available: ${report.error}\n`);
    lines.push("Run `pnpm compose:smoke:sandbox -- --env .env.acme` on a dedicated single-trust-boundary Docker host to refresh this artifact.\n");
    return lines.join("");
  }
  lines.push(bullet("Generated", report.generatedAt || "unknown"));
  const smokePassed = report.smokePassed ?? report.runtimePassed ?? (report.totals && Number(report.totals.failed || 0) === 0 && Number(report.totals.blocked || 0) === 0);
  lines.push(bullet("Smoke passed", smokePassed ? "yes" : "no"));
  if (report.totals) {
    lines.push(bullet("Step totals", `${report.totals.passed || 0} passed, ${report.totals.skipped || 0} skipped, ${report.totals.blocked || 0} blocked, ${report.totals.failed || 0} failed`));
  }
  if (Array.isArray(report.composeFiles) && report.composeFiles.length > 0) {
    lines.push(bullet("Compose files", report.composeFiles.join(", ")));
  }
  const doctor = Array.isArray(report.steps) ? report.steps.find((step) => step.name === "OpenClaw doctor") : null;
  if (doctor) lines.push(bullet("OpenClaw doctor", `${doctor.status}${doctor.detail ? `; ${doctor.detail}` : ""}`));
  lines.push("This artifact is opt-in because it mounts the Docker socket into the OpenClaw gateway.\n");
  return lines.join("");
}

function renderLocalAcceptanceReport(report) {
  if (report.error) {
    return `${section("Local Acceptance Evidence")}Missing or unreadable: ${report.error}\n`;
  }
  const lines = [section("Local Acceptance Evidence")];
  lines.push(bullet("Report", path.relative(repoRoot, localAcceptanceReportPath)));
  lines.push(bullet("Generated", report.generatedAt || "unknown"));
  lines.push(bullet("Local acceptance complete", report.localComplete === true ? "yes" : "no"));
  lines.push(bullet("Objective complete", report.objectiveComplete === true ? "yes" : "no"));
  if (report.totals) {
    lines.push(bullet("Step totals", `${report.totals.passed || 0} passed, ${report.totals.blocked || 0} blocked, ${report.totals.failed || 0} failed`));
  }
  if (report.completionAudit?.totals) {
    lines.push(bullet(
      "Completion audit",
      `${report.completionAudit.totals.passed}/${report.completionAudit.totals.checks} passed, ${report.completionAudit.totals.blocked} blocked, ${report.completionAudit.totals.failed} failed`,
    ));
  }
  if (report.finalReportArtifact) {
    lines.push(bullet("Final report artifact", `${report.finalReportArtifact.status}${report.finalReportArtifact.missing?.length ? `; missing ${report.finalReportArtifact.missing.join(", ")}` : ""}`));
  }
  if (Array.isArray(report.completionAudit?.blocked) && report.completionAudit.blocked.length > 0) {
    lines.push("\nCompletion-audit blockers:\n");
    for (const check of report.completionAudit.blocked) {
      lines.push(`- [${check.group}] ${check.requirement}: ${check.evidence}\n`);
    }
  }
  if (Array.isArray(report.steps) && report.steps.length > 0) {
    lines.push("\nSteps:\n");
    for (const step of report.steps) {
      lines.push(`- ${step.status.toUpperCase()} ${step.name} (${step.durationMs}ms): ${step.command.join(" ")}\n`);
    }
  }
  return lines.join("");
}

function renderCommands() {
  return `${section("Commands")}` +
    "Local/static acceptance without live Slack credentials. Docker is required for the Compose portions:\n\n" +
    "```bash\n" +
    "pnpm acceptance:local\n" +
    "pnpm acceptance:local -- --include-sandbox\n" +
    "```\n\n" +
    "Individual local/static checks:\n\n" +
    "```bash\n" +
    "pnpm verify\n" +
    "pnpm smoke:local\n" +
    "pnpm doctor -- --preflight-only\n" +
    "pnpm audit:completion -- --allow-blocked\n" +
    "```\n\n" +
    "Non-live Compose runtime smoke before Slack credentials:\n\n" +
    "```bash\n" +
    "pnpm compose:smoke\n" +
    "pnpm compose:smoke -- --profile queue\n" +
    "pnpm compose:smoke:sandbox -- --env .env.acme\n" +
    "pnpm compose:config -- --env .env.acme\n" +
    "pnpm compose:up -- --env .env.acme -d\n" +
    "pnpm compose:config -- --env .env.acme --file docker-compose.sandbox.yml\n" +
    "pnpm compose:up -- --env .env.acme --file docker-compose.sandbox.yml -d\n" +
    "pnpm compose:smoke -- --env .env.acme --file docker-compose.sandbox.yml --profile queue\n" +
    "```\n\n" +
    "Persistent live bot from a private live-env overlay:\n\n" +
    "```bash\n" +
    "pnpm compose:live -- --env .env.acme --live-env .env.acme.live\n" +
    "# Without a temporary Slack user token:\n" +
    "pnpm compose:live -- --env .env.acme --live-env .env.acme.live --manual-slack-posts --manual-user-id U...\n" +
    "```\n\n" +
    "Strict customer acceptance with Docker and live Slack/model credentials:\n\n" +
    "```bash\n" +
    "# Optional when live values are merged into the Compose env:\n" +
    "pnpm live:preflight -- --env .env.acme\n" +
    "\n" +
    "# Preferred private live-env overlay flow:\n" +
    "pnpm slack:user-token-probe -- --env .env.acme --live-env .env.acme.live\n" +
    "pnpm slack:dm-probe -- --env .env.acme --live-env .env.acme.live --manual-user-id U... --nudge\n" +
    "OPERANT_LIVE_MANUAL_SLACK_POSTS=0 OPERANT_LIVE_MANUAL_SLACK_NUDGE=0 pnpm compose:e2e -- --env .env.acme --live-env .env.acme.live --report .operant/compose-e2e-auto-report.json --allow-blocked --down --down-volumes\n" +
    "pnpm live:preflight -- --env .env.acme --live-env .env.acme.live\n" +
    "pnpm live:e2e -- --env .env.acme --live-env .env.acme.live --require-operant-records --require-dm --require-denied-user --require-slack-approval --require-slack-approval-completion\n" +
    "pnpm compose:e2e -- --env .env.acme --live-env .env.acme.live\n" +
    "OPERANT_REQUIRE_STRICT_LIVE=1 pnpm audit:completion\n" +
    "\n" +
    "# Shell-export alternative when not using --live-env:\n" +
    "export OPERANT_LIVE_ADMIN_SLACK_USER_ID=U...\n" +
    "# Normally supplied by the generated Compose env passed with --env.\n" +
    "# Export only when intentionally overriding that Compose env.\n" +
    "# export OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_...\n" +
    "export SLACK_CHANNEL_ID=C...\n" +
    "export SLACK_APP_TOKEN=<slack-app-token>\n" +
    "export SLACK_BOT_TOKEN=<slack-bot-token>\n" +
    "export SLACK_USER_TOKEN=<xoxp-or-xoxc-allowed-human-user-oauth-token>\n" +
    "export OPERANT_LIVE_DM_CHANNEL_ID=D...\n" +
    "# Optional two-human proof: export OPERANT_LIVE_DENIED_USER_TOKEN=<xoxp-or-xoxc-denied-human-user-oauth-token>\n" +
    "# Manual alternative: export OPERANT_LIVE_MANUAL_SLACK_POSTS=1 and optionally OPERANT_LIVE_MANUAL_SLACK_NUDGE=1 instead of the allowed user token.\n" +
    "# One-human denied-policy proof is the default when no denied-user token/ID is configured.\n" +
    "export OPENAI_API_KEY=<model-api-key>\n" +
    "pnpm compose:e2e -- --env .env.acme\n" +
    "OPERANT_REQUIRE_STRICT_LIVE=1 pnpm audit:completion\n" +
    "```\n\n" +
    "Model aliases are `OPERANT_LIVE_MODEL_API_KEY`, `MODEL_API_KEY`, `OPENAI_API_KEY`, or `ANTHROPIC_API_KEY`; provider-specific keys must match `OPERANT_LIVE_MODEL_PROVIDER`/`MODEL_PROVIDER`.\n\n" +
    "`pnpm compose:e2e` runs `pnpm live:preflight` before starting containers in strict live mode. The preflight verifies the Slack app-level token with `apps.connections.open`, checks Slack token identity and optional Slack team consistency with `auth.test`, rejects a non-bot token in the bot-token slot by requiring `bot_id`, verifies the bot can read the configured channel and DM with `conversations.info`, confirms allowed/denied target-channel membership with `conversations.members`, and checks OpenAI/Anthropic model-key authentication with the selected provider's read-only `/models` endpoint before the full E2E posts messages.\n\n" +
    "Strict Compose also writes sanitized Slack/OpenClaw probe evidence to `.operant/live-e2e-report.json` and `.operant/live-e2e-post-restart-report.json`, archives previous JSON reports under `.operant/report-archive/` before overwriting them, and waits for a human Slack approval click-through before accepting the approval-required path. The default completion audit documents this strict live report as optional; `OPERANT_REQUIRE_STRICT_LIVE=1` makes it mandatory for a customer acceptance run.\n";
}

async function main() {
  const audit = runAudit();
  const composeReport = await readJsonIfExists(composeReportPath);
  const composeAutoReport = await readJsonIfExists(composeAutoReportPath);
  const composeSmokeReport = await readJsonIfExists(composeSmokeReportPath);
  const sandboxSmokeReport = await readJsonIfExists(sandboxSmokeReportPath);
  const localAcceptanceReport = await readJsonIfExists(localAcceptanceReportPath);
  const slackDmProbeReport = await readJsonIfExists(slackDmProbeReportPath);
  const blocked = checksByStatus(audit, "blocked");
  const failed = checksByStatus(audit, "fail");
  const passed = audit.checks.filter((check) => check.ok);

  const lines = [
    "# Operant Final Verification Report\n\n",
    `Generated: ${new Date().toISOString()}\n\n`,
    `Objective: ${audit.objective}\n\n`,
    "## Decision\n\n",
    audit.complete
      ? "Complete: all completion-audit checks passed and no blockers remain.\n"
      : `Not complete: ${failed.length} failed and ${blocked.length} blocked completion-audit checks remain.\n`,
    section("Audit Summary"),
    bullet("Checks", `${audit.totals.passed}/${audit.totals.checks} passed`),
    bullet("Failed", audit.totals.failed),
    bullet("Blocked", audit.totals.blocked),
    renderChecks("Blocked Requirements", blocked),
    renderChecks("Failed Requirements", failed),
    renderLiveCompletionHandoff(audit, blocked, failed),
    renderSlackDmProbeReport(slackDmProbeReport),
    renderObjectiveSuccessCriteria(audit),
    renderLocalAcceptanceReport(localAcceptanceReport),
    renderComposeReport(composeReport),
    renderComposeAutoReport(composeAutoReport),
    renderComposeSmokeReport(composeSmokeReport),
    renderSandboxSmokeReport(sandboxSmokeReport),
    renderCommands(),
    renderAuditChecklist(audit),
    section("Passed Coverage"),
    passed.map((check) => `- [${check.group}] ${check.requirement}`).join("\n"),
    "\n",
  ];

  await mkdir(path.dirname(outputPath), { recursive: true });
  await writeFile(outputPath, lines.join(""));
  process.stdout.write(`Final report written to ${outputPath}\n`);
}

await main();
