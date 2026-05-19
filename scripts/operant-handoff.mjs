#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(scriptPath), "..");
const command = process.argv[2] || "";
const rawArgs = process.argv.slice(3).filter((arg) => arg !== "--");
const forceFreshCheckout = enabled(process.env.OPERANT_HANDOFF_FORCE_FRESH_CHECKOUT);

function usage() {
  console.log(`Usage: operant-handoff <readiness|verify|live-acceptance> [options]

Options for live-acceptance:
  --preflight-only             Run live preflight and Docker reachability checks only
  --env <path>                 Compose env file (default: OPERANT_COMPOSE_ENV or .operant/local-acceptance.env)
  --live-env <path>            Private live Slack/model overlay (default: OPERANT_LIVE_ENV or .operant/live-acceptance.env)
  --manual-slack-posts         Wait for human-posted Slack probes instead of verifier user tokens
  --manual-slack-nudge         In manual mode, ask the bot to post copy/paste prompts for humans
  --manual-user-id <id>        Allowed human Slack user ID for manual probes
  --denied-use-allowed-user    Temporarily deny the allowed user for one-human denied-policy probes
  --help, -h                   Show this help
`);
}

function localPath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function run(executable, args) {
  const result = spawnSync(executable, args, {
    cwd: repoRoot,
    env: process.env,
    stdio: "inherit",
  });
  process.exit(result.status ?? 1);
}

function enabled(value) {
  return value === "1" || /^true$/i.test(value || "");
}

function envFileEnables(envPath, name) {
  try {
    const body = readFileSync(path.resolve(repoRoot, envPath), "utf8");
    return new RegExp(`^${name}=(?:1|true)$`, "im").test(body);
  } catch {
    return false;
  }
}

function printFreshCheckoutHandoff() {
  console.log(`Operant live acceptance handoff

Generated .operant handoff helpers are not present in this checkout. Use the
tracked commands below, or run pnpm acceptance:local to refresh the local
.operant evidence bundle.

Fresh-checkout private-env path:

  pnpm init:env -- --output .operant/local-acceptance.env --force
  cp deploy/slack/live.env.example .operant/live-acceptance.env
  # Fill .operant/live-acceptance.env with real Slack/model values.
  pnpm live:preflight -- --env .operant/local-acceptance.env --live-env .operant/live-acceptance.env
  pnpm compose:e2e -- --env .operant/local-acceptance.env --live-env .operant/live-acceptance.env

Use OPERANT_COMPOSE_ENV and OPERANT_LIVE_ENV to point the live-acceptance alias
at different private env files.`);
}

function handleReadiness() {
  const helper = ".operant/print-readiness.mjs";
  if (!forceFreshCheckout && existsSync(localPath(helper))) {
    run(helper, rawArgs);
  }
  printFreshCheckoutHandoff();
}

function handleVerify() {
  const helper = ".operant/verify-handoff.sh";
  if (!forceFreshCheckout && existsSync(localPath(helper))) {
    const result = spawnSync(localPath(helper), rawArgs, {
      cwd: repoRoot,
      env: process.env,
      encoding: "utf8",
    });
    const output = `${result.stdout || ""}${result.stderr || ""}`;
    const status = result.status ?? 1;
    if (status === 0) {
      if (result.stdout) process.stdout.write(result.stdout);
      if (result.stderr) process.stderr.write(result.stderr);
      process.exit(0);
    }
    if (!isStaleHandoffReportSnapshot(output)) {
      if (result.stdout) process.stdout.write(result.stdout);
      if (result.stderr) process.stderr.write(result.stderr);
      process.exit(status);
    }

    console.error("Generated handoff bundle has stale live-report snapshot fields; running dynamic tracked verification.");
    process.exit(runDynamicHandoffVerify());
  }
  printFreshCheckoutHandoff();
  console.error("\nNo generated .operant handoff bundle is available to verify.");
  process.exit(1);
}

function isStaleHandoffReportSnapshot(output) {
  return (
    /\.operant\/live-e2e[^ \n]*\.json exists=(?:true|false) !== readiness (?:true|false)/.test(output) ||
    /unexpected live E2E artifacts:/.test(output)
  );
}

function runCheck(label, executable, args, options = {}) {
  const result = spawnSync(executable, args, {
    cwd: repoRoot,
    env: options.env || process.env,
    encoding: "utf8",
    timeout: options.timeout || undefined,
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  const status = result.status ?? 1;
  if (status !== 0) {
    console.error(`${label} failed with exit ${status}`);
    return false;
  }
  return true;
}

function readJson(relativePath) {
  return JSON.parse(readFileSync(localPath(relativePath), "utf8"));
}

function runDynamicHandoffVerify() {
  const requiredFiles = [
    ".operant/live-acceptance-readiness.json",
    ".operant/live-acceptance.env",
    ".operant/local-acceptance.env",
    ".operant/run-live-acceptance.sh",
    ".operant/verify-handoff.sh",
    ".operant/print-readiness.mjs",
  ];
  for (const file of requiredFiles) {
    if (!existsSync(localPath(file))) {
      console.error(`Missing generated handoff file: ${file}`);
      return 1;
    }
  }

  console.log("== dynamic helper syntax check ==");
  if (!runCheck("run-live-acceptance syntax", "bash", ["-n", ".operant/run-live-acceptance.sh"])) return 1;
  if (!runCheck("verify-handoff syntax", "bash", ["-n", ".operant/verify-handoff.sh"])) return 1;
  if (!runCheck("print-readiness syntax", process.execPath, ["--check", ".operant/print-readiness.mjs"])) return 1;
  console.log("dynamic helper syntax ok");

  console.log("== dynamic file modes ==");
  const readiness = readJson(".operant/live-acceptance-readiness.json");
  const expectedFileModes = readiness.privateInputs?.expectedFileModes || {};
  for (const [file, expected] of Object.entries(expectedFileModes)) {
    const actual = (statSync(localPath(file)).mode & 0o777).toString(8);
    console.log(`${actual} ${file}`);
    if (actual !== expected) {
      console.error(`${file} mode ${actual} !== ${expected}`);
      return 1;
    }
  }

  console.log("== dynamic readiness printer check ==");
  const readinessResult = spawnSync(localPath(".operant/print-readiness.mjs"), [], {
    cwd: repoRoot,
    env: process.env,
    encoding: "utf8",
  });
  if (readinessResult.stdout) process.stdout.write(readinessResult.stdout);
  if (readinessResult.stderr) process.stderr.write(readinessResult.stderr);
  if ((readinessResult.status ?? 1) !== 0) {
    console.error(`readiness printer failed with exit ${readinessResult.status ?? 1}`);
    return 1;
  }
  const readinessOutput = `${readinessResult.stdout || ""}${readinessResult.stderr || ""}`;
  for (const fragment of [
    "Operant live readiness:",
    "Completion audit:",
    "Blocked requirements:",
    "Live report artifacts:",
  ]) {
    if (!readinessOutput.includes(fragment)) {
      console.error(`readiness printer missing expected fragment: ${fragment}`);
      return 1;
    }
  }

  console.log("== dynamic strict audit consistency ==");
  const auditResult = spawnSync(process.execPath, ["scripts/operant-completion-audit.mjs", "--json"], {
    cwd: repoRoot,
    env: process.env,
    encoding: "utf8",
  });
  if (auditResult.stderr) process.stderr.write(auditResult.stderr);
  const auditStatus = auditResult.status ?? 1;
  let audit;
  try {
    audit = JSON.parse(auditResult.stdout || "");
  } catch (error) {
    console.error(`completion audit JSON parse failed: ${error.message}`);
    return 1;
  }
  if (![0, readiness.completionAudit?.expectedExitCodeWhileBlocked || 2].includes(auditStatus)) {
    console.error(`completion audit exited ${auditStatus}; expected 0 or ${readiness.completionAudit?.expectedExitCodeWhileBlocked || 2}`);
    return 1;
  }
  if (auditStatus !== 0 && Number(audit.totals?.failed || 0) !== 0) {
    console.error(`completion audit has failed checks while blocked: ${audit.totals.failed}`);
    return 1;
  }
  console.log(
    `dynamic strict audit ok: exit=${auditStatus} passed=${audit.totals?.passed ?? "unknown"} ` +
      `failed=${audit.totals?.failed ?? "unknown"} blocked=${audit.totals?.blocked ?? "unknown"}`,
  );
  console.log("dynamic handoff verification ok");
  return 0;
}

function parseLiveAcceptanceArgs(args = rawArgs, env = process.env) {
  const parsed = {
    preflightOnly: false,
    composeEnv: env.OPERANT_COMPOSE_ENV || ".operant/local-acceptance.env",
    liveEnv: env.OPERANT_LIVE_ENV || ".operant/live-acceptance.env",
    manualSlackPosts: false,
    manualSlackNudge: false,
    manualUserId: "",
    deniedUseAllowedUser: false,
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case "--preflight-only":
        parsed.preflightOnly = true;
        break;
      case "--env":
        parsed.composeEnv = args[index + 1] || "";
        index += 1;
        break;
      case "--live-env":
        parsed.liveEnv = args[index + 1] || "";
        index += 1;
        break;
      case "--manual-slack-posts":
        parsed.manualSlackPosts = true;
        break;
      case "--manual-slack-nudge":
        parsed.manualSlackNudge = true;
        break;
      case "--manual-user-id":
        parsed.manualUserId = args[index + 1] || "";
        index += 1;
        break;
      case "--denied-use-allowed-user":
        parsed.deniedUseAllowedUser = true;
        break;
      case "--help":
      case "-h":
        usage();
        process.exit(0);
        break;
      default:
        console.error(`Unknown option for live-acceptance: ${arg}`);
        usage();
        process.exit(1);
    }
  }

  if (!parsed.composeEnv) {
    console.error("--env requires a value");
    process.exit(1);
  }
  if (!parsed.liveEnv) {
    console.error("--live-env requires a value");
    process.exit(1);
  }
  if (parsed.manualUserId === "") {
    parsed.manualUserId = env.OPERANT_LIVE_ALLOWED_USER_ID || "";
  }
  parsed.manualSlackPosts =
    parsed.manualSlackPosts ||
    enabled(env.OPERANT_LIVE_MANUAL_SLACK_POSTS) ||
    envFileEnables(parsed.liveEnv, "OPERANT_LIVE_MANUAL_SLACK_POSTS");
  parsed.manualSlackNudge =
    parsed.manualSlackNudge ||
    enabled(env.OPERANT_LIVE_MANUAL_SLACK_NUDGE) ||
    envFileEnables(parsed.liveEnv, "OPERANT_LIVE_MANUAL_SLACK_NUDGE");
  parsed.deniedUseAllowedUser =
    parsed.deniedUseAllowedUser ||
    enabled(env.OPERANT_LIVE_DENIED_USE_ALLOWED_USER) ||
    envFileEnables(parsed.liveEnv, "OPERANT_LIVE_DENIED_USE_ALLOWED_USER");
  return parsed;
}

function runDirectLiveAcceptance(parsed) {
  const missingEnvFiles = [
    ["Compose env", parsed.composeEnv],
    ["Live env", parsed.liveEnv],
  ].filter(([, file]) => !existsSync(path.resolve(repoRoot, file)));

  if (missingEnvFiles.length > 0) {
    printFreshCheckoutHandoff();
    for (const [label, file] of missingEnvFiles) {
      console.error(`\nMissing ${label}: ${file}`);
    }
    process.exit(1);
  }

  const livePreflightArgs = ["live:preflight", "--", "--env", parsed.composeEnv, "--live-env", parsed.liveEnv];
  const composeArgs = ["compose:e2e", "--", "--env", parsed.composeEnv, "--live-env", parsed.liveEnv];

  if (parsed.manualSlackPosts) {
    livePreflightArgs.push("--manual-slack-posts");
    composeArgs.push("--manual-slack-posts");
  }
  if (parsed.manualSlackNudge) {
    composeArgs.push("--manual-slack-nudge");
  }
  if (parsed.manualUserId) {
    livePreflightArgs.push("--manual-user-id", parsed.manualUserId);
    composeArgs.push("--manual-user-id", parsed.manualUserId);
  }
  if (parsed.deniedUseAllowedUser) {
    livePreflightArgs.push("--denied-use-allowed-user");
    composeArgs.push("--denied-use-allowed-user");
  }

  let result = spawnSync("pnpm", livePreflightArgs, {
    cwd: repoRoot,
    env: process.env,
    stdio: "inherit",
  });
  if ((result.status ?? 1) !== 0) process.exit(result.status ?? 1);

  result = spawnSync("docker", ["info"], {
    cwd: repoRoot,
    env: process.env,
    stdio: "ignore",
  });
  if ((result.status ?? 1) !== 0) {
    console.error("Docker daemon is not reachable. Start Docker/Colima before strict live Compose acceptance.");
    process.exit(result.status ?? 1);
  }
  if (parsed.preflightOnly) process.exit(0);

  for (const [executable, args] of [
    ["pnpm", composeArgs],
    ["pnpm", ["audit:completion"]],
    ["pnpm", ["report:final"]],
  ]) {
    result = spawnSync(executable, args, {
      cwd: repoRoot,
      env: process.env,
      stdio: "inherit",
    });
    if ((result.status ?? 1) !== 0) process.exit(result.status ?? 1);
  }
}

function handleLiveAcceptance() {
  const helper = ".operant/run-live-acceptance.sh";
  const onlyPreflightArg = rawArgs.length === 0 || (rawArgs.length === 1 && rawArgs[0] === "--preflight-only");
  if (!forceFreshCheckout && existsSync(localPath(helper)) && onlyPreflightArg) {
    run(helper, rawArgs);
  }
  runDirectLiveAcceptance(parseLiveAcceptanceArgs());
}

function runSelfTestCase(label, args, expectedStatus, expectedPatterns) {
  const result = spawnSync(process.execPath, [scriptPath, ...args], {
    cwd: repoRoot,
    env: {
      ...process.env,
      OPERANT_COMPOSE_ENV: ".operant/nonexistent-compose.env",
      OPERANT_HANDOFF_FORCE_FRESH_CHECKOUT: "1",
      OPERANT_LIVE_ENV: ".operant/nonexistent-live.env",
    },
    encoding: "utf8",
  });
  const status = result.status ?? 1;
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  if (status !== expectedStatus) {
    throw new Error(`${label}: expected exit ${expectedStatus}, got ${status}\n${output}`);
  }
  for (const pattern of expectedPatterns) {
    if (!pattern.test(output)) {
      throw new Error(`${label}: expected output to match ${pattern}\n${output}`);
    }
  }
}

function runSelfTest() {
  runSelfTestCase("fresh readiness", ["readiness"], 0, [
    /Generated \.operant handoff helpers are not present/,
    /pnpm init:env -- --output \.operant\/local-acceptance\.env --force/,
    /pnpm compose:e2e -- --env \.operant\/local-acceptance\.env --live-env \.operant\/live-acceptance\.env/,
  ]);
  runSelfTestCase("fresh verify", ["verify"], 1, [
    /No generated \.operant handoff bundle is available to verify/,
  ]);
  runSelfTestCase("fresh live preflight missing env", ["live-acceptance", "--preflight-only"], 1, [
    /Fresh-checkout private-env path/,
    /Missing Compose env: \.operant\/nonexistent-compose\.env/,
    /Missing Live env: \.operant\/nonexistent-live\.env/,
  ]);
  runSelfTestCase("pnpm separator help", ["live-acceptance", "--preflight-only", "--", "--help"], 0, [
    /Usage: operant-handoff <readiness\|verify\|live-acceptance>/,
    /--preflight-only/,
    /--denied-use-allowed-user/,
  ]);
  const parsed = parseLiveAcceptanceArgs(
    [
      "--env",
      ".operant/local.env",
      "--live-env",
      ".operant/live.env",
      "--manual-slack-posts",
      "--manual-slack-nudge",
      "--manual-user-id",
      "U08E6M4KM35",
      "--denied-use-allowed-user",
    ],
    {},
  );
  if (
    parsed.composeEnv !== ".operant/local.env" ||
    parsed.liveEnv !== ".operant/live.env" ||
    parsed.manualSlackPosts !== true ||
    parsed.manualSlackNudge !== true ||
    parsed.manualUserId !== "U08E6M4KM35" ||
    parsed.deniedUseAllowedUser !== true
  ) {
    throw new Error("live acceptance parser did not preserve one-human manual strict options");
  }
  if (!isStaleHandoffReportSnapshot("Error: .operant/live-e2e-report.json exists=true !== readiness false")) {
    throw new Error("handoff stale-report detector did not catch report existence mismatch");
  }
  if (!isStaleHandoffReportSnapshot("unexpected live E2E artifacts: .operant/live-e2e-extra-report.json")) {
    throw new Error("handoff stale-report detector did not catch unexpected live report artifacts");
  }
  if (isStaleHandoffReportSnapshot("No generated .operant handoff bundle is available to verify.")) {
    throw new Error("handoff stale-report detector matched an unrelated error");
  }
  console.log("Operant handoff self-test passed.");
}

switch (command) {
  case "--self-test":
  case "self-test":
    runSelfTest();
    break;
  case "readiness":
    handleReadiness();
    break;
  case "verify":
    handleVerify();
    break;
  case "live-acceptance":
    handleLiveAcceptance();
    break;
  case "--help":
  case "-h":
    usage();
    break;
  default:
    console.error(`Unknown operant-handoff command: ${command || "(missing)"}`);
    usage();
    process.exit(1);
}
