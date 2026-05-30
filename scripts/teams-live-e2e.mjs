#!/usr/bin/env node

const help = `Usage: pnpm teams:live:e2e -- --manual-posts [--preflight-only]

Manual Microsoft Teams acceptance checklist:
  1. Start Operant with Teams credentials saved in the dashboard or live env.
  2. Expose the OpenClaw Teams webhook over HTTPS and set Azure Bot Messaging Endpoint to /api/messages.
  3. Post a Teams DM to Operant and a channel mention in an allowlisted team/channel.
  4. Run OpenClaw channels status with --probe --json, sync Operant observations, and confirm session/job/usage deltas.
  5. Exercise an approval-required prompt and confirm Operant approval records plus a human-observed Teams reply.

Options:
  --manual-posts        Required: Teams v1 acceptance is human-driven, not automated.
  --preflight-only      Print the checklist and the required live env keys, then exit.
  --help, -h            Show this help
`;

const knownFlags = new Set([
  "--manual-posts",
  "--preflight-only",
  "--help",
  "-h",
  "--self-test-arg-validation",
]);

const liveEnvKeys = [
  "TEAMS_APP_ID",
  "TEAMS_APP_PASSWORD",
  "TEAMS_TENANT_ID",
  "MSTEAMS_PUBLIC_MESSAGING_ENDPOINT",
  "OPERANT_LIVE_TEAMS_ALLOWED_AAD_USER_ID",
  "OPERANT_LIVE_TEAMS_APPROVER_AAD_USER_ID",
  "OPERANT_LIVE_TEAMS_TEAM_ID",
  "OPERANT_LIVE_TEAMS_CHANNEL_ID",
  "OPERANT_LIVE_TEAMS_DM_CONVERSATION_ID",
];

function parseArgs(argv) {
  const args = argv.filter((arg) => arg !== "--");
  const unknown = args.filter((arg) => !knownFlags.has(arg));
  if (unknown.length > 0) {
    throw new Error(`Unknown argument(s): ${unknown.join(", ")}`);
  }
  return {
    help: args.includes("--help") || args.includes("-h"),
    manualPosts: args.includes("--manual-posts"),
    preflightOnly: args.includes("--preflight-only"),
    selfTestArgValidation: args.includes("--self-test-arg-validation"),
  };
}

function assertArgValidationFails(argv, expectedMessage) {
  try {
    parseArgs(argv);
  } catch (error) {
    if (String(error.message).includes(expectedMessage)) return;
    throw new Error(`Expected validation error containing "${expectedMessage}", got "${error.message}"`);
  }
  throw new Error(`Expected validation failure for args: ${argv.join(" ")}`);
}

function runArgValidationSelfTest() {
  parseArgs(["--", "--manual-posts"]);
  parseArgs(["--manual-posts", "--preflight-only"]);
  assertArgValidationFails(["--unknown"], "Unknown argument");
  if (!liveEnvKeys.includes("MSTEAMS_PUBLIC_MESSAGING_ENDPOINT")) {
    throw new Error("teams live env key contract is missing MSTEAMS_PUBLIC_MESSAGING_ENDPOINT");
  }
  process.stdout.write("teams live e2e argument validation self-test passed.\n");
}

function main() {
  let parsed;
  try {
    parsed = parseArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n${help}`);
    process.exit(1);
  }

  if (parsed.selfTestArgValidation) {
    runArgValidationSelfTest();
    return;
  }

  if (parsed.help) {
    process.stdout.write(help);
    return;
  }

  if (parsed.preflightOnly) {
    process.stdout.write(help);
    process.stdout.write("\nRequired live env keys (see deploy/teams/live.env.example):\n");
    for (const key of liveEnvKeys) process.stdout.write(`  ${key}\n`);
    return;
  }

  if (!parsed.manualPosts) {
    process.stderr.write("Teams v1 acceptance is manual; pass --manual-posts.\n");
    process.exit(1);
  }

  process.stdout.write(help);
}

main();
