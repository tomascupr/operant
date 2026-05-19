import { pathToFileURL } from "node:url";

export const requiredAppLevelScopes = ["connections:write"];

export const requiredVerifierUserScopes = ["chat:write"];

export const requiredLiveBotScopes = [
  "app_mentions:read",
  "assistant:write",
  "channels:history",
  "channels:join",
  "channels:read",
  "chat:write",
  "im:history",
  "im:read",
  "im:write",
  "reactions:write",
];

export const requiredSlackBotEvents = [
  "app_mention",
  "message.channels",
  "message.im",
];

export const recommendedSlackBotEvents = [
  "app_home_opened",
  ...requiredSlackBotEvents,
  "channel_rename",
  "member_joined_channel",
  "member_left_channel",
  "message.groups",
  "message.mpim",
  "reaction_added",
  "reaction_removed",
  "pin_added",
  "pin_removed",
];

export const recommendedOpenClawBotScopes = Array.from(new Set([
  ...requiredLiveBotScopes,
  "commands",
  "emoji:read",
  "files:read",
  "files:write",
  "groups:history",
  "groups:read",
  "mpim:history",
  "mpim:read",
  "mpim:write",
  "pins:read",
  "pins:write",
  "reactions:read",
  "usergroups:read",
  "users:read",
]));

function parseSlackScopesFromManifestSection(source, sectionName) {
  const scopes = [];
  const lines = String(source || "").split(/\r?\n/);
  let inScopes = false;
  let sectionIndent = -1;
  const sectionPattern = new RegExp(`^(\\s*)${sectionName}:\\s*$`);
  for (const line of lines) {
    const sectionMatch = sectionPattern.exec(line);
    if (sectionMatch) {
      inScopes = true;
      sectionIndent = sectionMatch[1].length;
      continue;
    }
    if (!inScopes) continue;
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    const indent = line.match(/^\s*/)?.[0].length || 0;
    if (indent <= sectionIndent) break;
    const scopeMatch = /^\s*-\s*([A-Za-z0-9:._-]+)\s*$/.exec(line);
    if (scopeMatch) scopes.push(scopeMatch[1]);
  }
  return scopes;
}

export function parseSlackBotScopesFromManifest(source) {
  return parseSlackScopesFromManifestSection(source, "bot");
}

export function parseSlackUserScopesFromManifest(source) {
  return parseSlackScopesFromManifestSection(source, "user");
}

export function missingScopes(actualScopes, requiredScopes) {
  const actual = new Set(actualScopes);
  return requiredScopes.filter((scope) => !actual.has(scope));
}

export function slackScopeContract() {
  return {
    appLevelToken: {
      purpose: "Socket Mode ingress through Slack apps.connections.open",
      scopes: requiredAppLevelScopes,
    },
    verifierUserToken: {
      purpose: "Automated live verifier posts with a temporary human user token",
      scopes: requiredVerifierUserScopes,
    },
    minimumBotOAuthScopes: requiredLiveBotScopes,
    recommendedBotOAuthScopes: recommendedOpenClawBotScopes,
    requiredBotEventSubscriptions: requiredSlackBotEvents,
    recommendedBotEventSubscriptions: recommendedSlackBotEvents,
  };
}

function printTextContract() {
  const contract = slackScopeContract();
  process.stdout.write("Slack app-level token scopes:\n");
  for (const scope of contract.appLevelToken.scopes) process.stdout.write(`- ${scope}\n`);
  process.stdout.write("\nTemporary verifier user token scopes:\n");
  for (const scope of contract.verifierUserToken.scopes) process.stdout.write(`- ${scope}\n`);
  process.stdout.write("\nMinimum bot OAuth scopes for strict acceptance:\n");
  for (const scope of contract.minimumBotOAuthScopes) process.stdout.write(`- ${scope}\n`);
  process.stdout.write("\nRecommended bot OAuth scopes for full OpenClaw Slack feature coverage:\n");
  for (const scope of contract.recommendedBotOAuthScopes) process.stdout.write(`- ${scope}\n`);
  process.stdout.write("\nRequired Slack bot event subscriptions:\n");
  for (const event of contract.requiredBotEventSubscriptions) process.stdout.write(`- ${event}\n`);
  process.stdout.write("\nRecommended Slack bot event subscriptions for full OpenClaw Slack feature coverage:\n");
  for (const event of contract.recommendedBotEventSubscriptions) process.stdout.write(`- ${event}\n`);
}

function usage() {
  return `Usage: node scripts/slack-scope-contract.mjs [--json|--self-test]\n\nPrints the Slack app-level and bot OAuth scopes used by Operant verifiers.\n`;
}

function runSelfTest() {
  const contract = slackScopeContract();
  const required = new Set(contract.minimumBotOAuthScopes);
  if (!contract.appLevelToken.scopes.includes("connections:write")) throw new Error("missing app-level connections:write scope");
  if (!contract.verifierUserToken.scopes.includes("chat:write")) throw new Error("missing verifier user chat:write scope");
  if (!required.has("assistant:write")) throw new Error("missing strict assistant:write bot scope");
  if (!required.has("reactions:write")) throw new Error("missing strict reactions:write bot scope");
  if (missingScopes(contract.recommendedBotOAuthScopes, contract.minimumBotOAuthScopes).length > 0) {
    throw new Error("recommended scopes do not include all minimum bot scopes");
  }
  if (!contract.requiredBotEventSubscriptions.includes("app_mention")) throw new Error("missing app_mention event subscription");
  if (!contract.requiredBotEventSubscriptions.includes("message.channels")) throw new Error("missing message.channels event subscription");
  const parsed = parseSlackBotScopesFromManifest("oauth_config:\n  scopes:\n    bot:\n      - app_mentions:read\n      - assistant:write\n");
  if (parsed.join(",") !== "app_mentions:read,assistant:write") throw new Error("manifest scope parser failed");
  const parsedUser = parseSlackUserScopesFromManifest("oauth_config:\n  scopes:\n    user:\n      - chat:write\n    bot:\n      - app_mentions:read\n");
  if (parsedUser.join(",") !== "chat:write") throw new Error("manifest user scope parser failed");
  process.stdout.write("Slack scope contract self-test passed.\n");
}

function main() {
  const args = process.argv.slice(2).filter((arg) => arg !== "--");
  const knownArgs = new Set(["--help", "-h", "--json", "--self-test"]);
  const unknown = args.filter((arg) => !knownArgs.has(arg));
  if (unknown.length > 0) {
    process.stderr.write(`Unknown argument(s): ${unknown.join(", ")}\n${usage()}`);
    process.exit(1);
  }
  if (args.includes("--help") || args.includes("-h")) {
    process.stdout.write(usage());
    return;
  }
  if (args.includes("--self-test")) {
    runSelfTest();
    return;
  }
  if (args.includes("--json")) {
    process.stdout.write(`${JSON.stringify(slackScopeContract(), null, 2)}\n`);
    return;
  }
  printTextContract();
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
