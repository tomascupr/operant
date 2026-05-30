# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Operant is a self-hostable, MIT-licensed control plane for agents in Slack. It wraps OpenClaw, which owns Slack ingress/egress (Socket Mode) and the agent runtime; Operant adds: encrypted BYOK credential storage, RBAC + custom roles, channel/tool/approval policy, audit/usage/cost tracking, retention export/wipe, an admin dashboard, and a generated `openclaw.json` that points OpenClaw at Operant secrets through SecretRefs (no plaintext on disk).

The README is the project-facing overview. Operational setup lives in `docs/setup.md`; Slack scopes/events and live acceptance details live in `deploy/slack/README.md`. When in doubt about Slack/live-acceptance flow, scopes, manual vs. token mode, sandbox overlay, or env aliases, read those docs before improvising.

## Coding behavior

- **Think first.** State assumptions before coding; if uncertain, ask. When multiple interpretations exist, surface them — don't pick silently. Push back when a simpler approach exists.
- **Simplicity first.** Minimum code that solves the problem. No abstractions for single-use code, no error handling for impossible scenarios, no "flexibility" that wasn't asked for.
- **Surgical changes.** Touch only what the request requires. Don't "improve" adjacent code, comments, or formatting; don't refactor what isn't broken. Match existing style. Mention pre-existing dead code rather than deleting it.
- **Goal-driven execution.** Translate each task into a verifiable goal before coding ("fix the bug" → "write a failing reproducer, then make it pass"). For multi-step work, state plan + verify per step and loop until each step is green.

## Workspace layout

pnpm workspace, Node 24, pnpm 11. Two apps: `apps/control-plane` (`@operant/control-plane`) is the HTTP control plane; `apps/openclaw-plugin` (`@operant/openclaw-plugin`) is an OpenClaw plugin bundled into the gateway image. Everything else is operational scripting (`scripts/`), deploy artifacts (`deploy/{openclaw,slack,helm,fly}`), or docs.

- `apps/control-plane/src/server.ts` (~2.8k LoC) is the entire HTTP API. No framework — raw `node:http` with a single `route()` function dispatching on method+pathname. New endpoints go in `route()` near the existing handlers; static files under `apps/control-plane/public/` are served by the same process.
- `apps/control-plane/src/{secrets,policy,rbac,openclaw-config,openclaw-ops,retention,redaction,seed,schema,auth,db}.ts` — domain modules; `schema.ts` holds zod validators and shared types; `redaction.ts` is the shared sanitizer applied before persisting reports/audit payloads (token-shape regexes for Slack/OpenAI/GitHub/AWS plus a sensitive-key matcher).
- `apps/control-plane/migrations/NNN_*.sql` — raw SQL migrations applied transactionally by `runMigrations` on boot. To add one, drop the next-numbered file; the runner records it in `schema_migrations`.
- `apps/control-plane/tests/*.test.ts` — Node's built-in `node:test`. Tests run against compiled JS (`dist/tests/*.test.js`), not via ts-node.
- `apps/control-plane/public/{index.html,app.js,styles.css}` — vanilla JS dashboard. Strict CSP allows only same-origin scripts/styles, so no CDNs or inline scripts.
- `apps/openclaw-plugin/src/index.ts` — `definePluginEntry` registers `operant_ping` plus the two Pipedream factory tools. `register(api)` reads env (`OPERANT_CONTROL_PLANE_URL`, `OPERANT_INTERNAL_TOKEN`, the five `PIPEDREAM_*` vars + `OPERANT_MCP_SOURCE_PIPEDREAM_URL`); incomplete env logs a warn and silently skips the dependent tool set rather than throwing.
- `apps/openclaw-plugin/src/operant-client.ts` — fetch wrapper for `/internal/plugin/user-context` and `/internal/plugin/policy-check` against the control plane (bearer = `OPERANT_INTERNAL_TOKEN`).
- `apps/openclaw-plugin/src/pipedream/{client,tools}.ts` — Pipedream Connect MCP transport over Streamable HTTP. `client.ts` mints + caches an OAuth client-credentials token, sends `Accept: application/json, text/event-stream`, and `parseSseJsonRpc` extracts the JSON-RPC envelope from the SSE response Pipedream always returns. `tools.ts` builds the per-Slack-user factory tools, derives `app/action` from the tool name (split on first `-`), and runs each through `evaluatePipedreamPolicy` against Operant.
- `apps/openclaw-plugin/openclaw.plugin.json` — manifest declaring `contracts.tools` (the three tools above) and `activation.onStartup: false` (lazy load). The OpenClaw plugin loader reads this when extracting the tarball.
- `apps/openclaw-plugin/tests/*.test.ts` — same `node:test` pattern as control-plane (build, then run compiled JS). `tests/stub-server.ts` is the shared in-process HTTP stub for OAuth + MCP fixtures.
- `scripts/operant-*.mjs` + `scripts/slack-*.mjs` — heavyweight Node CLIs (doctor, smoke, live E2E, compose E2E, completion audit, final report, handoff, etc.). Each accepts `--self-test-*` flags that exercise their own arg/env parsing; `pnpm verify:scripts` runs them all and they must stay self-testable.
- `deploy/openclaw/operant-secret-resolver.mjs` — runs inside the OpenClaw gateway container; reads stdin, fetches secrets from the control-plane's `/internal/openclaw/secrets/<id>` using `OPERANT_INTERNAL_TOKEN`, writes JSON to stdout.
- `deploy/openclaw/Dockerfile.gateway` — multi-stage build: stage 1 (`node:24-alpine`) `pnpm install` + `pnpm --filter @operant/openclaw-plugin build` + `npm pack` into `/build/packed/`; stage 2 (openclaw base) `COPY`s the tarball into `/usr/local/share/operant/openclaw/plugins/` so `ensure-channel-plugins.sh` can `openclaw plugins install --force` it on first boot.

## Commands

Install once: `pnpm install`. Generate a stack-scoped `.env`: `pnpm init:env` (use `--project-name`, `--http-port`, etc., and `--output .env.acme` for additional trust boundaries).

Inner dev loop (no Docker):
- `pnpm typecheck` — `tsc -p apps/control-plane/tsconfig.json --noEmit`
- `pnpm build` — `tsc` into `apps/control-plane/dist/`
- `pnpm test` — builds, then `node --test dist/tests/*.test.js`. Single test file: `pnpm --filter @operant/control-plane build && node --test apps/control-plane/dist/tests/policy.test.js`. Single test by name within a file: `node --test --test-name-pattern="<regex>" apps/control-plane/dist/tests/policy.test.js`.
- `pnpm dev` — builds and runs `node dist/src/server.js`. Requires `DATABASE_URL` and `OPERANT_SECRET_KEY` in the environment; easiest path is `pnpm compose:up` first, then `pnpm dev` against `localhost:5432`.
- `pnpm smoke` / `pnpm smoke:local` — process-level smoke against `apps/control-plane` (no Docker); asserts CSP and security headers. The `:local` variant runs in `--managed` mode.
- `pnpm dashboard:e2e` — headless Chrome dashboard E2E (honours `CHROME_PATH`). Included in the full `pnpm verify` chain.

Full static gauntlet: `pnpm verify` chains `verify:scripts` → `typecheck` → `test` → `dashboard:e2e` → `verify:compose` → `verify:deploy`. `verify:scripts` runs `node --check` plus self-tests for every script and three `compose config` dry runs (base, queue profile, sandbox overlay). Run this before claiming anything passes.

Runtime / live gates (in dependency order):
- `pnpm doctor -- --preflight-only` — local env + Compose preflight
- `pnpm compose:config` / `pnpm compose:up [-- --profile queue] [-- --file docker-compose.sandbox.yml]` / `pnpm compose:down` — compose lifecycle (all wrap `scripts/operant-compose.mjs`)
- `pnpm doctor` — full health/ready/OpenClaw checks against the running stack
- `pnpm compose:smoke` / `pnpm compose:smoke:sandbox` — non-live runtime smoke; writes `.operant/compose-smoke-report.json`
- `pnpm compose:live` — full Compose E2E with the live + completion-audit gates skipped (fast inner loop when iterating on compose itself)
- `pnpm live:preflight -- --env .env --live-env .env.live` — validates Slack + model creds without starting Compose
- `pnpm live:e2e` — assisted live Slack/OpenClaw E2E against an already-running stack
- `pnpm compose:e2e -- --env .env --live-env .env.live` — strict live + restart gate (full customer-run flow); writes `.operant/compose-e2e-report.json`
- `pnpm audit:completion` — completion audit; refuses to pass until Docker + live gates land in the recorded reports with matching SHA-256 fingerprints
- `pnpm report:final` — regenerates `.operant/final-report.md`
- `pnpm acceptance:local [-- --include-sandbox]` — bundles the local/static gauntlet and regenerates reports
- `pnpm handoff:{readiness,verify}`, `pnpm live:acceptance{,:preflight}` — customer-facing wrappers; in a fresh checkout (no `.operant/` bundle) they print the direct command path instead of failing.

Slack diagnostics: `pnpm slack:scopes [-- --json]` prints the required bot scopes; `pnpm slack:socket-probe -- --env .env --manual-user-id U... --nudge` opens a raw Socket Mode connection to isolate Slack-app-side issues from OpenClaw. Additional probes — `pnpm slack:manifest-probe` exports the installed Slack app manifest via a Slack config token and validates it against the scope contract; `pnpm slack:dm-probe` waits for a human to post a nonce in the bot DM channel as live-DM evidence; `pnpm slack:user-token` exchanges an OAuth callback code for a user token and writes it to a gitignored env file (never prints it); `pnpm slack:user-token-probe` posts a message as the user token and reads it back with the bot token to verify Slack stored it as a true human-authored message rather than app-authored (the distinction OpenClaw uses to suppress bot loops).

## Architecture

**Trust boundary = Compose project.** One stack per workspace. `OPERANT_COMPOSE_PROJECT_NAME` scopes Postgres, Redis, OpenClaw state, and the generated-config volume on a Docker host. Never reuse a project name, host port set, OpenClaw state volume, or credential set across workspaces. All host ports bind to `127.0.0.1` by default (`OPERANT_HTTP_BIND`, `POSTGRES_HOST_BIND`, `OPENCLAW_GATEWAY_HOST_BIND`).

**Services (`docker-compose.yml`).** `postgres` (16-alpine), `redis` (7-alpine, `queue` profile only — Operant runs synchronous today), `policy-audit` (control plane, image built from `apps/control-plane/Dockerfile`; non-root `node` user; `OPENCLAW_VERSION` pinned), and `openclaw-gateway` (image built from `deploy/openclaw/Dockerfile.gateway`; reads the generated config from `operant-openclaw-config` volume; runs `openclaw gateway run`).

**Sandbox overlay (`docker-compose.sandbox.yml`).** Opt-in only. Base Compose intentionally does **not** mount the Docker socket, so generated config sets `agents.defaults.sandbox.mode=off`. The overlay flips it to `docker`, mounts `/var/run/docker.sock`, adds the gateway to `OPENCLAW_DOCKER_GID`, and bootstraps `openclaw-sandbox:bookworm-slim`. Single-trust-boundary hosts only.

**Secrets.** AES-256-GCM, envelope format `v1:<iv>:<tag>:<ciphertext>` (`apps/control-plane/src/secrets.ts`). `OPERANT_SECRET_KEY` must decode to exactly 32 bytes (base64 / 64-hex / raw utf8). Encrypted blobs are stored in Postgres; plaintext never leaves the control plane. OpenClaw resolves secrets at runtime by spawning `operant-secret-resolver.mjs`, which hits `/internal/openclaw/secrets/<SecretRefId>` with `Authorization: Bearer $OPERANT_INTERNAL_TOKEN`. SecretRef IDs follow `workspaces/<workspaceId>/<path>` for workspace-shared credentials and `workspaces/<workspaceId>/users/<slackUserId>/<path>` for per-user credentials (`buildSecretRefId(workspaceId, path, { slackUserId? })`). The inverse `parseSecretRefId` returns `{ workspaceId, slackUserId }` and is used in `handleSecret` to populate the `integration_credential.resolved` audit row so per-user credential pulls are attestable.

**OpenClaw config generation (`openclaw-config.ts`).** Pure function over `OpenClawConfigInput` → JSON config. Compiles channel allowlists, global tool deny/allow/approval lists, plugin gates (Slack always enabled), and pins `agentRuntime.id=pi` when the model key is OpenAI to avoid OpenClaw's default Codex harness (which fails the zero-critical security gate). Per-user/per-role tool entitlements stay in Operant policy storage/API because current OpenClaw config exposes global tool lists rather than a general per-user tool matrix. `checksumConfig` is what reload checks compare against.

**OpenClaw ops (`openclaw-ops.ts`).** Wrappers around `openclaw <check>` commands (`status`, `doctor`, `security audit`, `channels status`, `secrets reload`, `approvals get`, `cron status`, `tasks list`, `gateway usage-cost`, `config validate`). All return parsed JSON when available. `extractOpenClaw*Observations` parses session/task/usage-cost data so `/api/openclaw/observations/sync` can mirror it into Operant tables. Operant **observes** OpenClaw cron/tasks rather than rebuilding a scheduler.

**Policy engine (`policy.ts`).** Order: (a) DM allowlist (deny if `chatType==="direct"` and user not in `allowedDmUserIds`); (b) channel policy (must be allowlisted, enabled, user not in `deniedUserIds`, user in `allowedUserIds` when set); (c) tool policy by `tool` + `action` (`*` action matches all) and optional `slackUserIds`/`roleNames` principals. Explicit `deny` beats `approval_required` beats `allow`; scoped allow/approval policies deny users without a matching Slack ID or role for that tool/action, while unscoped missing matches still fall through to allow. `summarizeApprovalRequirement` separately matches approval policies on action/resource wildcards.

**RBAC (`rbac.ts`).** Six built-ins: `owner`, `admin`, `integration_admin`, `billing_usage_admin`, `member`, `viewer`. Permissions are `action:resource` tuples; `*` is a wildcard on either side. Custom roles store explicit grant pairs in `role_permissions`. `permissionMatches` enforces wildcard semantics.

**Auth (`auth.ts`).** Two surfaces: dashboard sessions (random `base64url` bearer tokens, sha256-hashed at rest, table `admin_sessions`) and the internal SecretRef bearer (`OPERANT_INTERNAL_TOKEN`, compared with `timingSafeEqual`). Admin bootstrap: first credential save will create the workspace owner when `OPERANT_ADMIN_LOGIN_TOKEN` and the admin Slack user ID are provided together.

**HTTP routing.** Hard-coded `if (req.method === "X" && url.pathname === "...")` chain at the bottom of `server.ts`. `/healthz`, `/readyz`, `/api/*` (dashboard surfaces), `/internal/openclaw/{secrets/*,events}` (OpenClaw → Operant), then a static fallback for `/`. Response headers force `cache-control: no-store` plus a strict same-origin CSP — extending the dashboard with external resources will break it; bundle locally instead.

**Slack manifest** lives at `deploy/slack/manifest.yaml`. The minimum strict-acceptance bot scopes are encoded in `scripts/slack-scope-contract.mjs` and validated by `pnpm live:preflight`; the app-level token must have `connections:write` for Socket Mode. After any scope or event-subscription change, **reinstall or re-authorize** the Slack app — old tokens do not pick up new scopes.

## Invariants and gotchas

- **Build before test.** `pnpm test` and `pnpm typecheck` both work on the TypeScript source, but the test runner reads `dist/tests/*.test.js`. Edit a test, then either `pnpm test` (which builds first) or `pnpm --filter @operant/control-plane build` before running `node --test` directly.
- **Migrations are append-only.** Don't rewrite an applied migration; add the next number. The bootstrap path (`ensureDefaultWorkspace` + `seedRolesAndPermissions`) runs on every start and is idempotent.
- **Reports are evidence, not artifacts.** `.operant/` is gitignored but the completion audit hashes `package.json` scripts, `pnpm-lock.yaml`, `.env.example`, both compose files, the gateway Dockerfile, the sandbox overlay, the secret resolver, the Slack manifest, and the entire script set; any change invalidates a stored report. Re-run `pnpm compose:e2e` and `pnpm audit:completion` after touching those.
- **Live preflight enforces shape.** App-level tokens must start `xapp-`, bot tokens `xoxb-`, user tokens `xoxp-`; allowed/denied user tokens must resolve to different Slack users; the bot `auth.test` must return `bot_id`. Documented placeholders (`U...`, `<slack-bot-token>`) are rejected.
- **Generated dashboard tokens are not live creds.** Smoke tests seed synthetic `OPERANT_ADMIN_LOGIN_TOKEN` / `OPERANT_INTERNAL_TOKEN`; the live gate refuses to accept those values as Slack/model credentials.
- **`docker compose exec openclaw-gateway openclaw devices approve --latest` is a preview, not an approval.** Use the explicit request ID. Expected operator scopes: `operator.read`, `operator.approvals`, `operator.talk.secrets` (or `operator.admin`).
- **CSP locks the dashboard down.** `default-src 'self'`, no `unsafe-inline`. Vanilla JS only; don't add a bundler or pull external scripts.
- **`OPERANT_OPENCLAW_SANDBOX_MODE=off` is correct for base compose.** Only the sandbox overlay should set it to `docker`. The doctor/audit treat the wrong value as a config bug.

## Live testing without user tokens

Set `OPERANT_LIVE_MANUAL_SLACK_POSTS=1` (or pass `--manual-slack-posts`) and the verifier waits for the configured humans to post the printed mention/DM/denied/approval prompts. Manual mode is the right path when you only have app-level + bot tokens; a timeout in manual mode means the verifier reached the live checkpoint and is still waiting for a human, not that the run failed. The `:manual` script aliases (`pnpm live:preflight:manual`, `pnpm live:e2e:manual`, `pnpm compose:e2e:manual`) are pre-wired with `--manual-slack-posts --manual-slack-nudge`.

## When unsure

Trace through the actual command rather than guessing — every `scripts/operant-*.mjs` has `--help` and the larger ones (`doctor`, `live-e2e`, `compose-e2e`, `completion-audit`, `final-report`) have self-test flags that document their own invariants.
