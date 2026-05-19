# Operant Setup Guide

This guide keeps operational setup out of the project README. Use it to run a
single self-hosted Operant trust boundary, configure Slack/OpenClaw, and
optionally produce strict live evidence for customer acceptance packages.

## Local Stack

```bash
pnpm install
pnpm init:env -- --project-name operant-acme --http-port 18080 --postgres-port 15432 --gateway-port 28789 --output .env.acme
pnpm doctor -- --env .env.acme --preflight-only
pnpm compose:up -- --env .env.acme -d
pnpm doctor -- --env .env.acme
```

Open the dashboard at the `OPERANT_HTTP_PORT` from the env file, for example
`http://localhost:18080`.

Run one Compose project per company/workspace/trust boundary. Do not share an
OpenClaw gateway, state volume, generated config volume, host port set, or
credential set across unrelated workspaces.

`pnpm compose:up -- --env .env.acme -d` starts the dashboard-first stack. Enter
Slack/model credentials in the admin dashboard, then leave that stack running
for employees to mention or DM Operant in Slack.

If your Slack/model values are in a private live env overlay, use the
env-driven live path instead:

```bash
pnpm compose:live -- --env .env.acme --live-env .env.acme.live
```

That command starts Compose, seeds Slack/model credentials and allowlists
through Operant, verifies the generated OpenClaw config, runs doctor/restart
checks, and leaves the live bot running. If no temporary Slack user token is
available, add `--manual-slack-posts --manual-user-id U...` to seed the allowed
human user without trying automated Slack posts.

Stop either path with `pnpm compose:down -- --env .env.acme`; add `-v` only
when deleting local volumes for a disposable evaluation stack.

## Dashboard Setup

### First sign-in

The login form needs two values:

- **Slack user ID** (`U...`). The human who will be the workspace owner.
  Look it up in Slack via profile → "Copy member ID", or set it ahead of time
  with `OPERANT_LIVE_ADMIN_SLACK_USER_ID` in your env.
- **Admin login token**. The generated `OPERANT_ADMIN_LOGIN_TOKEN` value from
  your env file. Treat it like a password; rotate it by editing the env and
  restarting the control plane.

The first credential save promotes that Slack user ID to the `owner` role.
Later sign-ins reuse the same two values.

### Workspace naming

The dashboard shows the workspace as `OPERANT_DEFAULT_COMPANY_NAME` /
`OPERANT_DEFAULT_WORKSPACE_NAME` from your env (defaults: "Acme Inc." / "Acme
Slack"). Either edit those before first `pnpm compose:up`, or rename later
from the Setup tab (or `PUT /api/settings` with
`{"companyName": "...", "workspaceName": "..."}`).

### Tab walkthrough

Use the dashboard tabs left to right for a first deployment:

1. **Setup**: sign in with the generated admin login token, save Slack/model
   credentials, review masked SecretRef state, and wait for **Ready to run Slack
   acceptance**.
2. **Health**: confirm workspace settings, config history, and Pipedream
   diagnostics before inviting operators.
3. **Policy**: edit channels, tool rules, and approval rules with the structured
   controls; keep the raw JSON editor for full-document edits and advanced
   review.
4. **People**: add Slack users, assign built-in or custom roles, and create
   custom action/resource permission pairs.
5. **Approvals**, **Activity**, and **Usage**: inspect pending decisions,
   sessions/jobs, audit rows, usage events, and model/tool cost breakdowns.
6. **Data** and **OpenClaw**: run export, wipe, retention purge, config
   generation, observation sync, and OpenClaw checks only after confirming the
   dashboard dialog for each high-risk action.

Use **Integration Credentials** on the Data tab for customer-owned API/tool
secrets. Secret values are write-only in the browser; saved rows show masked
SecretRef metadata instead of plaintext.

## Pipedream Connect (per-user SaaS tools)

The OpenClaw gateway ships the Operant plugin (`apps/openclaw-plugin`), which
exposes two MCP-shaped tools the agent can call from Slack:
`pipedream_list_actions` and `pipedream_run_action`. They bridge to Pipedream
Connect using a per-Slack-user external id, so each human OAuths their own
SaaS account once and the audit row pins to that human; not a shared service
account.

The plugin only registers the Pipedream tools when all five vars are present
in the gateway environment. With any missing, only `operant_ping` registers
and the gateway boot log prints which vars are absent.

To enable Pipedream tools:

1. Sign up at <https://pipedream.com> and create a project. Copy the project id
   from the URL (`proj_xxxxxxx`).
2. In **Project Settings → OAuth Clients**, create a project OAuth client; copy
   the client id and client secret.
3. Decide between `development` and `production` environments. Pipedream
   Connect treats them as separate token namespaces (a user connected in `dev`
   is not connected in `prod`).
4. Add the five vars to your live overlay (`.env.acme.live`). They're already
   in `.env.example`:

   ```bash
   OPERANT_MCP_SOURCE_PIPEDREAM_URL=https://remote.mcp.pipedream.net/v3
   PIPEDREAM_PROJECT_CLIENT_ID=...
   PIPEDREAM_PROJECT_CLIENT_SECRET=...
   PIPEDREAM_PROJECT_ID=proj_xxxxxxx
   PIPEDREAM_ENVIRONMENT=development
   ```

5. Restart the gateway: `pnpm compose:up -- --env .env.acme -d` (or `docker
   compose restart openclaw-gateway`).
6. Verify in the gateway log: `Operant 0.1.0 enabled` should appear in
   `docker compose exec openclaw-gateway openclaw plugins list`.

Pipedream requires an explicit `app` slug per call (there is no list-all mode).
Common slugs: `gmail`, `slack`, `notion`, `github`, `linear`, `hubspot`,
`google_sheets`. The full catalog is at <https://pipedream.com/apps>.

Once enabled, a Slack user asks the bot for an action and the flow is:

1. Bot calls `pipedream_list_actions {"app": "gmail"}`. The plugin filters the
   returned tools through your Operant policy and returns the allowed set as
   JSON, e.g. `gmail-send-email`, `gmail-list-labels`.
2. Bot calls `pipedream_run_action {"toolName": "gmail-send-email", "args":
   {...}}`. The plugin re-checks the policy (deny / approval_required / allow)
   for `pipedream:gmail/send-email`, forwards to Pipedream Connect with the
   Slack user id in `x-pd-external-user-id`, and returns the Pipedream
   response.
3. **First call per user per app:** Pipedream responds with a connect link
   (`https://pipedream.com/_static/connect.html?token=ctok_...`). The agent
   posts that URL into the Slack thread; the human clicks it, OAuths their own
   account in their browser, then retries. Subsequent calls run under their
   credentials with no further prompts.

The Pipedream-hosted connect link does not require any new Slack scopes; the
bot's existing `chat:write` is enough to post the URL.

To gate or approve Pipedream tools per user/role, use the existing Operant
**Policy Preview** with `tool = pipedream:<app>` (for example
`pipedream:gmail`, `pipedream:notion`) and `action = <action>` (`send-email`,
`*`). Explicit deny beats approval_required beats allow, same as for any other
tool.

## Slack App

Start with [deploy/slack/manifest.yaml](../deploy/slack/manifest.yaml), then
follow [deploy/slack/README.md](../deploy/slack/README.md).

The app-level token is separate from the bot token. Slack requires an app-level
token with `connections:write` for `apps.connections.open`, which returns the
temporary Socket Mode WebSocket URL that OpenClaw uses for Slack events and
interactive payloads. The bot token can read/post as the bot, but it cannot
replace the app-level token for ingress.

Do not enter an Event Subscriptions Request URL when using Socket Mode. Socket
Mode and Event Subscriptions must both be on, the Request URL must stay empty,
and the app must be reinstalled or reauthorized after changing scopes or event
subscriptions.

Before debugging OpenClaw, isolate Slack delivery:

```bash
pnpm slack:socket-probe -- --env .env.acme.live --manual-user-id U... --nudge
```

If Slack returns `[WARN] Socket Mode is not turned on.`, enable Socket Mode for
the same Slack app ID as the bot token, save the app, and reinstall or
reauthorize it. If the probe receives `hello` but no human mention event,
repair Event Subscriptions or the app install before running strict Compose E2E.
If public-channel mentions work but manual DM evidence is missing, isolate the
allowed-user DM before running the full strict gate:

```bash
pnpm slack:dm-probe -- --env .env.acme --live-env .env.acme.live --manual-user-id U... --nudge
```

The DM probe verifies that `OPERANT_LIVE_DM_CHANNEL_ID` is the bot DM for the
allowed human with `conversations.open`, posts an optional copy/paste nudge,
mirrors a channel reminder when `SLACK_CHANNEL_ID` is configured, and waits for
the exact human-authored DM message. Bot-authored nudges and channel reminders
are not accepted as evidence.

If Slack shows “Bot DMs are not enabled” or the human cannot type in the bot
DM, fix the Slack app before rerunning: in the Slack app dashboard go to
**Features -> App Home -> Messages Tab**, enable the Messages tab, and keep
user input writable. In the manifest this is
`features.app_home.messages_tab_enabled: true` and
`features.app_home.messages_tab_read_only_enabled: false`; after changing it in
Slack, reinstall or re-authorize the app so the installed bot receives the
updated setting.

If you have a Slack configuration/user token with `app_configurations:read`,
verify the installed manifest instead of relying on the UI:

```bash
pnpm slack:manifest-probe -- --env .env.acme.live
```

Slack app and bot tokens cannot export manifests. The probe needs
`SLACK_CONFIG_TOKEN` plus either `SLACK_APP_ID` or an `xapp-...` app token it
can use to infer the app ID.

For live verifiers, manual human-post mode, and strict acceptance gates, see
[docs/acceptance.md](acceptance.md).

## OpenClaw Operator Pairing

OpenClaw operator-scoped checks such as secrets reload, exec approvals, and
usage-cost can require an approved paired operator device. The everyday Slack
path; mention/DM the bot, policy decisions, audit, dashboard; does **not**
need a paired operator; you only need this for strict-acceptance runs and the
operator-scoped checks listed above.

If a strict run or `pnpm doctor` reports `pairing required`, inspect and approve
the exact request ID:

```bash
docker compose exec openclaw-gateway openclaw devices list
docker compose exec openclaw-gateway openclaw devices approve <requestId>
```

Expected operator scopes include `operator.read`, `operator.approvals`, and
`operator.talk.secrets`; `operator.admin` satisfies them. Do not use
`openclaw devices approve --latest` as the final approval step because OpenClaw
uses it as a preview.

### Scope upgrades are incremental

OpenClaw escalates an operator device one scope at a time. The first
`docker compose exec openclaw-gateway openclaw devices list` after a fresh
start shows a pending request for `operator.pairing`. Approve it; the next
operator-scoped command (for example `openclaw secrets reload`) requests
`operator.talk.secrets` and creates a second pending request. Approve that
one too. After two approvals the gateway has the scopes needed for
`secrets reload`, exec approvals, and usage-cost.

If you saw `unknown requestId` errors on older releases, that was the
2026.5.12 rotating-request-ID bug. The default `OPENCLAW_VERSION` is now
`2026.5.18`, where each `devices list` / `devices approve` round-trip uses
a stable request ID and the documented flow works as written.

## Integration Credentials

Integration credentials are scoped either to the workspace (shared) or to a
specific Slack user. Leave the **Slack user ID** field blank in the dashboard's
Integration Credentials form to store one workspace-shared row (the
back-compatible default). Set a Slack user ID to store a per-user row, so each
employee can connect their own Gmail/GitHub/Linear/HubSpot token without
sharing it with the workspace. The SecretRef path encodes the scope as
`workspaces/<wsId>/integrations/<kind>/<key>` for shared rows and
`workspaces/<wsId>/users/<slackUserId>/integrations/<kind>/<key>` for
user-scoped rows, and each resolution is recorded as an
`integration_credential.resolved` audit row carrying the parsed `slackUserId`.

To verify customer-owned tool credentials, set
`OPERANT_LIVE_INTEGRATION_CREDENTIALS` to comma-separated `kind/key=ENV_VAR`
entries, for example `github/api-token=GITHUB_TOKEN`.

For labels or structured metadata, use `OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON`,
a JSON array of objects with `kind`, `key`, optional `label`, optional
`slackUserId`, and either `secretValueEnv` or `secretValue`. Prefer
`secretValueEnv`; generated reports redact referenced env values and
inline JSON secret values before writing evidence.

## Docker Sandbox Overlay

Base Compose intentionally does not mount the host Docker socket into the
OpenClaw gateway, so generated OpenClaw config sets
`agents.defaults.sandbox.mode=off` by default. For Docker-backed OpenClaw tool
sandboxing, use a dedicated single-trust-boundary Docker host:

```bash
pnpm compose:up -- --env .env.acme --file docker-compose.sandbox.yml -d
pnpm compose:smoke -- --env .env.acme --file docker-compose.sandbox.yml --profile queue
```

The overlay sets `OPERANT_OPENCLAW_SANDBOX_MODE=docker`, builds a local gateway
image with Docker CLI installed, adds the gateway process to
`OPENCLAW_DOCKER_GID`, and bootstraps OpenClaw's default sandbox runtime image.
Mounting the Docker socket gives the gateway broad control over the Docker host,
so do not use the overlay on a shared host for unrelated workspaces.
