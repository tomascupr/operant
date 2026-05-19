# Slack App Setup

Use [manifest.yaml](manifest.yaml) as the starting point for the customer-owned
Slack app. It enables Socket Mode, configures the bot user, subscribes to the
events OpenClaw needs for App Home, DMs, mentions, channel/group messages,
reactions, and pins, and grants the recommended bot scopes. Keep App Home's
Home and Messages tabs enabled so Slack can deliver the App Home and DM surfaces
OpenClaw owns.

## Create the app from the manifest

1. Open [**https://api.slack.com/apps?new_app=1**](https://api.slack.com/apps?new_app=1).
   Sign in if Slack prompts you. The "Create an app" modal opens.
2. Pick **From an app manifest**, then choose the workspace you want to install
   into.
3. Paste the contents of [manifest.yaml](manifest.yaml) into the YAML textarea
   (the dialog defaults to JSON — switch the toggle to YAML first). Review the
   summary screen and click **Create**.
4. Continue with the install steps below.

If your workspace requires admin approval for new apps, the manifest dialog
will queue an approval request instead of creating the app immediately.

## After creating the app from the manifest

1. Install the app into the customer Slack workspace.
2. Copy the Bot User OAuth Token (`xoxb-...`) into Operant's dashboard.
3. In Slack's Basic Information page, generate an app-level token with the
   `connections:write` scope.
4. Copy the App-Level Token (`xapp-...`) into Operant's dashboard.

In the Operant dashboard, use **Credential Setup** for the Slack bot token,
Slack app-level token, model provider/name/API key, allowed DM users, allowed
channels, and approval users. Use **User Access**, **Custom Roles**, and
**Policy Preview** for workspace permissions after the first credential setup
creates the owner session.

Slack's app-level `connections:write` token is required for Socket Mode and is
managed separately from bot OAuth scopes. Slack's `apps.connections.open`
method requires that app-level token and returns the temporary WebSocket URL
used by Socket Mode. The bot token can read conversations and post replies, but
it cannot replace the app-level token for Slack event and interactive-payload
ingress.

Do not enter an Event Subscriptions **Request URL** for the Socket Mode setup.
With Socket Mode enabled, Slack delivers events and interactive payloads over
the WebSocket opened by OpenClaw with the `xapp-...` token. If the Slack UI will
not save manual Event Subscriptions changes with the Request URL empty, import
[manifest.yaml](manifest.yaml) from **App Manifest** and reinstall the app
instead.

Operator verification checklist:

1. **Settings → Socket Mode** is On for the same Slack app that owns the bot.
2. **Event Subscriptions** is On and the **Request URL** field is empty.
3. **Subscribe to bot events** includes at least `app_mention`,
   `message.channels`, and `message.im`.
4. The app has been reinstalled or re-authorized after changing scopes, Socket
   Mode, or Event Subscriptions.
5. `pnpm slack:socket-probe -- --env .env.acme.live --manual-user-id U... --nudge`
   prints `open`, `hello`, observes the bot nudge and human mention envelopes,
   and reports `pass`.
6. `pnpm live:e2e` then sees an OpenClaw-authored thread reply to the
   human-authored mention.

If the raw probe prints Slack's `[WARN] Socket Mode is not turned on.`, Socket
Mode was not saved for the installed app. If it opens and receives `hello` but
observes zero event envelopes after the human posts the prompted mention, Event
Subscriptions were not saved, not enabled, or not applied through reinstall.

## Required Scopes

The app-level token must have:

- `connections:write` for `apps.connections.open` and Socket Mode ingress.

The temporary human user token used by the automated verifier must have this
User Token Scope:

- `chat:write`

The included app manifest declares this under `oauth_config.scopes.user`. It is
only for verifier-authored test posts; if `pnpm slack:user-token-probe` reports
Slack still stored those posts with `bot_id`/`app_id`, use manual human-post
mode for strict acceptance.

App Home must also allow DMs. The manifest sets
`features.app_home.messages_tab_enabled: true` and
`features.app_home.messages_tab_read_only_enabled: false`. If you configured
the Slack app manually or edited it in the UI, go to
**Features -> App Home -> Messages Tab**, enable the Messages tab, leave user
input writable, save changes, and reinstall or re-authorize the app before
testing DMs. Slack's “Bot DMs are not enabled” message means this setting is
missing for the installed app, even when the bot can send DM nudges with
`im:write`.

When you have a Slack configuration/user token with `app_configurations:read`,
verify the installed app manifest directly:

```bash
pnpm slack:manifest-probe -- --env .env.acme.live
```

The probe exports the installed manifest with `apps.manifest.export` and checks
Socket Mode, writable App Home Messages, required bot events, and minimum bot
scopes. It writes `.operant/slack-manifest-probe-report.json`. Slack app and
bot tokens cannot call manifest APIs; Slack's manifest APIs require a
configuration token. Add `app_configurations:write` only if you intentionally
want to update manifests through Slack's manifest APIs.

Minimum bot OAuth scopes for the strict public-channel plus DM acceptance path
with OpenClaw's Slack plugin:

```bash
pnpm slack:scopes
pnpm slack:scopes -- --json
```

- `app_mentions:read`
- `assistant:write`
- `channels:history`
- `channels:join`
- `channels:read`
- `chat:write`
- `im:history`
- `im:read`
- `im:write`
- `reactions:write`

`channels:join` is only optional if an operator always invites the bot manually
with `/invite @Operant`. `im:write` is required by live preflight so it can
verify that `OPERANT_LIVE_DM_CHANNEL_ID` is the bot DM for the allowed test
user.
`assistant:write` is included because OpenClaw's generated Slack setup manifest
requires it for the assistant-owned Slack reply surface and thinking/status
line. `reactions:write` is included so OpenClaw can acknowledge incoming
messages with an emoji reaction. Add `groups:read` when private-channel
metadata or private-channel tests are in scope; OpenClaw may log a channel
resolution warning without it but can still use explicit configured public
channel IDs. Add `users:read` when you want the verifier to confirm that the bot
identity belongs to the same Slack app as the Socket Mode token. Add
`reactions:read` when you want reaction event auditing or reaction
removal/readback coverage. Add `mpim:read`/`mpim:history` only when testing
group DMs.

Minimum bot event subscriptions:

- `app_mention`
- `message.channels`
- `message.im`

Recommended bot event subscriptions for the full OpenClaw Slack manifest:

- `app_home_opened`
- `app_mention`
- `channel_rename`
- `member_joined_channel`
- `member_left_channel`
- `message.channels`
- `message.groups`
- `message.im`
- `message.mpim`
- `reaction_added`
- `reaction_removed`
- `pin_added`
- `pin_removed`

Recommended bot OAuth scopes for full OpenClaw operation and broad Slack feature
coverage:

- `app_mentions:read`
- `assistant:write`
- `channels:history`
- `channels:join`
- `channels:read`
- `chat:write`
- `commands`
- `emoji:read`
- `files:read`
- `files:write`
- `groups:history`
- `groups:read`
- `im:history`
- `im:read`
- `im:write`
- `mpim:history`
- `mpim:read`
- `mpim:write`
- `pins:read`
- `pins:write`
- `reactions:read`
- `reactions:write`
- `usergroups:read`
- `users:read`

`channels:join` is not required if an operator always invites the bot manually
to the public test channel, but it is required for automated
`conversations.join` setup probes. `im:write` is required for
`conversations.open` when the setup probe creates or resumes the allowed-user
DM. If Slack returns `missing_scope`, update the manifest, reinstall or
re-authorize the app in the workspace, and replace the bot token before
rerunning `pnpm live:preflight`.

If Slack messages are visible to the verifier but OpenClaw's `channels status`
still shows `lastInboundAt: null`, Slack is not delivering events to the
configured Socket Mode app. Re-import this manifest, verify Socket Mode and
Event Subscriptions are enabled, confirm the bot events above are present, then
reinstall or re-authorize the app. Passing OAuth checks are not enough here:
`auth.test` can show the right scopes and `apps.connections.open` can return a
Socket Mode URL while also including `response_metadata.messages` warnings such
as `[WARN] Socket Mode is not turned on.` Treat that warning as a hard Slack app
setup failure. The app can also receive no `app_mention` or `message.channels`
envelopes when Event Subscriptions were not saved or the workspace install was
not refreshed.

Use the raw Socket Mode probe to prove event delivery independently of
OpenClaw. Stop the OpenClaw gateway or ensure no other Socket Mode client is
connected, then run:

```bash
pnpm slack:socket-probe -- --env .env --manual-user-id U... --nudge
```

The probe opens Socket Mode directly with the app-level token, rejects Slack's
`Socket Mode is not turned on` warning, posts a copy/paste nudge with the bot
token, acknowledges envelopes, and waits for the human mention event. If it
receives `hello` but no matching event, repair the Slack app manifest/install
before retesting Operant.

Use the DM probe when public-channel mentions work but strict manual acceptance
is waiting for a human-authored DM:

```bash
pnpm slack:dm-probe -- --env .env.acme --live-env .env.acme.live --manual-user-id U... --nudge
```

The probe checks that `OPERANT_LIVE_DM_CHANNEL_ID` is a real IM channel and
that `conversations.open` for the allowed human returns the same channel. It can
post a bot nudge with the exact text to copy, mirror a reminder into the test
channel when `SLACK_CHANNEL_ID` is configured, then wait for a new message from
that human in the Operant DM. Channel reminders are guidance only; the evidence
must be human-authored in the DM. This catches the common cases where the DM
channel belongs to a different user, the bot cannot read the DM, or the full
strict run is simply missing the human DM input. If the human cannot type in
the bot DM, repair App Home Messages first; scopes and `conversations.open`
alone do not make the app's DM input writable.

Temporary human user tokens used only for acceptance testing need enough
user-token permission to post `chat.postMessage` probes. The allowed user must
be a member of the test channel. The allowed token also posts into
`OPERANT_LIVE_DM_CHANNEL_ID`, so that DM must belong to the same human user as
`SLACK_USER_TOKEN`/`OPERANT_LIVE_SLACK_USER_TOKEN`; if you change the allowed
test user, change the DM channel ID too. Live preflight now verifies that the
configured DM channel is the bot DM for that allowed user. A distinct denied
user token is optional; without it, strict acceptance uses the one-human
temporary-deny proof.

Do not store Slack tokens in this repository or in the generated OpenClaw config.
Operant stores them encrypted in Postgres and emits only SecretRefs.

## Live E2E Verification

`pnpm compose:live -- --env .env.acme --live-env .env.acme.live` starts
Compose, seeds Slack/model credentials from the private live env, verifies the
generated OpenClaw config, runs doctor/restart checks, and leaves the
persistent OpenClaw Slack bot running. If you are not using a temporary Slack
user token, add `--manual-slack-posts --manual-user-id U...` so Operant can
seed the allowed human user without automated Slack posts. Keep that stack
running for ordinary mention and DM testing.

The dashboard-first alternative is `pnpm compose:up -- --env .env.acme -d`;
enter Slack/model credentials in the admin dashboard before expecting Slack
mentions or DMs to work.

`pnpm live:e2e` and `pnpm compose:e2e` are finite verifiers. They need
temporary user tokens or manual human Slack posts so they can prove real app
mentions, DMs, denied-policy behavior, approvals, and restart behavior. Keep
those tokens out of Operant configuration; they are only for customer-run
acceptance testing. The verifier writes sanitized report JSON with message
timestamps and probe status but no Slack token values.

For the strict acceptance run, prepare these Slack token classes:

- App-level token: used only for `apps.connections.open`; it must have
  `connections:write` and start with `xapp-`. Slack uses it to issue the
  Socket Mode WebSocket URL that OpenClaw connects to for events and
  interactive payloads.
- Bot token: installed from the manifest below; preflight and live E2E require
  its `auth.test` identity to include `bot_id`, then the verifier uses it for
  `conversations.info`, `conversations.members`, and `conversations.replies`
  while OpenClaw uses it for Slack ingress, thread replies, files, streaming,
  and approvals.
- Temporary allowed user token: used only by the verifier to call `auth.test`
  and post test messages with `chat.postMessage`; it must post in the test
  channel and into the configured DM.
- Optional configuration token: used only by `pnpm slack:manifest-probe` to
  call `apps.manifest.export` and verify the installed app settings. It needs
  `app_configurations:read`; app and bot tokens cannot replace it.
  They must be real human user OAuth tokens, typically starting with `xoxp-` or
  `xoxc-`; do not use a Slack user ID such as `U...`, the bot token `xoxb-...`,
  or the placeholder `<allowed-test-user-token>`.
  Adding `chat:write` under User Token Scopes is only the first step. Generate
  the actual token through Slack OAuth with `user_scope=chat:write`, approve as
  the human Slack user, copy the redirected `code=...`, then exchange it with
  `oauth.v2.user.access`. Put the returned `access_token` in
  `SLACK_USER_TOKEN`. The `redirect_uri` in the authorize URL must exactly
  match a Redirect URL saved under **OAuth & Permissions**; copied spaces, line
  breaks, or a different scheme/host/path cause Slack's `redirect_uri did not
  match any configured URIs` error.
  A distinct denied-user token is optional for two-human testing only; strict
  acceptance defaults to temporarily denying the allowed user and restoring
  policy before approval testing.
  To avoid copying tokens into the terminal output, use
  `pnpm slack:user-token -- --env .env.acme.live --target SLACK_USER_TOKEN --callback-url 'http://localhost:3999/slack/oauth/callback?code=...&state='`
  for the allowed user. Add `--denied` only when you intentionally want the
  optional two-human denied-user proof.
  To create the optional manifest-probe token, authorize with
  `user_scope=app_configurations:read`, then exchange the callback with
  `pnpm slack:user-token -- --env .env.acme.live --target SLACK_CONFIG_TOKEN --callback-url 'http://localhost:3999/slack/oauth/callback?code=...&state='`.
  After saving the allowed user token, run
  `pnpm slack:user-token-probe -- --env .env.acme --live-env .env.acme.live`.
  It posts one diagnostic message with `chat.postMessage` and `as_user=true`,
  reads it back with the bot token, deletes the message by default, and writes
  `.operant/slack-user-token-post-probe-report.json`. If the report says the
  message was app-authored, use manual mode for strict live acceptance.
  Slack's current `chat:write` scope supports user tokens, but some app/token
  combinations still create messages with `bot_id`/`app_id` in the returned
  Slack message object even when `as_user=true` is requested. OpenClaw
  intentionally ignores those app-authored messages to avoid bot loops, so the
  verifier now fails fast with that diagnosis. If you see it, use manual mode
  for live acceptance; manual mode requires real human-authored Slack messages
  and rejects bot/app-authored posts.
  The bot token performs the `conversations.info`, `conversations.members`, and
  `conversations.replies` checks for the configured channel, DM, membership,
  and threads. In optional two-human mode, the denied user should be a member of
  the test channel so Operant policy, rather than Slack membership, suppresses
  the bot reply.

As an alternative to a temporary allowed-human OAuth token, set
`OPERANT_LIVE_MANUAL_SLACK_POSTS=1` and optionally provide
`OPERANT_LIVE_ALLOWED_USER_ID` or pass `--manual-user-id`.
In that mode `pnpm live:e2e` and `pnpm compose:e2e` print the exact mention,
DM, denied-policy, and approval prompts for the allowed human to post in Slack. The verifier
does not call `chat.postMessage` with user tokens; it observes the human posts,
thread replies, DM replies, membership, and approval completion with the bot
token. Manual mode still requires the bot to be invited to `SLACK_CHANNEL_ID`,
the allowed human to be a channel member, and `OPERANT_LIVE_DM_CHANNEL_ID` to be
the bot DM for the allowed human. With nudges enabled, DM prompts also mirror a
channel reminder so the operator can see that the verifier is waiting on a DM,
but only the actual human-authored DM counts as evidence.

The strict denied-policy proof is one-human by default when no distinct denied
user token or ID is configured. The verifier temporarily updates the ephemeral
Compose policy to deny the allowed test user, waits for that same human to post
the denied-policy prompt, proves no Slack thread reply appears, then restores
the original policy before the approval-required probe.
The denied-user probe is a Slack admission-policy check: a channel member denied
by Operant policy should get no Operant thread reply. It is separate from
control-plane RBAC and from tool policies, which can allow, deny, or require
approval for specific tool/action pairs after a Slack request is admitted.
For optional two-human testing, ask the colleague to join the test channel, copy their
Slack member ID, and type only the denied-user prompt when the verifier prints
it. Set `OPERANT_LIVE_DENIED_USER_ID=U_COLLEAGUE_ID` or pass
`--denied-user-id U_COLLEAGUE_ID`. The colleague's message must be a normal
top-level Slack-client message; the correct outcome is no Operant thread reply,
proving policy suppression rather than channel membership failure.
Set `OPERANT_LIVE_MANUAL_SLACK_NUDGE=1` or pass `--manual-slack-nudge` when you
want the bot to post copy/paste reminders in the target channel/DM during manual
mode. Those reminders include the verifier expiry and are only operator
guidance; acceptance still requires messages from the named human Slack users.
Type each prompt directly in the Slack client as that human user. Do not use a
Slack OAuth/user token, webhook, workflow, or API client for manual evidence:
Slack can display a human name while storing `bot_id`/`app_id`, and
Operant/OpenClaw intentionally rejects that app-authored shape to avoid bot
loops.
Runs with a timeout shorter than 30 seconds skip bot-posted nudges so quick
blocked-evidence refreshes do not leave stale prompts in Slack.
The human posts must be made while the verifier command is still running.
Older messages and messages posted after a timeout are intentionally ignored.
Manual runs with Slack nudges post a timeout diagnostic in Slack when the
expected human-authored message is not visible before expiry.
When a probe is run with `--json`, machine-readable JSON stays on stdout and
the human copy/paste prompt is printed on stderr. Keep the terminal visible
during manual runs; the newest printed nonce is the only one accepted.
When a human mention is accepted but no bot reply appears, the live report
includes OpenClaw's Slack inbound status. `lastInboundAt` after the human
message proves Slack delivery worked and moves debugging to OpenClaw execution,
policy, model-provider, or gateway logs; no new inbound timestamp means the
Socket Mode/Event Subscription path still needs fixing.
Live and Compose verifiers archive the previous sanitized JSON evidence under
`.operant/report-archive/` before overwriting the main report path, so reruns do
not erase the prompt-specific artifact needed for Slack debugging.

Manual mode is still a full live OpenClaw acceptance path, not a token-only
preflight. In the strict `pnpm compose:e2e` gate, the human sequence runs once
before Compose restart and once again after Compose restart: channel mention,
DM prompt, denied-user mention with no bot reply or one-human denied-policy
prompt with no bot reply, then the approval prompt plus a human approval click
in Slack. If the verifier times out waiting for one of those manual posts, rerun with a longer `--timeout-ms` and
`--approval-completion-timeout-ms`, or use temporary human user tokens for
automated posting.

Generated Operant config also pins direct OpenAI API-key traffic to OpenClaw's
`pi` agent runtime. OpenClaw's default `openai/gpt-*` routing can select the
Codex harness; Operant avoids that default so the standard live acceptance path
keeps the deep security audit at zero critical findings. If a custom deployment
chooses Codex instead, install and allowlist that harness intentionally and
accept the separate child-process trust boundary.

Create the DM channel for `OPERANT_LIVE_DM_CHANNEL_ID` between the allowed test
user and the bot before final acceptance. Invite the bot to the channel in
`SLACK_CHANNEL_ID`, and keep both test users in that channel. Slack method
permissions can vary by token type and channel type, so run
`pnpm live:preflight -- --env .env.acme --live-env .env.acme.live` before the
full Compose gate; it validates the Socket Mode token, token identities,
workspace consistency, bot channel/DM reachability, the allowed-user DM channel,
and model-key auth without starting Compose.

After Compose starts, strict OpenClaw operator checks may require a paired
operator device before `secrets reload`, exec approvals, or usage-cost can pass.
If the verifier reports `pairing required`, inspect and approve the exact
pending request from the gateway host:

```bash
docker compose exec openclaw-gateway openclaw devices list
docker compose exec openclaw-gateway openclaw devices approve <requestId>
```

`openclaw devices approve --latest` is only a preview; rerun with the exact
request ID after verifying the requested scopes. Expected scopes include
`operator.read`, `operator.approvals`, and `operator.talk.secrets`;
`operator.admin` satisfies them.

Required environment:

```bash
OPERANT_LIVE_ADMIN_SLACK_USER_ID=U...
# Normally supplied by the generated Compose env passed with --env.
# OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_...
SLACK_CHANNEL_ID=C...
SLACK_APP_TOKEN=<slack-app-token>
SLACK_BOT_TOKEN=<slack-bot-token>
SLACK_USER_TOKEN=<xoxp-or-xoxc-allowed-human-user-oauth-token>
OPERANT_LIVE_DM_CHANNEL_ID=D...
# Optional distinct denied user for two-human proof only:
# OPERANT_LIVE_DENIED_USER_TOKEN=<xoxp-or-xoxc-denied-human-user-oauth-token>
# OPERANT_LIVE_DENIED_USER_ID=U...
# Or instead of the allowed user-token line:
# OPERANT_LIVE_MANUAL_SLACK_POSTS=1
# OPERANT_LIVE_MANUAL_SLACK_NUDGE=1
# OPERANT_LIVE_ALLOWED_USER_ID=U...
OPENAI_API_KEY=<model-api-key>
OPERANT_LIVE_APPROVAL_PROMPT='Use the exec tool to run exactly: echo operant-approval'
```

You can start from [live.env.example](live.env.example):

```bash
cp deploy/slack/live.env.example .env.acme.live
```

Fill the private copy with real values, then pass it as a live overlay:

```bash
pnpm live:preflight -- --env .env.acme --live-env .env.acme.live
pnpm live:e2e -- --env .env.acme --live-env .env.acme.live --require-operant-records --require-dm --require-denied-user --require-slack-approval --require-slack-approval-completion
pnpm compose:e2e -- --env .env.acme --live-env .env.acme.live
```

Manual verifier mode uses the same commands with `--manual-slack-posts` and,
when the allowed human is not the admin, `--manual-user-id U...`.
The root aliases `pnpm live:preflight:manual`, `pnpm live:e2e:manual`, and
`pnpm compose:e2e:manual` include the manual Slack-post flags and bot nudge
flag for the common assisted path. The manual `live:e2e` and `compose:e2e`
aliases also set fifteen-minute waits for human Slack posts and approval
completion. If you override them with a shorter `--timeout-ms`, post before the
Slack prompt expiry; messages after the wait window are intentionally ignored.
After the verifier exits or times out, old prompts are inert. Rerun the
verifier and answer the newest prompt, or use the persistent Compose stack for
normal Slack testing.

For a one-command strict handoff, `pnpm live:acceptance` runs live preflight,
strict Compose E2E, completion audit, and final report. The default completion
audit documents this path as optional; set `OPERANT_REQUIRE_STRICT_LIVE=1` when
you want strict live evidence to be mandatory:

```bash
OPERANT_REQUIRE_STRICT_LIVE=1 \
pnpm live:acceptance -- --env .env.acme --live-env .env.acme.live --manual-slack-posts --manual-slack-nudge --manual-user-id U...
```

With no distinct denied user configured, this uses the one-human temporary deny
proof automatically.

For the generated local handoff bundle, the same strict sequence is available
through root aliases backed by tracked scripts:

```bash
pnpm handoff:readiness
pnpm handoff:verify
pnpm live:acceptance:preflight
pnpm live:acceptance
```

When the generated `.operant` handoff bundle exists, these aliases delegate to
`.operant/print-readiness.mjs`, `.operant/verify-handoff.sh`,
`.operant/run-live-acceptance.sh --preflight-only`, and
`.operant/run-live-acceptance.sh`. In a fresh checkout without that ignored
bundle, the readiness alias prints the direct setup path instead of failing on a
missing local file. The live acceptance aliases default to
`.operant/local-acceptance.env` plus `.operant/live-acceptance.env`; override
those paths with `OPERANT_COMPOSE_ENV` and `OPERANT_LIVE_ENV` when targeting
different private env files.

You can also export those values into your shell or merge them into the
generated Compose env file used for `--env .env.acme`. Do not commit the private
copy.

The verifier also accepts `OPERANT_LIVE_SLACK_CHANNEL_ID`,
`OPERANT_LIVE_SLACK_BOT_TOKEN`, and `OPERANT_LIVE_SLACK_USER_TOKEN` instead of
the generic `SLACK_CHANNEL_ID`, `SLACK_BOT_TOKEN`, and `SLACK_USER_TOKEN`
names. The full Compose gate additionally needs `SLACK_APP_TOKEN` or
`OPERANT_LIVE_SLACK_APP_TOKEN` so it can seed the OpenClaw Slack Socket Mode
config through Operant, plus a model key supplied as
`OPERANT_LIVE_MODEL_API_KEY`, `MODEL_API_KEY`, `OPENAI_API_KEY`, or
`ANTHROPIC_API_KEY`. Generic model keys work with any provider; provider-specific
keys are only accepted for the matching `MODEL_PROVIDER`, so Anthropic live
checks require `ANTHROPIC_API_KEY` or a generic model key instead of
`OPENAI_API_KEY`.
Optional policy seed variables `OPERANT_LIVE_ALLOWED_DM_USER_IDS`,
`OPERANT_LIVE_ALLOWED_CHANNEL_IDS`, and `OPERANT_LIVE_APPROVER_SLACK_USER_IDS`
add customer-specific users, channels, and approvers to the credential seed;
the full Compose gate verifies those values in the generated OpenClaw Slack
config. The admin Slack user is always retained as an approval approver so the
strict Operant approval probe can verify persisted approval records even when
customer-specific approvers are also configured.
Optional customer integration credential seed checks can use
`OPERANT_LIVE_INTEGRATION_CREDENTIALS=kind/key=ENV_VAR` entries or
`OPERANT_LIVE_INTEGRATION_CREDENTIALS_JSON` with `kind`, `key`, optional
`label`, and either `secretValueEnv` or `secretValue`. Prefer `secretValueEnv`;
generated acceptance reports redact both referenced env values and inline JSON
secret values before writing evidence.
`pnpm compose:e2e` runs the live preflight automatically before starting
containers in strict live mode. Run `pnpm live:preflight -- --env .env.acme`
separately to check these live variables and expected Slack ID/token prefixes
without starting the full customer acceptance run. The preflight also
rejects a reused allowed/denied Slack user token in automated mode, verifies
the app-level token can open a Socket Mode URL with `apps.connections.open`,
runs Slack `auth.test` for the bot and, when user tokens are used, the
test/denied tokens, verifies bot access to the configured channel and DM with
`conversations.info`, verifies allowed and denied target-channel membership
with `conversations.members`, verifies the bot token's installed OAuth scopes
from Slack's `x-oauth-scopes` response header, verifies optional
`OPERANT_LIVE_BOT_USER_ID` and
`OPERANT_LIVE_DENIED_USER_ID` values against the corresponding Slack
`auth.test` identities when user tokens are available, verifies optional
`OPERANT_LIVE_SLACK_TEAM_ID` or `SLACK_TEAM_ID` values against returned
`team_id` values, and rejects Slack tokens from different workspaces.
`pnpm live:e2e` repeats those identity and team checks before posting Slack
probes in automated mode or waiting for human posts in manual mode, while
rejecting bot tokens used as test-user credentials and allowed/denied tokens
that resolve to the same Slack user. It also verifies OpenAI and Anthropic
model keys through the read-only `/models` endpoint for the
selected provider, and does not print token values. Use `--skip-live-preflight`, `--skip-slack-auth-test`, or
`--skip-model-auth-test` only for offline structural checks; these skips disable
strict completion. Generated redaction/smoke model keys are treated as
placeholders and do not satisfy the live credential gate.

Run with `--require-operant-records --require-dm --require-denied-user
--require-slack-approval --require-slack-approval-completion` for final acceptance so a Slack thread reply alone
does not pass if Operant session/job/usage records fail to move, the DM path is
broken, the denied-user policy still gets a bot reply, or OpenClaw's approval UI
does not appear and continue after a human approver clicks approve. `--require-operant-records`
requires positive session, job, and usage deltas.

Final acceptance probes:

- `OPERANT_LIVE_DM_CHANNEL_ID=D...` posts the same test user's DM to the bot and
  waits for a bot thread reply.
- The denied-policy probe temporarily denies the allowed human by default,
  checks `POST /api/policy/evaluate` returns `deny`, and fails if OpenClaw
  replies in that thread. `OPERANT_LIVE_DENIED_USER_TOKEN` or
  `OPERANT_LIVE_DENIED_USER_ID` switches this to an optional two-human proof.
- `OPERANT_LIVE_APPROVAL_PROMPT` can override the default harmless exec-style
  approval probe. Final Compose E2E waits for OpenClaw's Slack approval UI to
  appear in a bot/OpenClaw-originated thread reply, then waits for a later bot
  reply after a human approver approves in Slack.
