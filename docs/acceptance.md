# Operant Acceptance Guide

This guide covers the live verifiers and strict acceptance gates for customer
acceptance packages. For normal evaluation and operator setup, start with
[setup.md](setup.md); only come back here when you need live evidence.

## Live Env Overlay

Start the private live overlay from the template:

```bash
cp deploy/slack/live.env.example .env.acme.live
```

Keep real Slack/model tokens out of git. The generated Compose env passed with
`--env` supplies generated stack secrets such as `OPERANT_ADMIN_LOGIN_TOKEN`;
keep that value commented in the live overlay unless intentionally overriding
the stack env.

For a live Slack/OpenClaw check:

```bash
# compose:live only brings up the stack; it skips the live + post-restart gates run by the verifiers below.
pnpm compose:live -- --env .env.acme --live-env .env.acme.live
pnpm live:preflight -- --env .env.acme --live-env .env.acme.live
pnpm live:e2e -- --env .env.acme --live-env .env.acme.live --require-operant-records --require-dm --require-denied-user --require-slack-approval --require-slack-approval-completion
pnpm compose:e2e -- --env .env.acme --live-env .env.acme.live
```

If you are using manual human Slack posts instead of temporary human user
tokens, use the manual aliases:

```bash
pnpm live:preflight:manual -- --env .env.acme --live-env .env.acme.live --manual-user-id U...
pnpm compose:e2e:manual -- --env .env.acme --live-env .env.acme.live --manual-user-id U...
```

For the full strict handoff in one command, use the live-acceptance wrapper.
The default completion audit documents this path as optional; set
`OPERANT_REQUIRE_STRICT_LIVE=1` when you want strict live evidence to be
mandatory:

```bash
OPERANT_REQUIRE_STRICT_LIVE=1 \
pnpm live:acceptance -- --env .env.acme --live-env .env.acme.live --manual-slack-posts --manual-slack-nudge --manual-user-id U...
```

The denied-policy proof does not require a second human account. If no distinct
denied user token or ID is configured, the verifier temporarily denies the allowed
human, proves no reply, then restores policy before the approval probe.

The manual `live:e2e` and `compose:e2e` aliases use fifteen-minute waits for
human Slack posts and approval completion. If you override them with a shorter
`--timeout-ms`, post before the Slack prompt expiry; the verifier intentionally
ignores messages that arrive after its wait window closes.

Do not treat a verifier prompt as a persistent bot session. `pnpm live:e2e` and
`pnpm compose:e2e` are finite probes that exit after success, timeout, or a
blocked result. After the verifier exits or times out, replying to an old Slack
prompt will not produce a bot response. For ordinary Slack testing, keep either
`pnpm compose:up -- --env .env.acme -d` after dashboard setup or
`pnpm compose:live -- --env .env.acme --live-env .env.acme.live` running, then
post a fresh mention or DM.

Shell-export alternative when not using `--live-env`:

```bash
export OPERANT_LIVE_ADMIN_SLACK_USER_ID=U...
# Normally supplied by the generated Compose env passed with --env.
# export OPERANT_ADMIN_LOGIN_TOKEN=operant_admin_...
export SLACK_CHANNEL_ID=C...
export SLACK_APP_TOKEN=<slack-app-token>
export SLACK_BOT_TOKEN=<slack-bot-token>
export SLACK_USER_TOKEN=<xoxp-or-xoxc-allowed-human-user-oauth-token>
export OPERANT_LIVE_DM_CHANNEL_ID=D...
# Optional two-human denied-policy proof only:
# export OPERANT_LIVE_DENIED_USER_TOKEN=<xoxp-or-xoxc-denied-human-user-oauth-token>
export OPENAI_API_KEY=<model-api-key>
pnpm compose:e2e -- --env .env.acme
```

## Human Verifier Tokens

Use a temporary human Slack user token for `SLACK_USER_TOKEN`, not the bot
token. The live verifier uses that token only for `auth.test` and
`chat.postMessage`. It must be a real human user OAuth token, typically
starting with `xoxp-` or `xoxc-`. Do not put a Slack user ID such as `U...`,
the bot token `xoxb-...`, or the placeholder `<allowed-test-user-token>` in
`SLACK_USER_TOKEN`. The allowed user must be a member of the test channel and
must own the DM configured as `OPERANT_LIVE_DM_CHANNEL_ID`.

The included Slack app manifest declares `chat:write` under User Token Scopes,
but that does not create the token by itself. If you configured Slack manually,
add `chat:write` under **OAuth & Permissions -> User Token Scopes**. To generate
a temporary human user token, add a Redirect URL such as
`http://localhost:3999/slack/oauth/callback`, save it, then open Slack OAuth
with the app client ID:

```text
https://slack.com/oauth/v2/authorize?client_id=CLIENT_ID&user_scope=chat:write&redirect_uri=http%3A%2F%2Flocalhost%3A3999%2Fslack%2Foauth%2Fcallback
```

Approve as the human Slack user that should post verifier messages. Slack
redirects to localhost; the page may fail to load, but the address bar includes
`code=...`. Exchange that code for the user token:

```bash
curl -sS -u 'CLIENT_ID:CLIENT_SECRET' \
  -d 'code=PASTE_CODE_HERE' \
  -d 'redirect_uri=http://localhost:3999/slack/oauth/callback' \
  https://slack.com/api/oauth.v2.user.access
```

Or use the built-in helper, which reads `SLACK_CLIENT_ID` and
`SLACK_CLIENT_SECRET` from the env file, exchanges the code, verifies the
returned token with Slack `auth.test`, and saves the access token without
printing it:

```bash
pnpm slack:user-token -- --env .env.acme.live --target SLACK_USER_TOKEN --callback-url 'http://localhost:3999/slack/oauth/callback?code=...&state='
# Optional two-human proof only:
# pnpm slack:user-token -- --env .env.acme.live --denied --callback-url 'http://localhost:3999/slack/oauth/callback?code=...&state='
# Optional installed-manifest probe only:
# authorize with user_scope=app_configurations:read, then:
# pnpm slack:user-token -- --env .env.acme.live --target SLACK_CONFIG_TOKEN --callback-url 'http://localhost:3999/slack/oauth/callback?code=...&state='
```

After saving the allowed user token, verify the actual authorship shape before
a long strict run:

```bash
pnpm slack:user-token-probe -- --env .env.acme --live-env .env.acme.live
```

The probe posts one diagnostic message with `chat.postMessage` and
`as_user=true`, reads it back with the bot token, deletes it by default, and writes
`.operant/slack-user-token-post-probe-report.json`. If it reports
app-authored output, use manual mode because OpenClaw intentionally ignores
bot/app-authored Slack messages to prevent loops.

If you use `curl`, copy the returned `access_token` into `SLACK_USER_TOKEN`.
If you use the helper, it writes the selected env var directly. Verify it with
`pnpm live:preflight -- --env .env.acme --live-env .env.acme.live`; Slack
`invalid_auth` means the value is not a usable user OAuth token. A second human
token is optional only when you intentionally want a colleague-backed
two-human proof.
Slack `redirect_uri did not match any configured URIs` means the URL in
`redirect_uri` was not saved exactly in the app, or the URL contains a copied
space or line break. If Slack refuses to save an `http://localhost...` URL, use
an HTTPS placeholder such as `https://localhost/slack/oauth/callback` and use
that same value in both the authorize URL and `oauth.v2.user.access` exchange.

Slack `auth.test` can resolve a token to a human user while `chat.postMessage`
still creates an app-authored message carrying `bot_id` or `app_id`, even when
the verifier requests `as_user=true`. OpenClaw ignores app-authored messages to
avoid bot loops, so the live verifier rejects that output immediately instead of
waiting for a reply that will never come. If that happens, use manual mode; it
waits for real human-authored Slack messages and also rejects bot/app-authored
posts.

The bot token handles `auth.test`, `conversations.open`,
`conversations.info`, `conversations.members`, and `conversations.replies`
checks for the configured channel, allowed-user DM, channel membership, and
threads. `OPERANT_LIVE_DM_CHANNEL_ID` must be the bot DM for the allowed test
user; live preflight verifies that relationship without printing token values.
By default, the strict verifier temporarily updates the ephemeral Compose policy
to deny the allowed test user, proves that the denied mention gets no bot reply,
and restores the original policy before the approval-required probe. For an
optional two-human proof, set `OPERANT_LIVE_DENIED_USER_ID` or provide
`OPERANT_LIVE_DENIED_USER_TOKEN`; that distinct denied user must already be a
member of the test channel so Operant policy, not Slack membership, suppresses
the bot reply.

Optional identity checks use `OPERANT_LIVE_BOT_USER_ID` and
`OPERANT_LIVE_DENIED_USER_ID` against Slack `auth.test`.

## Manual Human-Post Mode

If you do not want temporary human user OAuth tokens, use manual mode:

```bash
export OPERANT_LIVE_MANUAL_SLACK_POSTS=1
export OPERANT_LIVE_MANUAL_SLACK_NUDGE=1
export OPERANT_LIVE_ALLOWED_USER_ID=U...
# One-human temporary-deny proof is the default when no distinct denied user is configured.
# Optional two-human proof only:
# export OPERANT_LIVE_DENIED_USER_ID=U...
pnpm compose:e2e:manual -- --env .env.acme --live-env .env.acme.live --manual-user-id U...
```

Manual mode still performs the same live OpenClaw run. The verifier prints the
mention, DM, denied-user, and approval prompts, including Slack client links
when the workspace team ID is available. Humans post them in Slack, and the bot
token observes the messages, thread replies, DM replies, membership, and
approval completion with Slack read APIs. Bot-authored nudges are never accepted
as evidence. DM prompts also mirror a reminder into the configured test channel
when nudges are enabled, but the evidence still has to be posted in the Operant
DM. If Slack says bot DMs are not enabled, enable App Home Messages for the
installed app, keep the messages tab writable, reinstall or re-authorize, and
rerun the verifier with a fresh nonce. Type the prompt directly in the Slack
client as the named human user; do not send it through OAuth/user-token
automation, webhooks, workflows, or API
clients. Slack can display a human name while still storing `bot_id` or
`app_id`, and the verifier rejects that app-authored shape because OpenClaw will
ignore it to avoid bot loops. The manual root aliases default to fifteen-minute
waits for human posts and approval completion. Bot-authored nudges include an
expiry, and runs with a timeout shorter than 30 seconds skip Slack nudges to
avoid stale prompts. The human posts must happen while the verifier command is
running; older messages and messages posted after a timeout are intentionally
ignored. Manual runs with Slack nudges post a timeout diagnostic in Slack when
the expected human-authored message is not visible before expiry.
If a channel mention is accepted but no thread reply appears, the live report
records whether OpenClaw saw a Slack inbound event after the human message. No
inbound event means Socket Mode/Event Subscription delivery is still broken;
inbound-without-reply means Slack delivery worked and the next place to inspect
is OpenClaw execution, policy, model-provider, or gateway logs.
Before replacing `.operant/live-e2e-report.json`,
`.operant/live-e2e-post-restart-report.json`, or the Compose E2E report, the
verifier archives the previous sanitized JSON under `.operant/report-archive/`
so the exact evidence for a failed prompt is not lost by a later rerun.

The denied-user proof exercises Slack admission policy: a user who is a member
of the target channel but denied by Operant policy should receive no Operant
thread reply. This is separate from RBAC for the admin/control-plane UI and from
tool policies, which can allow, deny, or require approval for a specific
tool/action after a Slack request has been admitted.

The default proof is one-human: Operant temporarily denies the allowed Slack
user for one probe, verifies no reply, then restores policy. To optionally use
a colleague instead, ask them to join the test channel, copy their Slack member
ID, and type only the denied-user prompt when the verifier prints it. Set
`OPERANT_LIVE_DENIED_USER_ID=U_COLLEAGUE_ID` or pass
`--denied-user-id U_COLLEAGUE_ID`. The colleague must post the prompt directly
in the Slack client as a normal top-level channel message. The expected result
is no Operant thread reply, proving policy suppression rather than channel
membership failure.

Before a long manual strict run, use the targeted DM probe when changing the
allowed test user or DM channel:

```bash
pnpm slack:dm-probe -- --env .env.acme --live-env .env.acme.live --manual-user-id U... --nudge --timeout-ms 300000
```

When a probe is run with `--json`, machine-readable JSON stays on stdout and
the human copy/paste prompt is printed on stderr. Keep the terminal visible
during manual runs; the newest printed nonce is the only one accepted.

A complete `pnpm compose:e2e` manual strict run needs this sequence once before
Compose restart and once again after Compose restart:

1. The allowed human posts the exact channel mention printed by the verifier.
2. The allowed human posts the exact DM prompt printed by the verifier.
3. The allowed human posts the denied-policy prompt after the verifier
   temporarily denies that user, and the verifier observes no bot reply. In the
   optional two-human mode, the configured colleague posts the denied-user
   channel mention instead.
4. The allowed human posts the approval prompt, then an approver clicks approve
   in Slack so the verifier observes the post-approval bot reply.

## Acceptance Gates

Non-live runtime smoke:

```bash
pnpm compose:smoke -- --env .env.acme --profile queue --allow-blocked --down --down-volumes
pnpm compose:smoke:sandbox -- --env .env.acme
```

`--down-volumes` is destructive. The Compose E2E harness refuses that flag
unless the selected env file sets a non-default `OPERANT_COMPOSE_PROJECT_NAME`
and any `COMPOSE_PROJECT_NAME` override matches it.

Strict final gate:

```bash
pnpm compose:e2e -- --env .env.acme --live-env .env.acme.live
pnpm audit:completion
pnpm report:final
```

The strict final gate requires the Operant approval probe, DM probe,
denied-user no-reply probe, positive session/job/usage deltas, OpenClaw Slack
approval UI probe, and post-approval bot reply after the human Slack approval
click. Use `--skip-approval-probe`, `--skip-dm-probe`,
`--skip-denied-user-probe`, `--skip-slack-approval-probe`, or
`--skip-slack-approval-completion` only for interim debugging.

`--require-operant-records` requires positive deltas for sessions, jobs, and
usage. `--require-dm`, `--require-denied-user`, `--require-slack-approval`, and
`--require-slack-approval-completion` keep the live verifier from accepting a
partial Slack thread reply as final acceptance.

## Microsoft Teams Acceptance

Teams v1 acceptance is manual and human-observed, not an automated verifier like
the Slack live gates. The script prints a checklist for a human to follow.

1. Copy `deploy/teams/live.env.example` to a private, gitignored live env file
   (for example `.env.acme.teams.live`); never commit real Teams credentials.

   ```bash
   cp deploy/teams/live.env.example .env.acme.teams.live
   ```

   The keys are `TEAMS_APP_ID`, `TEAMS_APP_PASSWORD`, `TEAMS_TENANT_ID`,
   `MSTEAMS_PUBLIC_MESSAGING_ENDPOINT`, `OPERANT_LIVE_TEAMS_ALLOWED_AAD_USER_ID`,
   `OPERANT_LIVE_TEAMS_APPROVER_AAD_USER_ID`, `OPERANT_LIVE_TEAMS_TEAM_ID`,
   `OPERANT_LIVE_TEAMS_CHANNEL_ID`, and `OPERANT_LIVE_TEAMS_DM_CONVERSATION_ID`
   (plus optional `*_PROMPT` overrides).

2. Print the manual checklist and the required live-env keys, then exit:

   ```bash
   pnpm teams:live:preflight
   ```

3. With a stack running and Teams credentials saved, expose the OpenClaw Teams
   webhook over HTTPS (the Azure Bot Messaging Endpoint pointing at the gateway),
   then run the manual acceptance:

   ```bash
   pnpm teams:live:e2e:manual
   ```

   The manual alias passes `--manual-posts`; plain `pnpm teams:live:e2e` exits
   because v1 acceptance is manual.

The verifier takes no `--env`/`--live-env` flags, so load the live env into the
shell environment instead of passing it on the command line.

Per the checklist, the human exercises a Teams DM and an allowlisted channel
mention, runs OpenClaw `channels status --probe --json`, syncs Operant
observations to confirm session/job/usage deltas, and exercises an
approval-required prompt to confirm Operant approval records plus a
human-observed Teams reply.
