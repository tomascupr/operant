# Microsoft Teams App Setup

Operant reuses OpenClaw's `msteams` channel. Do not run a Bot Framework
handler in Operant; configure Azure Bot Service to deliver messages to the
OpenClaw gateway webhook.

## Azure Bot

1. Create or reuse an Azure Bot registration.
2. Copy the app/client ID, tenant ID, and client secret into Operant's dashboard
   Teams setup fields or a private live env file.
3. Expose the gateway webhook over HTTPS. In Compose the internal webhook port
   is `3978`, published as `MSTEAMS_WEBHOOK_HOST_PORT`; use your own reverse
   proxy or tunnel.
4. Set the Azure Bot **Messaging endpoint** to:

```text
https://<your-public-host>/api/messages
```

Operant does not bundle a tunnel provider.

## Teams App Package

Use `manifest.json` as the starting package manifest. Replace both placeholder
UUIDs with the Azure Bot app/client ID, then zip:

```bash
cd deploy/teams
zip -r operant-teams-app.zip manifest.json color.png outline.png
```

The v1 package declares personal, team, and group chat bot scopes. RSC
permissions are limited to text parity: channel/chat message read, channel
message send, member/owner reads, and team/channel settings reads. File history,
SharePoint retrieval, proactive tenant install, and Graph-heavy history sync are
out of scope for v1.

## Live Check

Copy `live.env.example` to a private file, start Operant, then post both:

- A direct message to the Operant bot.
- A channel message that mentions the bot in an allowed team/channel.

After posting, run OpenClaw status probes and Operant observation sync from the
dashboard or CLI. Acceptance requires a human-observed Teams reply plus Operant
session/job/usage deltas and approval records when the approval prompt path is
tested.

