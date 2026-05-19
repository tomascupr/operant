# Changelog

All notable changes to Operant are documented here.
Format inspired by [Keep a Changelog](https://keepachangelog.com).

## [0.1.0] - 2026-05-19

### Added
- Add manual Slack live verification path (2eba764)
- Add assisted manual Slack prompts (6eff527)
- Add raw Slack probe to final handoff (6bd8fcc)
- Add manual live acceptance aliases (cb6c38f)
- Add Slack links to manual verifier prompts (6fed6c8)
- Add Slack user token exchange helper (216db72)
- Add Slack user token authorship probe (b3dcdb2)
- Add one-human Slack denied-policy verifier mode (6e7ee27)
- Add persistent live Compose startup (4bb5f24)
- Add scoped OpenClaw tool entitlements (62311d2)
- Add Slack installed manifest probe (0384559)
- Add /internal/plugin/* endpoints and OperantClient (0c7e722)
- Add PipedreamClient for Pipedream Connect MCP (e7ed8c4)
- Add Pipedream catalog and tool factories (dbc9cfa)
- Add Pipedream dashboard diagnostics (1ba80de)
- Add control plane dashboard refresh (14772d2)


### Changed
- Always allowlist Operant plugin tools in generated OpenClaw config (0ee4548)
- Move typebox from devDependencies to dependencies (8d192c1)
- Send Pipedream MCP required headers (project, environment, app slug) (841bbde)
- Force JSON responses from Pipedream MCP (drop SSE from accept) (76a6871)
- Parse Pipedream SSE responses end-to-end (5954dc8)
- Restructure docs for first-time evaluators (3c2b0dc)


### Documentation
- Document Slack scope guard verification (4941394)
- Document live Slack prerequisite check (97f2ef6)
- Document Operant setup and fix OpenClaw sync (043d8bd)
- Document live DM history blocker (d91ef7d)
- Document latest manual Slack blocker (da5647d)
- Document Slack App Home DM requirement (5cbef21)
- Document manual JSON prompt output (7855e34)
- Document Pipedream Connect plugin + sanitize plugin client errors (d7846ad)


### Fixed
- Fix OpenClaw OpenAI runtime routing (b922ed8)
- Fix Slack live diagnostics and OpenClaw compose setup (32baf5c)
- Fix gateway build and bootstrap-aware dashboard sign-in (224eaaa)


### Other
- Initial Operant control plane (693a613)
- Update live acceptance evidence docs (7356c9d)
- Make final report preserve failed live gaps (cd3f43d)
- Fail live preflight on missing Slack bot scopes (ecaad1b)
- Share Slack scope contract across verifiers (a971b82)
- Improve dashboard responsive safeguards (b274d4b)
- Classify Slack scope preflight as blocked (ac4856f)
- Cover Slack scope blocker classification (8986568)
- Clarify live Slack acceptance blocker (e92d6d3)
- Track live handoff helper aliases (e9f9e5c)
- Polish fresh checkout handoff helper (35a505b)
- Cover fresh checkout handoff helper (6517511)
- Verify dashboard admin setup fields (a754f18)
- Detect disabled Slack Socket Mode during preflight (41b9345)
- Classify manual Slack acceptance as blocked (4140726)
- Update live acceptance status docs (8606ed8)
- Clarify manual live acceptance restart flow (6ea1cf5)
- Update live Slack acceptance evidence (dd5fa9f)
- Validate live Slack DM preflight (0d40130)
- Update live DM acceptance evidence (931f7ed)
- Polish Operant docs and Slack DM probe (f76b93a)
- Record targeted Slack DM probe evidence (f8e5c89)
- Write Slack DM probe evidence report (072609f)
- Include Slack DM probe in final report (b5a4e3d)
- Report automated Slack token probe evidence (1521fe9)
- Clarify Slack verifier user tokens (448d2b9)
- Polish OSS README (a78b31c)
- Refresh live evidence handoff (24c543c)
- Nonce post-restart Slack verifier prompts (1c2c811)
- Clarify Slack verifier OAuth setup (15b27f6)
- Clarify manual Slack verifier nudges (509e443)
- Detect app-authored Slack verifier posts (7136a3a)
- Isolate local acceptance evidence (36511c2)
- Improve manual Slack E2E diagnostics (ab13ce8)
- Improve live Slack troubleshooting evidence (30115ff)
- Archive live verifier reports before overwrite (d507ef1)
- Clarify manual Slack verifier prompts (43de59a)
- Request Slack user-authored verifier posts (83f2806)
- Make manual Slack verification less brittle (1434dd0)
- Default manual Slack timeout in verifier (bed879a)
- Declare Slack verifier user scope (50a2657)
- Extend manual Slack verifier window (2af5623)
- Explain missed manual Slack prompts (4256565)
- Cover integration credentials in synthetic smoke (36b846e)
- Clarify persistent Slack bot run mode (63ff97b)
- Support one-human live acceptance handoff (fe1ee98)
- Clarify manual Slack live acceptance (19c3015)
- Polish live handoff verification (81c2d6d)
- Default live acceptance to one human (4e5d184)
- Clarify manual DM acceptance nudges (fed2bf4)
- Clarify generic Slack setup docs (89aedb7)
- Show DM probe prompt in JSON mode (b407a62)
- Record latest Slack DM probe evidence (11def9d)
- Make strict live Slack evidence opt-in for completion audit (3b716ea)
- Scope integration credentials per Slack user (96b06d6)
- Wire per-user integration credentials into dashboard and docs (5bec7c5)
- Scaffold @operant/openclaw-plugin workspace (97760b4)
- Install operant plugin into the OpenClaw gateway image (e68924a)
- Constrain dashboard role and model-provider inputs to dropdowns (1dccd5d)
- Generated OpenClaw config now passes config-validate for Anthropic (aceca86)
- Pre-fill credential form and let saved secrets stay hidden (feef12d)
- Declare tool contract + per-session activation on plugin manifest (1dd9f5f)
- Require app slug on pipedream_list_actions; drop catalog (086cff6)
- Bump OpenClaw to 2026.5.18 and add launch-prep scaffolding (0b23ac2)


### Security
- Harden live Compose OpenClaw checks (38a5040)
- Harden live Slack verifier polling (0781069)
- Harden live Slack verifier blockers (96a417d)
- Harden handoff verification for stale live reports (ae6b1e3)
- Harden control plane release blockers (171fced)


