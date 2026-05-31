# Changelog

All notable changes to Operant are documented here.
Format inspired by [Keep a Changelog](https://keepachangelog.com).

## [0.5.1] - 2026-05-31

### Documentation
- sharpen the README for OSS, document scheduled workflows, and correct API/contributor docs (7f0b11a)


### Fixed
- harden redaction, gateway-output scrubbing, fetch timeouts, and workflow materialization (3fd83c5)

## [0.5.0] - 2026-05-31

### Added
- governed scheduled workflows (2ef16ba)


### Documentation
- document governed scheduled workflows (v0.5.0) (8cc929d)

## [0.4.0] - 2026-05-30

### Added
- governed team memory + skills store (20e0e6c)


### Documentation
- document governed memory + skills (v0.4.0) (942711f)


### Fixed
- upgrade the Operant plugin in place on reused state volumes (8d5a49b)

## [0.3.1] - 2026-05-30

### Documentation
- reflect dual-identity Pipedream policy and Teams audit attribution (9537456)


### Fixed
- enforce per-user Pipedream policy by principal and attribute Teams actors correctly (4661dfc)

## [0.3.0] - 2026-05-30

### Added
- Add login rate limiting to blunt admin-token brute-force (62bb715)
- Add per-user cost attribution and daily trend to the FinOps dashboard (a5d85e9)
- Add Teams dual-identity schema (migrations 009-011) + widen channel-policy upsert (a405fe8)
- Add Teams identifier schemas and optional dual-identity record fields (df38b17)
- Add Microsoft Teams as a dual-identity chat platform (control plane) (ff0559b)
- Add Teams to the dashboard (login, setup, policy, people) (7da7912)


### Chore
- add GitHub community health files (46a828a)


### Documentation
- Document the Pipedream sub-processor boundary and audit semantics (0e36957)
- Document Teams in the API reference and project guidance (3e2decc)
- align the README, docs, and project guidance with the Teams release (e0a5556)


### Fixed
- Fix Pipedream connect-token mint to project-scoped path (54f17b8)
- Fix dashboard E2E Pipedream stub to project-scoped connect-token path (bd5f3f5)
- close redaction gaps, bound the plugin's control-plane fetch, and harden Teams user upsert (2c0ec52)


### Other
- Update agent guidance (293e34e)
- Close verified Pipedream governance gaps (connect authz + wipe revocation) (5caf6b6)
- Record the Slack chat principal on Pipedream audit rows (72b1bac)
- Disclose Pipedream as a sub-processor at connect time (08a082c)
- Make the policy engine dual-identity (Slack + Teams) (b7013d6)
- Wire Teams into deploy, scripts, env, and docs (b94f8b5)
- Make Teams first-class in the README marketing; drop em-dashes (a86aef6)

## [0.2.0] - 2026-05-22

### Added
- Add one-click Slack app creation link (f0cd007)
- Add real-workspace screenshot to README (1fcf6bd)
- Add Unreleased section, strip dead commit hashes (5e92b64)
- Add self-serve Pipedream marketplace (4f578b3)


### Fixed
- Fix CI: let pnpm/action-setup pick version from packageManager (dccfa15)


### Other
- Rewrite README from first principles for accuracy and clarity (c723fb4)
- Polish for public-release flip (a272cde)
- Smooth the first-time install path (edc62d5)
- Reposition as 'self-hosted agents in Slack' (fc70e9a)
- Close quickstart gap after compose:up (a1c9b8e)
- Release v0.2.0 (14685cd)

## [0.1.0] - 2026-05-19

### Other
- Initial commit (49064d5)


