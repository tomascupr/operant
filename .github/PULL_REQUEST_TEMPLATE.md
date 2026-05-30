## Summary

<!-- What does this change and why? Link the issue it addresses. -->

Closes #

## Checklist

- [ ] `pnpm typecheck` passes
- [ ] `pnpm test` passes (builds `@operant/control-plane` and `@operant/openclaw-plugin`, then runs `node:test`)
- [ ] New behavior has a `node:test` test under `apps/control-plane/tests/` or `apps/openclaw-plugin/tests/`
- [ ] Any new migration is append-only (`apps/control-plane/migrations/NNN_*.sql`, next number; no rewrites of applied migrations)
- [ ] Dashboard changes stay vanilla JS with no external scripts or bundler (strict same-origin CSP preserved)
- [ ] No secrets, real Slack/Teams tokens, or production credentials in the diff

## Notes for reviewers

<!-- Anything tricky, follow-ups, or things you want a second opinion on. -->
