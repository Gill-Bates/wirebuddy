<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# auth

## Purpose

Logs into WireBuddy and bootstraps an authenticated session.

## Key Files

| File | Description |
|---|---|
| `login-flow.mjs` | `performLogin`, `detectLoginFailure` |
| `auth-state.mjs` | `bootstrapAuthenticatedSession`, `applyTheme` |
| `credential-validation.mjs` | `validateCredentials` |

## For AI Agents

### Working In This Directory

- Credentials come from `UI_LINT_USERNAME`/`UI_LINT_PASSWORD`; never log or persist them.

### Testing Requirements

- Covered by `tests/run-ui-lint.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- No special constraints beyond the parent directory guidance.

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
