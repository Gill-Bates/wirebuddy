<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# scopes

## Purpose

Predicates deciding whether an audit entry belongs to a page scope (route/device).

## Key Files

| File | Description |
|---|---|
| `dashboard.mjs` | `isDashboardScope`, `isMobileDashboardScope` |
| `status.mjs` | `isStatusScope`, `isExpectedStatusUnavailable` |
| `users.mjs` | `isUsersScope`, `isMobileUsersScope` |

## For AI Agents

### Working In This Directory

- No special constraints beyond the parent directory guidance.

### Testing Requirements

- Covered by `tests/findings/layout-policy.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- Used by `../policies/`

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
