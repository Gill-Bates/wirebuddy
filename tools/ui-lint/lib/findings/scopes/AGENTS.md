<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# scopes

## Purpose

Predicates deciding whether an audit entry belongs to a page scope (route/device).

## Key Files

| File | Description |
|---|---|
| `dashboard.mjs` | `isDashboardScope`, `isMobileDashboardScope` |
| `status.mjs` | `isExpectedStatusUnavailable` |
| `users.mjs` | `isUsersScope`, `isMobileUsersScope` |

## For AI Agents

### Testing Requirements

- Covered by `tests/findings/layout-policy.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

## Dependencies

### Internal

- Used by `../policies/`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
