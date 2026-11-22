<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# policies

## Purpose

Declarative finding policies per area: each `build*Policy` returns rules that turn audit results into findings.

## Key Files

| File | Description |
|---|---|
| `index.mjs` | `buildFindingPolicies` aggregates all policies |
| `accessibility-policy.mjs` | `buildAccessibilityPolicy` |
| `dashboard-policy.mjs` | `buildDashboardPolicy` |
| `layout-policy.mjs` | `buildLayoutPolicy` (largest; button height, form switch spacing, overflow) |
| `network-policy.mjs` | `buildNetworkPolicy` |
| `users-policy.mjs` | `buildUsersPolicy` |
| `visual-policy.mjs` | `buildVisualPolicy` |

## For AI Agents

### Working In This Directory

- Add new policies to `index.mjs`; scope predicates come from `../scopes/`.

### Testing Requirements

- Covered by `tests/findings/layout-policy.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

## Dependencies

### Internal

- `../scopes/`, `../../config/`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
