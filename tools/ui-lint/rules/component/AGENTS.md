<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# component

## Purpose

Component-level rules.

## Key Files

| File | Description |
|---|---|
| `changelog-details.mjs` | About changelog keeps `<details>`/`<summary>` disclosure semantics |
| `dashboard-light-surfaces.mjs` | Dashboard KPI cards use a light surface in the light theme (luminance limit 0.18) |

## For AI Agents

### Testing Requirements

- Covered by `tests/component/changelog-details.spec.js`, `tests/component/dashboard-light-surfaces.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

## Dependencies

### Internal

- `../../lib/rule-registry.mjs`
- `../manifest.mjs` (entry required)

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
