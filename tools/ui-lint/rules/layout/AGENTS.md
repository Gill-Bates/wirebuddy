<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# layout

## Purpose

Layout rules.

## Key Files

| File | Description |
|---|---|
| `form-switch-spacing.mjs` | Helper text stays attached to `.form-switch` rows (max margin 1px) |
| `overflow.mjs` | Horizontal overflow and clipping via `layout-diagnostics.mjs` (rule id `horizontal-overflow`) |
| `settings-logs-layout.mjs` | Settings > Logs metrics row and delete footer spacing |

## For AI Agents

### Testing Requirements

- Covered by `tests/layout/form-switch-spacing.spec.js`, `tests/layout/settings-logs-layout.spec.js`, `tests/overflow/mobile-overflow.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

## Dependencies

### Internal

- `../../lib/layout-diagnostics.mjs`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
