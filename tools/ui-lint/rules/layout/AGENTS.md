<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
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

### Working In This Directory

- No special constraints beyond the parent directory guidance.

### Testing Requirements

- Covered by `tests/layout/form-switch-spacing.spec.js`, `tests/layout/settings-logs-layout.spec.js`, `tests/overflow/mobile-overflow.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- Header comment `// Rule: ...`; `meta` object + `registerRule`.

## Dependencies

### Internal

- `../../lib/layout-diagnostics.mjs`

### External

- None

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
