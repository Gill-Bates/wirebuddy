<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# console

## Purpose

Console message noise control: an allowlist of ignorable messages, filtering helper and a severity scorer.

## Key Files

| File | Description |
|---|---|
| `allowlist.mjs` | `CONSOLE_ALLOWLIST` regex list (e.g. ResizeObserver loop, favicon load failures) |
| `filters.mjs` | `filterConsoleEntries(entries, allowlist)` |
| `severity.mjs` | `CONSOLE_SEVERITY` weights and `scoreConsoleSeverity` |

## For AI Agents

### Working In This Directory

- Add allowlist entries only for verified benign browser noise; every entry hides findings.

### Testing Requirements

- Covered by `tests/audit-helpers.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

## Dependencies

### Internal

- `../orchestration/audit-runner.mjs`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
