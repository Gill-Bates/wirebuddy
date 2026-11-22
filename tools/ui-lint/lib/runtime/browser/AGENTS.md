<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# browser

## Purpose

Browser launch, context options, navigation settling and session objects.

## Key Files

| File | Description |
|---|---|
| `launcher.mjs` | `BrowserAdapters`, `getBrowserLauncher` |
| `context.mjs` | `createBrowserContextOptions` |
| `navigation.mjs` | `waitForNavigationSettled`, `waitForVisualStability` |
| `session.mjs` | `createBrowserSession` |

## For AI Agents

### Testing Requirements

- Covered by `tests/run-ui-lint.spec.js`, `tests/orchestration/audit-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
