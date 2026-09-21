<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# dom

## Purpose

DOM mutation-stability observer injected into pages and a classifier for mutation bursts.

## Key Files

| File | Description |
|---|---|
| `mutation-observer.mjs` | `installDOMStabilityObserver(context)` (init script, state under `Symbol.for('uiLint.runtime')`) and `collectDOMStabilityMetrics` |
| `stability.mjs` | `classifyMutationSeverity(stats)` -> blocking/serious/... by burst and reconnect counts |

## For AI Agents

### Working In This Directory

- No special constraints beyond the parent directory guidance.

### Testing Requirements

- Covered by `tests/orchestration/audit-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../orchestration/audit-runner.mjs`

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
