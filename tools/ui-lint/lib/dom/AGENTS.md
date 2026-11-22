<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# dom

## Purpose

DOM mutation-stability observer injected into pages and a classifier for mutation bursts.

## Key Files

| File | Description |
|---|---|
| `mutation-observer.mjs` | `installDOMStabilityObserver(context)` (init script, state under `Symbol.for('uiLint.runtime')`) and `collectDOMStabilityMetrics` |
| `stability.mjs` | `classifyMutationSeverity(stats)` -> blocking/serious/... by burst and reconnect counts |

## For AI Agents

### Testing Requirements

- Covered by `tests/orchestration/audit-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

## Dependencies

### Internal

- `../orchestration/audit-runner.mjs`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
