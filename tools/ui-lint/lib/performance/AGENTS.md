<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# performance

## Purpose

Collects page performance data: navigation timing, Web Vitals, memory, scroll performance, and installs PerformanceObservers.

## Key Files

| File | Description |
|---|---|
| `metrics.mjs` | `collectPerformanceMetrics`, `collectNavigationPerformanceMetrics` |
| `observers.mjs` | `installPerformanceObservers` |
| `web-vitals.mjs` | `collectWebVitalsMetrics` |
| `memory.mjs` | `collectMemoryMetrics` (Chromium only) |
| `scroll-performance.mjs` | `collectScrollPerformanceMetrics` |

## For AI Agents

### Working In This Directory

- Gate engine-specific APIs with `../browsers/capabilities.mjs`.

### Testing Requirements

- No dedicated spec under `tests/`; it is exercised indirectly through `run-ui-lint.mjs` (via the `orchestration/audit-runner.mjs` facade). Verify with a real audit run against a running WireBuddy (`npm run audit`, needs `UI_LINT_USERNAME`/`UI_LINT_PASSWORD`).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../browsers/capabilities.mjs`
- `../orchestration/audit-runner.mjs`

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
