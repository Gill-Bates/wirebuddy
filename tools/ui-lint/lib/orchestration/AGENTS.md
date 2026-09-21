<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# orchestration

## Purpose

Facade and small runner for the extended audits: re-exports console, axe, performance, font, SSIM, DOM-stability and browser modules, and runs axe/performance/font audits together.

## Key Files

| File | Description |
|---|---|
| `audit-runner.mjs` | Re-export hub plus `runExtendedAudits(page, {browserName, includeAxe, includePerformance, includeFonts})` |
| `telemetry.mjs` | `createAuditTelemetry`, `finalizeAuditTelemetry` |

## For AI Agents

### Working In This Directory

- `lib/audit-helpers.mjs` and `run-ui-lint.mjs` import from here; removing a re-export breaks them.

### Testing Requirements

- Covered by `tests/orchestration/audit-runtime.spec.js`, `tests/audit-helpers.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../accessibility/`, `../browsers/`, `../console/`, `../dom/`, `../fonts/`, `../performance/`, `../visual/`

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
