<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# accessibility

## Purpose

Runs axe-core against a page and normalises its violations into the linter's finding shape with WCAG-derived severities.

## Key Files

| File | Description |
|---|---|
| `axe-runner.mjs` | `runAxeAudit(page)`: executes axe and maps results through the normaliser |
| `violation-normalizer.mjs` | `normalizeAccessibilityFinding(provider, violation)` |
| `wcag-mapping.mjs` | `AXE_IMPACT_TO_SEVERITY` (critical->blocking, serious->serious, ...) and `mapAxeImpactToSeverity` |

## For AI Agents

### Working In This Directory

- Severity names must match the vocabulary in `findings/severity/severity-levels.mjs`.

### Testing Requirements

- No dedicated spec under `tests/`; it is exercised indirectly through `run-ui-lint.mjs` (via the `orchestration/audit-runner.mjs` facade). Verify with a real audit run against a running WireBuddy (`npm run audit`, needs `UI_LINT_USERNAME`/`UI_LINT_PASSWORD`).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../orchestration/audit-runner.mjs` (re-export and `runExtendedAudits`)

### External

- `@axe-core/playwright` (used by the runner)

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
