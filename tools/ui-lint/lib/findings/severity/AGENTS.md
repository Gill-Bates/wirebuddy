<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# severity

## Purpose

Severity vocabulary, weights and escalation/downgrade rules.

## Key Files

| File | Description |
|---|---|
| `severity-levels.mjs` | `SEVERITY_LEVELS`, `RISK_LEVELS` |
| `severity-weights.mjs` | `SEVERITY_WEIGHTS` |
| `escalation.mjs` | `applyEscalationRules` |
| `downgrade-rules.mjs` | `applyDowngradeRules` |

## For AI Agents

### Working In This Directory

- Severity names are shared with `../../accessibility/wcag-mapping.mjs` and `../../rule-orchestration/severity-normalizer.mjs`.

### Testing Requirements

- Covered by `tests/findings/layout-policy.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- No special constraints beyond the parent directory guidance.

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
