<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# engine

## Purpose

Findings pipeline core: evaluates policy rules against audit data, deduplicates, correlates, and scores severity.

## Key Files

| File | Description |
|---|---|
| `findings-engine.mjs` | `createFindingsContext`, `evaluateFindings` |
| `policy-engine.mjs` | `POLICY_VERSION`, `createFinding`, count/flag/threshold/custom rule evaluators, `evaluatePolicyRules`, `deduplicateFindings` |
| `decision-tree.mjs` | `correlateFindings` |
| `scoring-engine.mjs` | `scoreFindings`, `buildSummary` |
| `severity-engine.mjs` | `evaluateSeverity`, `severityToRiskLevel`, `severityWeight` |

## For AI Agents

### Working In This Directory

- Bumping `POLICY_VERSION` signals a behaviour change in policy evaluation.

### Testing Requirements

- Covered by `tests/findings/layout-policy.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../policies/`, `../severity/`

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
