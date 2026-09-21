<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# rule-orchestration

## Purpose

Engine behind `lib/rule-registry.mjs`: rule registration and metadata normalisation, dependency-aware execution planning, resource management, telemetry and failure explanation.

## Key Files

| File | Description |
|---|---|
| `registry-engine.mjs` | State-based registry (`createRuleRegistryState`, `registerRuleWithState`, `runRuleWithState`, `runAllRulesWithState`, capability/owner lookup, execution graph); ~460 lines |
| `rule-builder.mjs` | `RuleBuilder` fluent rule definition |
| `execution-planner.mjs` | `planExecution` (resolves `requires`/`optional`) |
| `resource-manager.mjs` | `createResourceManager` |
| `severity-normalizer.mjs` | `normalizeSeverity`, `normalizeSeverityByBrowser`, `severityWeight` |
| `telemetry.mjs` | `createRuleTelemetry`, `finalizeRuleTelemetry`, `classifyFailure` |
| `explainability.mjs` | `buildRuleExplanation`, `whyDidRuleFail` |
| `index.mjs` | Export surface |

## For AI Agents

### Working In This Directory

- Rule `meta` fields (`requires`, `capabilities`, `scopes`, `executionMode`) are validated here; extend validation when adding a meta field.

### Testing Requirements

- Covered by `tests/rules/rule-registry-orchestration.spec.js`, `tests/rules/index.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../rule-registry.mjs`, `../../rules/`

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
