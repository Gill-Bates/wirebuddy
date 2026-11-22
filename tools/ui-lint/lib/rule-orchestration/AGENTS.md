<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# rule-orchestration

## Purpose

Engine behind `lib/rule-registry.mjs`: rule registration and metadata normalisation, dependency-aware execution planning, resource management, telemetry and failure explanation.

## Key Files

| File | Description |
|---|---|
| `registry-engine.mjs` | State-based registry (`createRuleRegistryState`, `registerRuleWithState`, `runRuleWithState`, `runAllRulesWithState`, capability/owner lookup, execution graph) |
| `rule-builder.mjs` | `RuleBuilder` category factories (`accessibility`, `layout`, `mobile`, `component`, `performance`), each `(id, name, run)` |
| `execution-planner.mjs` | `planExecution`: dependency closure over `meta.dependencies`, browser/device/environment filtering, skips rules with missing dependencies, batches by priority and cost |
| `resource-manager.mjs` | `createResourceManager` |
| `severity-normalizer.mjs` | `normalizeSeverity`, `normalizeSeverityByBrowser`, `severityWeight` |
| `telemetry.mjs` | `createRuleTelemetry`, `finalizeRuleTelemetry`, `classifyFailure` |
| `explainability.mjs` | `buildRuleExplanation`, `whyDidRuleFail` |
| `index.mjs` | Export surface |

## For AI Agents

### Working In This Directory

- `registerRuleWithState` requires only `id` and a `run` function; `normalizeRuleMeta` (`registry-engine.mjs`) rebuilds `meta` field by field with defaults, so a new meta field must be added there or it is dropped.

### Testing Requirements

- Covered by `tests/rules/rule-registry-orchestration.spec.js`, `tests/rules/index.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

## Dependencies

### Internal

- `../rule-registry.mjs`, `../../rules/`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
