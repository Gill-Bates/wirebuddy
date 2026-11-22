<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# rules

## Purpose

Lint rules executed against each audited view. A manifest lists the rule modules; `index.mjs` dynamically imports them so each registers itself with `lib/rule-registry.mjs`. Rules are grouped by category directory.

## Key Files

| File | Description |
|---|---|
| `manifest.mjs` | `RULE_MANIFEST`: id and path for each rule (single source of loaded rules) |
| `index.mjs` | `loadRules()` imports every manifest entry once and returns the catalog; re-exports registry runners (`runRule`, `runAllRules`, `runCategory`, ...); a top-level `await loadRules()` registers all rules on import |

## Subdirectories

| Directory | Purpose |
|---|---|
| `accessibility/` | click-targets, control-contracts, focus-indicators (see `accessibility/AGENTS.md`) |
| `component/` | changelog-details, dashboard-light-surfaces (see `component/AGENTS.md`) |
| `layout/` | form-switch-spacing, overflow, settings-logs-layout (see `layout/AGENTS.md`) |
| `mobile/` | scroll-traps (see `mobile/AGENTS.md`) |

## For AI Agents

### Working In This Directory

- A new rule needs: a module that exports `meta`, builds the rule with `RuleBuilder.<category>(id, name, run)`, assigns `rule.meta = meta`, calls `registerRule(rule)` and default-exports it; a `RULE_MANIFEST` entry; and a spec in `tests/`. `tests/rules/index.spec.js` checks manifest and catalog stay aligned.
- Functions a rule passes to `page.evaluate` run in the page; keep them self-contained.

### Testing Requirements

- Covered by `tests/rules/index.spec.js`, `tests/rules/rule-registry-orchestration.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

### Common Patterns

- The file header carries a `// Rule: <summary>` line after the copyright.
- `meta` fields: id, category, severity, browsers, devices, requires, optional, capabilities, performanceCost, tags, executionMode, scopes, severityByBrowser; the registry normalises them (`lib/rule-orchestration/registry-engine.mjs`).

## Dependencies

### Internal

- `../lib/rule-registry.mjs`, `../lib/` diagnostics helpers

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
