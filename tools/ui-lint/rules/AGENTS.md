<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# rules

## Purpose

Lint rules executed against each audited view. A manifest lists the rule modules; `index.mjs` dynamically imports them so each registers itself with `lib/rule-registry.mjs`. Rules are grouped by category directory.

## Key Files

| File | Description |
|---|---|
| `manifest.mjs` | `RULE_MANIFEST`: id and path for each rule (single source of loaded rules) |
| `index.mjs` | `loadRules()` imports every manifest entry once and returns the catalog; re-exports registry runners (`runRule`, `runAllRules`, `runCategory`, ...); top-level await `loadedRules` |

## Subdirectories

| Directory | Purpose |
|---|---|
| `accessibility/` | click-targets, control-contracts, focus-indicators (see `accessibility/AGENTS.md`) |
| `component/` | changelog-details, dashboard-light-surfaces (see `component/AGENTS.md`) |
| `layout/` | form-switch-spacing, overflow, settings-logs-layout (see `layout/AGENTS.md`) |
| `mobile/` | scroll-traps (see `mobile/AGENTS.md`) |

## For AI Agents

### Working In This Directory

- A new rule needs: a module registering via `registerRule(new RuleBuilder(meta)...)`, a `RULE_MANIFEST` entry, and a spec in `tests/`. `tests/rules/index.spec.js` checks manifest and catalog stay aligned.
- Rule `check` bodies run in the page; keep them self-contained.

### Testing Requirements

- Covered by `tests/rules/index.spec.js`, `tests/rules/rule-registry-orchestration.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- Each rule exports `meta` (id, category, severity, browsers, devices, requires, capabilities, performanceCost, tags, executionMode, scopes) and registers itself on import.

## Dependencies

### Internal

- `../lib/rule-registry.mjs`, `../lib/` diagnostics helpers

### External

- None

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
