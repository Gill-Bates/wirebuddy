<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# rules

## Purpose

Specs for the rule manifest and registry orchestration.

## Key Files

| File | Description |
|---|---|
| `index.spec.js` | Manifest and loaded catalog stay aligned |
| `rule-registry-orchestration.spec.js` | Metadata normalisation, capability discovery, dependency planning, telemetry |

## For AI Agents

### Testing Requirements

- Run `cd tools/ui-lint && npx playwright test tests/rules/`; requires installed Playwright browsers.

## Dependencies

### Internal

- `../../rules/`, `../../lib/rule-registry.mjs`

### External

- `@playwright/test`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
