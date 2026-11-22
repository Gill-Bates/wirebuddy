<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# config

## Purpose

Specs for the configuration and token runtime platforms.

## Key Files

| File | Description |
|---|---|
| `config-platform.spec.js` | Token resolver metadata, WCAG evaluation, payload builders, motion/theme registries |
| `design-token-runtime.spec.js` | Token runtime var chains/units, serialisable payloads, drift, provider registration |

## For AI Agents

### Testing Requirements

- Run `cd tools/ui-lint && npx playwright test tests/config/`; requires installed Playwright browsers.

## Dependencies

### Internal

- `../../lib/config/`, `../../lib/design-tokens/`

### External

- `@playwright/test`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
