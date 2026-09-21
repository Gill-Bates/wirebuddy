<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# config

## Purpose

Specs for the configuration, token runtime and device runtime platforms.

## Key Files

| File | Description |
|---|---|
| `config-platform.spec.js` | Token resolver metadata, WCAG evaluation, payload builders, motion/theme registries |
| `design-token-runtime.spec.js` | Token runtime var chains/units, serialisable payloads, drift, provider registration |
| `device-runtime.spec.js` | Device runtime, deterministic matrix hash, Playwright adapter |

## For AI Agents

### Working In This Directory

- No special constraints beyond the parent directory guidance.

### Testing Requirements

- Run `cd tools/ui-lint && npx playwright test tests/config/`; requires installed Playwright browsers.

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../../lib/config/`, `../../lib/design-tokens/`, `../../lib/device-runtime/`

### External

- `@playwright/test`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
