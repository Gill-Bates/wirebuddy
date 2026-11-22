<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# overflow

## Purpose

Spec for the horizontal-overflow rule on mobile fixtures.

## Key Files

| File | Description |
|---|---|
| `mobile-overflow.spec.js` | Peers, nodes and dashboard stay in viewport; local scrollers acceptable (largest spec) |

## For AI Agents

### Testing Requirements

- Run `cd tools/ui-lint && npx playwright test tests/overflow/`; requires installed Playwright browsers.

## Dependencies

### Internal

- `../../rules/layout/overflow.mjs`, `../support/`

### External

- `@playwright/test`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
