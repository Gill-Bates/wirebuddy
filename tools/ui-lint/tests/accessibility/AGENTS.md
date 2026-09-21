<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# accessibility

## Purpose

Specs for the accessibility rules and touch-target contract.

## Key Files

| File | Description |
|---|---|
| `click-targets.spec.js` | Viewport-aware thresholds; grouped peer actions and occlusion |
| `control-contracts.spec.js` | Button type and decorative icon contract |
| `focus-indicators.spec.js` | Contrast helper, tab order, low-contrast rings, modal focus escape |
| `touch-targets.spec.js` | Peer and node mobile actions meet the token minimum (uses `mountContractPage`) |

## For AI Agents

### Working In This Directory

- No special constraints beyond the parent directory guidance.

### Testing Requirements

- Run `cd tools/ui-lint && npx playwright test tests/accessibility/`; requires installed Playwright browsers.

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../../rules/accessibility/`, `../../lib/`, `../support/`

### External

- `@playwright/test`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
