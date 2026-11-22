<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# accessibility

## Purpose

Accessibility thresholds resolved from tokens.

## Key Files

| File | Description |
|---|---|
| `focus.mjs` | `FOCUS_POLICY` |
| `touch-targets.mjs` | `TOUCH_TARGET_POLICY`, `CLICK_TARGET_MIN_SIZE_PX`, input-group and standard-button height expectations/tolerances |
| `wcag.mjs` | `WCAG_CONTRAST`, `WCAG_CONTRAST_POLICY`, `isLargeText`, `evaluateContrast` |

## For AI Agents

### Testing Requirements

- Covered by `tests/config/config-platform.spec.js`, `tests/accessibility/touch-targets.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

## Dependencies

### Internal

- `../tokens/resolver.mjs`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
