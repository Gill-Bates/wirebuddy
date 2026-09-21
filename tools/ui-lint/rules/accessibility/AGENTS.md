<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# accessibility

## Purpose

Accessibility rules.

## Key Files

| File | Description |
|---|---|
| `click-targets.mjs` | Minimum touch/click target size (WCAG 2.5.5), density- and viewport-aware; groups peer actions, flags occlusion |
| `control-contracts.mjs` | Buttons declare a `type`; decorative icons are hidden from the accessible name |
| `focus-indicators.mjs` | Visible focus indicators (WCAG 2.4.7), tab order and modal focus escape |

## For AI Agents

### Working In This Directory

- No special constraints beyond the parent directory guidance.

### Testing Requirements

- Covered by `tests/accessibility/click-targets.spec.js`, `tests/accessibility/control-contracts.spec.js`, `tests/accessibility/focus-indicators.spec.js`, `tests/accessibility/touch-targets.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- Header comment `// Rule: ...`; `meta` object + `registerRule`.

## Dependencies

### Internal

- `../../lib/interaction-utils.mjs`, `focus-flow.mjs`, `focus-visibility.mjs`

### External

- None

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
