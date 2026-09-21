<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# utilities

## Purpose
Tiny single-purpose helper classes, mostly replacing inline `style=` attributes so CSP-friendly templates stay clean. Loaded globally by `base.html`.

## Key Files
| File | Description |
|------|-------------|
| `wb-state.css` | `.is-hidden`, `.is-empty` and similar state classes toggled by JS (`js/ui-state.js`) |
| `state-extended.css` | Extra state/display helpers (hidden-by-default, disabled interaction replacing inline `pointer-events: none`) |
| `icons.css` | Material Icons baseline alignment and size modifiers |

## For AI Agents
### Working In This Directory
- Keep helpers atomic; prefer adding a class here over inline styles. `wb-state.css` is also `@import`ed by some page sheets.

### Testing Requirements
`node tools/ui-lint/run-ui-lint.mjs`

### Common Patterns
- `is-*` state classes; `!important` is acceptable only for hide/disable helpers.

## Dependencies
### Internal
- `../../js/ui-state.js`, templates.
### External
- `../../vendor/material-icons.css` for the icon classes.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
