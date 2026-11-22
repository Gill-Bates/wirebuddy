<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# utilities

## Purpose
Tiny single-purpose helper classes, mostly replacing inline `style=` attributes so CSP-friendly templates stay clean. Loaded globally by `base.html`.

## Key Files
| File | Description |
|------|-------------|
| `wb-state.css` | `.is-hidden`, `.is-empty` and similar state classes toggled by JS (`js/ui-state.js`) |
| `state-extended.css` | `.wb-cell-half` only |
| `icons.css` | Material Icons baseline alignment and size modifiers |

## For AI Agents
### Working In This Directory
- Keep helpers atomic; prefer adding a class here over inline styles. `wb-state.css` is also `@import`ed by some page sheets.

### Testing Requirements
See `../../AGENTS.md`.

### Common Patterns
- `is-*` state classes; `!important` is acceptable only for hide/disable helpers.

## Dependencies
### Internal
- `../../js/ui-state.js`, templates.
### External
- `../../vendor/material-icons.css` for the icon classes.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
