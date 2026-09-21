<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# core

## Purpose
Bottom of the design system: raw design tokens and the semantic mapping on top of them. Loaded first after Bootstrap; everything else consumes these custom properties.

## Key Files
| File | Description |
|------|-------------|
| `tokens.css` | Single source of truth for design decisions (colour, spacing, radius, typography, breakpoints as `--wb-*`); the UI linter validates against it |
| `semantic.css` | Maps core tokens to purpose-specific tokens (surfaces, text, status, z-index layers); sits between tokens and components |

## For AI Agents
### Working In This Directory
- Add or change a value here first, then reference it elsewhere. Keep raw values out of components/pages.
- Changing a token affects every page and `js/core/design-tokens.js` consumers (charts); check both themes.

### Testing Requirements
`node tools/ui-lint/run-ui-lint.mjs`

### Common Patterns
- Raw tokens in `tokens.css`, intent-named tokens in `semantic.css`; never the reverse.

## Dependencies
### Internal
- Consumed by all other CSS and by `../../js/core/design-tokens.js`.
### External
- Overrides/extends Bootstrap CSS variables where noted.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
