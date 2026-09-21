<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# foundations

## Purpose
Cross-cutting policies applied to the whole UI: accessibility, responsive breakpoints and layout primitives. Loaded after `core/` and before components.

## Key Files
| File | Description |
|------|-------------|
| `accessibility.css` | Centralised a11y rules: focus rings, reduced motion, screen-reader helpers, contrast-related policies |
| `breakpoints.css` | Breakpoint policy; documents the values from `tokens.css` that all media queries must use |
| `layout.css` | Reusable flex/grid layout primitives replacing duplicated declarations in page CSS |

## For AI Agents
### Working In This Directory
- New a11y or responsive rules belong here, not scattered in page sheets. Prefer an existing layout primitive over new flex/grid boilerplate.

### Testing Requirements
`node tools/ui-lint/run-ui-lint.mjs` (accessibility, layout and mobile rule groups apply directly).

### Common Patterns
- Media queries use the documented breakpoint values only; respect `prefers-reduced-motion`.

## Dependencies
### Internal
- `../core/tokens.css`, `../core/semantic.css`.
### External
- None.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
