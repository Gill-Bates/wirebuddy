<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# core

## Purpose
Runtime infrastructure shared by every page controller; loaded from `base.html` before page scripts.

## Key Files
| File | Description |
|------|-------------|
| `dom.js` | Large (~1900 lines) deterministic UI runtime: declarative `el()` DOM construction, scheduling (rAF), safe rendering helpers |
| `design-tokens.js` | `window.DesignTokens`: reads CSS custom properties at runtime so JS (e.g. Chart.js colours) follows the CSS tokens |
| `logger.js` | `window.WBLogger`: levelled, structured frontend logging with optional context |

## For AI Agents
### Working In This Directory
- Changes here affect every page; keep APIs backward compatible. Do not add page-specific logic.

### Testing Requirements
`node tools/ui-lint/run-ui-lint.mjs`; manually smoke test several pages.

### Common Patterns
- Global namespace objects, frozen/guarded exports.

## Dependencies
### Internal
- `../../css/core/tokens.css` (read by design-tokens.js).
### External
- None.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
