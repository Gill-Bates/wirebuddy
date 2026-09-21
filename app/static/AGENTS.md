<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# static

## Purpose
Everything the browser fetches from `/static/`: hand-written CSS (a layered design system plus per-page sheets), plain-script JavaScript (no bundler, no ES module imports; modules attach to `window`), and vendored third-party libraries. Templates in `../templates/` reference these files by absolute `/static/...` URLs.

## Key Files
None at this level; all content lives in the subdirectories below. (`img/`, `vendor/fonts/` and `vendor/images/` are assets and are not documented.)

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `css/` | Design tokens, foundations, components, utilities, page sheets; see `css/AGENTS.md` |
| `js/` | Page controllers, shared runtime helpers, settings modules; see `js/AGENTS.md` |
| `vendor/` | Vendored Bootstrap, Chart.js, Leaflet, Material Icons; see `vendor/AGENTS.md` |

## For AI Agents
### Working In This Directory
- No build step: files are served as-is, so edits are live after a hard refresh. Do not introduce bundlers, ES module `import`, or npm-managed frontend deps.
- Load order and which files a page uses is decided in `../templates/base.html` (global) and each page template's `extra_css`/`extra_js` blocks. Add a new file there or it will not load.
- Never edit `vendor/`.
- Avoid inline `style=`/`onclick=` in templates; CSP-strict conventions push styling into CSS classes here.

### Testing Requirements
Run the UI lint after any CSS or template change: `node tools/ui-lint/run-ui-lint.mjs`. There is no JS test runner for these files; verify in the browser (light and dark theme, mobile width).

### Common Patterns
- Design tokens (`--wb-*`) are the single source of truth for colour, spacing, radius; JS reads them via `js/core/design-tokens.js`.
- Copyright header comment (`// app/static/...`) at the top of first-party files.

## Dependencies
### Internal
- `../templates/` (consumers), `../../tools/ui-lint/` (validates CSS/HTML against tokens), backend JSON API used by `js/api.js`.
### External
- Bundled in `vendor/` only.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
