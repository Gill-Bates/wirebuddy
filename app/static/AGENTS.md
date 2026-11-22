<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# static

## Purpose
Everything the browser fetches from `/static/`: hand-written CSS (a layered design system plus per-page sheets), classic-script JavaScript (no bundler, no ES modules; APIs are globals on `window`), and vendored third-party libraries. Templates in `../templates/` reference these files by absolute `/static/...` URLs.

## Key Files
None at this level; all content lives in the subdirectories below. (`img/`, `vendor/fonts/` and `vendor/images/` are assets and are not documented.)

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `css/` | Design tokens, foundations, components, utilities, page sheets; see `css/AGENTS.md` |
| `js/` | Page controllers, shared runtime helpers, settings modules; see `js/AGENTS.md` |
| `vendor/` | Vendored Bootstrap, Chart.js, Leaflet, GridStack, Material Icons; see `vendor/AGENTS.md` |

## For AI Agents
### Working In This Directory
- No build step: files are served as-is, so edits go live without a rebuild. `main.py` serves `/static` with `Cache-Control: no-cache` (browsers revalidate via ETag/304), so no hard refresh is needed. Do not introduce bundlers, ES module `import`, or npm-managed frontend deps.
- Load order and which files a page uses is decided in `../templates/base.html` (global), `../templates/auth_base.html` and the standalone status pages (reduced sets), and each page template's `extra_css`/`extra_js` blocks. Add a new file there or it will not load.
- Never edit `vendor/`.
- No inline `style=` attributes, `<style>` blocks, inline `<script>` or `on*=` handlers: the CSP in `main.py` (`style-src 'self'`, `script-src 'self'`, `script-src-attr 'none'`) blocks them. Styling goes into CSS classes here, behaviour into files under `js/`.

### Testing Requirements
This is the home of the frontend checks; the `AGENTS.md` files below point here.
- Browser checks: the isolated `tests/e2e/` drivers or the `tools/ui-lint` audit, with the commands and credentials described in the root `AGENTS.md`. Check light and dark theme and mobile width.
- Source-level contracts in `pytest` read these files directly, so renames and refactors break them: `test_frontend_cleanup.py` (`js/settings.js` retention helpers, needs Node.js), `test_settings_stale_slider.py` (`js/settings.js`, `css/pages/settings.css`), `test_dashboard_widget_registry.py` (`js/dashboard_widgets.js`), `test_peer_stale.py` (`js/peers.js`).
- `tools/ui-lint/tests/runtime/` specs load `js/core/dom.js`, `js/core/format.js`, `js/settings/components.js`, `js/dashboard_widgets.js`, `js/dashboard_grid.js`, `js/base-ui.js` and `js/modal.js` (see `tools/ui-lint/tests/runtime/AGENTS.md`).
- Source CSS lint, not a gate: `npm run lint` in `tools/stylelint/`.

### Common Patterns
- Design tokens (`--wb-*`) are the single source of truth for colour, spacing, radius; chart colours are read from them by `WBShared.getChartColors()` in `js/dashboard_traffic_shared.js`.
- First-party JS files start with the `//` header block (file path `app/static/...`, copyright line); CSS files carry no uniform header.

## Dependencies
### Internal
- `../templates/` (consumers), `../../tools/ui-lint/` (audits the rendered UI, including design-token drift), backend JSON API used by `js/api.js`.
### External
- Bundled in `vendor/` only.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
