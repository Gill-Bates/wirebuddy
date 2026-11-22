<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# vendor

## Purpose
Vendored third-party libraries served locally (no CDN, works offline and under strict CSP). Read-only: never edit these files; upgrade by replacing them wholesale. `fonts/` and `images/` subdirectories (icon fonts, Leaflet marker images) are not documented.

## Key Files
| File | Description |
|------|-------------|
| `bootstrap.min.css`, `bootstrap.bundle.min.js` | Bootstrap 5.3.3 (bundle includes Popper) |
| `material-icons.css` | Material Icons font-face and `.material-icons` class |
| `chart.umd.min.js` | Chart.js 4.5.1 |
| `chartjs-plugin-datalabels.min.js` | chartjs-plugin-datalabels 2.2.0; not referenced by any template or script |
| `leaflet.js`, `leaflet.css` | Leaflet 1.9.4 maps |
| `leaflet-heat.js` | Leaflet heat-map layer (simpleheat); not referenced by any template or script |
| `leaflet-gesture-handling.min.js`, `leaflet-gesture-handling.min.css` | Two-finger/ctrl-scroll gesture handling for Leaflet |
| `gridstack-all.js`, `gridstack.min.css` | GridStack 14.0.0 (MIT); drives the draggable per-user dashboard grid. Loaded only by `dashboard.html` |

## For AI Agents
### Working In This Directory
- Do not edit. Customisation belongs in `../css/` or `../js/`. Bootstrap and Material Icons load on every page; Chart.js (dashboard, traffic, DNS) and GridStack (dashboard) are included per page; the Leaflet CSS sits in `dashboard.html` while `dashboard.js` lazy-loads `leaflet.js` and the gesture-handling plugin.
- The JS files and `gridstack.min.css` carry a prepended `// app/static/vendor/<file>` copyright block above the upstream header; an upgrade replaces the upstream content and keeps that block.

### Testing Requirements
None for these files; `tools/ui-lint/tests/runtime/dashboard-grid.spec.js` and `modal-keyboard.spec.js` load `gridstack-all.js` and Bootstrap, so rerun them after an upgrade and smoke test charts and the map.

### Common Patterns
- Referenced as `/static/vendor/<file>` from templates.

## Dependencies
### Internal
- Used by `../../templates/` and `../js/`.
### External
- Upstream projects listed above (licence headers are kept in each file).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
