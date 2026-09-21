<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# vendor

## Purpose
Vendored third-party libraries served locally (no CDN, works offline and under strict CSP). Read-only: never edit these files; upgrade by replacing them wholesale. `fonts/` and `images/` subdirectories (icon fonts, Leaflet marker images) are not documented.

## Key Files
| File | Description |
|------|-------------|
| `bootstrap.min.css`, `bootstrap.bundle.min.js` | Bootstrap 5.3.3 (bundle includes Popper) |
| `material-icons.css` | Material Icons font-face and `.material-icons` class |
| `chart.umd.min.js` | Chart.js 4.5.1 |
| `chartjs-plugin-datalabels.min.js` | chartjs-plugin-datalabels 2.2.0 |
| `leaflet.js`, `leaflet.css` | Leaflet 1.9.4 maps |
| `leaflet-heat.js` | Leaflet heat-map layer |
| `leaflet-gesture-handling.min.js`, `leaflet-gesture-handling.min.css` | Two-finger/ctrl-scroll gesture handling for Leaflet |

## For AI Agents
### Working In This Directory
- Do not edit. Customisation belongs in `../css/` or `../js/`. Bootstrap and Material Icons load on every page; Chart.js and Leaflet are included per page in `extra_js`.

### Testing Requirements
None for these files; UI lint excludes third-party code. After an upgrade, smoke test charts and maps.

### Common Patterns
- Referenced as `/static/vendor/<file>` from templates.

## Dependencies
### Internal
- Used by `../../templates/` and `../js/`.
### External
- Upstream projects listed above (licence headers are kept in each file).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
