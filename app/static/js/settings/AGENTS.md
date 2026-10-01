<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# settings

## Purpose
Split-out pieces of the Settings page. `components.js` and `speedtest.js` are loaded by `settings.html` alongside the monolithic `../settings.js`.

## Key Files
| File | Description |
|------|-------------|
| `components.js` | Reusable settings UI components built with `el()`, under `window.WB` |
| `speedtest.js` | Extracted speedtest runtime for the Settings page |

## For AI Agents
### Working In This Directory
- `templates/settings.html` loads `settings.js` (the monolith) alongside `components.js` and `speedtest.js`; page behaviour lives in the monolith unless it was split out here.

### Testing Requirements
`node tools/ui-lint/run-ui-lint.mjs`; manually test each Settings tab.

### Common Patterns
- IIFE attaching to `window.WB` (e.g. `window.WB.settingsComponents`, `window.WB.settingsSpeedtest`).

## Dependencies
### Internal
- `../core/dom.js`, `../api.js`, `../dashboard_traffic_shared.js`, `../components/retention-slider.js`, `../../../templates/settings/`.
### External
- Chart.js for speedtest graphs.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
