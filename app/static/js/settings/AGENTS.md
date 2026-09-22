<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# settings

## Purpose
Split-out pieces of the Settings page. `components.js` and `speedtest.js` are loaded by `settings.html` alongside the monolithic `../settings.js`. `core.js` plus `modules/` are a modular bootstrap (`SettingsApp.registerModule`) that must NOT be loaded together with `settings.js`: `core.js` throws if the other bootstrap is present.

## Key Files
| File | Description |
|------|-------------|
| `components.js` | Reusable settings UI components built with `el()`, under `window.WB` |
| `speedtest.js` | Extracted speedtest runtime for the Settings page |
| `core.js` | Modular bootstrap: shared state, utilities and module registry (`registerModule`); sets `__WB_SETTINGS_BOOTSTRAP__ = 'modular'` |
| `modules/backup.js` | Backup settings module (registered with `SettingsApp`) |
| `modules/logs.js` | Logs/metrics settings module |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `modules/` | Modules for the modular bootstrap (`backup.js`, `logs.js`); described here, no separate AGENTS.md |

## For AI Agents
### Working In This Directory
- Check which bootstrap `templates/settings.html` loads before editing: currently `settings.js` (the monolith) alongside `components.js` and `speedtest.js`. The modular `core.js`/`modules/` bootstrap is not wired in yet, so a behaviour may live in either the monolith or a module.

### Testing Requirements
`node tools/ui-lint/run-ui-lint.mjs`; manually test each Settings tab.

### Common Patterns
- Modules: `SettingsApp.registerModule('name', (function () { ... return api; })())`.

## Dependencies
### Internal
- `../core/dom.js`, `../api.js`, `../dashboard_traffic_shared.js`, `../components/retention-slider.js`, `../../../templates/settings/`.
### External
- Chart.js for speedtest graphs.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
