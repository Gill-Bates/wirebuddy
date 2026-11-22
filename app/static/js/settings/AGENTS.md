<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# settings

## Purpose
Split-out pieces of the Settings page. `settings.html` loads `components.js` and `speedtest.js` before the monolithic `../settings.js`; page behaviour lives in the monolith unless it was split out here.

## Key Files
| File | Description |
|------|-------------|
| `components.js` | `window.WB.settingsComponents`: settings UI building blocks built with `el()` |
| `speedtest.js` | `window.WB.settingsSpeedtest`: speedtest settings, retention, SSE-streamed run and result/history rendering for the Settings page |

## For AI Agents
### Working In This Directory
- `speedtest.js` aborts at load when the `WBShared` formatters are missing, so `dashboard_traffic_shared.js` must stay before it in `settings.html`.

### Testing Requirements
See `../../AGENTS.md`; `tools/ui-lint/tests/runtime/dom-runtime.spec.js` loads `components.js`. Click through each Settings tab.

### Common Patterns
- IIFE attaching to `window.WB` (e.g. `window.WB.settingsComponents`, `window.WB.settingsSpeedtest`).

## Dependencies
### Internal
- `../core/dom.js`, `../core/format.js`, `../core/flags.js`, `../api.js`, `../toast.js`, `../dashboard_traffic_shared.js`, `../../../templates/settings/`.
### External
- None.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
