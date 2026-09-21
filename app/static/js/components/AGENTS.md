<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# components

## Purpose
Reusable JS widgets shared across pages. Loaded globally from `base.html`.

## Key Files
| File | Description |
|------|-------------|
| `retention-slider.js` | Generic retention slider component registered under `window.WB`; used by settings (backup and TSDB log/metrics retention) |

## For AI Agents
### Working In This Directory
- Keep components configuration-driven (no page-specific IDs). Register on `window.WB`.

### Testing Requirements
`node tools/ui-lint/run-ui-lint.mjs`; test the Settings backup and logs tabs.

### Common Patterns
- `window.WB = window.WB || {}` then attach.

## Dependencies
### Internal
- `../core/dom.js`, `../../css/` slider styles.
### External
- None.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
