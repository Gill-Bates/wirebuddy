<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# settings

## Purpose
Markup partials `include`d by `../settings.html`: one per settings tab plus the shared modals. They hold no CSS or JS: the page's styles are `static/css/pages/settings.css` and its scripts `static/js/settings.js` and `static/js/settings/`.

## Key Files
| File | Description |
|------|-------------|
| `_tab_general.html`, `_tab_wireguard.html`, `_tab_dns.html`, `_tab_letsencrypt.html`, `_tab_logs.html`, `_tab_backup.html` | Tab panes (general has a `copyable_url` macro) |
| `_modals.html` | Modals shared across tabs |

## For AI Agents
### Working In This Directory
- Adding a tab means: `_tab_*.html`, an entry in the `tabs` list and an include in `settings.html`, and the tab id in the valid-tab lists of `static/js/settings.js` and `static/js/settings/core.js` (both exist today).
- Do not add `<script>` or `<style>` partials here; page logic and styles belong in `static/`.

### Testing Requirements
`node tools/ui-lint/run-ui-lint.mjs`; click through every tab, including backup/restore.

### Common Patterns
- Underscore-prefixed partials; IDs prefixed by feature (e.g. `wg-`).

## Dependencies
### Internal
- `../settings.html`, `../../static/js/settings.js`, `../../static/js/settings/`, `../../static/css/pages/settings.css`.
### External
- Bootstrap tabs and modals.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
