<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# css

## Purpose
WireBuddy's stylesheet tree. A token-driven design system is loaded globally by `templates/base.html`, in this cascade order: Bootstrap 5.3.3 (vendor) then Material Icons, `core/`, `foundations/`, `components/`, `utilities/`, `wb-ui-system.css`, `style.css`, and finally page CSS from each template's `extra_css` block. Later layers override earlier ones, so page CSS should compose tokens rather than re-declare values. `auth_base.html` and the status pages load a reduced set with `style.css` before `wb-ui-system.css`.

## Key Files
| File | Description |
|------|-------------|
| `wb-ui-system.css` | Central UI system (~1100 lines, numbered sections): tokens, typography, cards, KPI/stat cards, buttons, tables, badges, forms, section spacing, page header, list groups, alerts, dropdowns, modals, nav tabs, progress, tooltips |
| `style.css` | Global app styles on top of Bootstrap variables: shell/sidebar, z-index layering, shared widgets |
| `dashboard.css`, `dns.css`, `peers.css`, `traffic.css`, `users.css`, `login.css` | Page-specific rule bodies, `@import`ed by the matching `pages/<name>.css` (for all but `dashboard` that sheet holds only `@import` lines) |
| `status.css` | Public status page flow visualisation (own tokens `--flow-*`); linked directly by `status.html` and `status_disabled.html`, not via `pages/` |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `core/` | Design tokens and semantic token mapping; see `core/AGENTS.md` |
| `foundations/` | Accessibility, breakpoints, layout primitives; see `foundations/AGENTS.md` |
| `components/` | Reusable component styles; see `components/AGENTS.md` |
| `utilities/` | Small state/icon helper classes; see `utilities/AGENTS.md` |
| `pages/` | Per-page stylesheets; see `pages/AGENTS.md` |

## For AI Agents
### Working In This Directory
- Layering: `core` (raw tokens) -> `semantic` (purpose tokens) -> `foundations` -> `components` -> `utilities` -> `wb-ui-system.css`/`style.css` -> `pages`. Put a rule in the lowest layer that owns it.
- Use `var(--wb-*)` tokens for colour, spacing, radius, z-index; do not hard-code hex/px where a token exists (ui-lint reports token drift).
- Breakpoints follow `foundations/breakpoints.css`; do not invent new ones.
- Both light and dark themes (Bootstrap `data-bs-theme`) must work.

### Testing Requirements
See `../AGENTS.md`; ui-lint rule groups live under `tools/ui-lint/rules/` (accessibility, component, layout, mobile).

### Common Patterns
- `wb-` prefix for design-system classes; `is-*` for state classes.
- Section banners `/* ---------- N. Name ---------- */` in `wb-ui-system.css`.

## Dependencies
### Internal
- `../vendor/bootstrap.min.css`, `../vendor/material-icons.css`; `../../templates/base.html` and `auth_base.html` for load order; `../js/dashboard_traffic_shared.js` reads chart colours from the tokens at runtime.
### External
- Bootstrap 5.3.3 variables/classes.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
