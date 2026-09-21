<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# components

## Purpose
Self-contained reusable component styles. `buttons.css`, `empty-state.css` and `scroll-container.css` load globally from `base.html`; `kpi-card.css` and `responsive-table.css` are opt-in through page wrappers in `../pages/`.

## Key Files
| File | Description |
|------|-------------|
| `buttons.css` | Unified button hierarchy and action-button sizing (replaces scattered button styles) |
| `empty-state.css` | Empty-state block (icon, title, text) replacing ad-hoc `.chart-empty-state` patterns |
| `kpi-card.css` | `.wb-kpi-card` compact/mobile layout; used by dashboard, DNS, settings |
| `responsive-table.css` | `.wb-responsive-table` with meta/actions cells collapsing on mobile; used by peers, traffic, users, nodes |
| `scroll-container.css` | Central scroll container behaviour (overflow, scrollbar gutter, iOS fixes) |

## For AI Agents
### Working In This Directory
- Extend a component here rather than re-styling it in a page sheet. Markup for KPI cards comes from `templates/macros/kpi.html`.

### Testing Requirements
`node tools/ui-lint/run-ui-lint.mjs` (component rules).

### Common Patterns
- `.wb-<component>` root class with token-based values; header comment explains what the file replaces.

## Dependencies
### Internal
- `../core/`, `../foundations/`; imported by `../pages/*.css`.
### External
- Bootstrap table/card/button classes.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
