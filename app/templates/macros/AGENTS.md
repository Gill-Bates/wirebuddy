<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# macros

## Purpose
Jinja macros shared by several pages, keeping repeated markup consistent.

## Key Files
| File | Description |
|------|-------------|
| `peer_form.html` | `peer_routing_fields(edit=false)`: node picker, routing, DNS/filtering and client-isolation fields shared by the Add and Edit peer modals in `peers.html`; `edit=true` emits the Edit modal's `edit-`/`edit…Help` ids that `static/js/peers.js` binds to. Import `with context` (reads `nodes`, `local_fqdn`, `local_country_code`) |
| `nav.html` | `nav_item(path, icon, label, external)` sidebar link; must not emit element IDs (duplicate-ID guard) |
| `kpi.html` | `kpi_card(icon, label, value_id, value, subtext, status_class, live)` KPI tile styled by `components/kpi-card.css` |
| `geo.html` | `geo_badge` and `geo_ip_stack`: country flag, city and AS-org display for IPs |
| `password.html` | `password_requirements(requirements_id, extra_class)` live password checklist shared by `../users.html` and `../change_password.html`; the `data-req` keys are the contract with the password checks in `static/js/` |

## For AI Agents
### Working In This Directory
- Import with `{% from 'macros/x.html' import y %}`; add `with context` when the macro reads page context (`base.html`, `status.html` and `peers.html` do). Keep signatures backward compatible.

### Testing Requirements
See `../../static/AGENTS.md`.

### Common Patterns
- Macros take IDs as parameters so JS can target them; use `{%- -%}` whitespace control.

## Dependencies
### Internal
- Importers: `../base.html` (`nav`), `../dns.html` (`kpi`), `../peers.html` (`peer_form`, `geo`), `../users.html` (`geo`, `password`), `../change_password.html` (`password`), `../status.html` (`geo`); `../../static/css/components/kpi-card.css`.
### External
- Jinja2.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
