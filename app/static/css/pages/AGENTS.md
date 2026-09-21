<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# pages

## Purpose
One stylesheet per page, linked from that template's `extra_css` block after the global design system. Several are thin wrappers that `@import` a component sheet plus the page rules living one level up in `../`.

## Key Files
| File | Description |
|------|-------------|
| `dashboard.css` | Dashboard KPI fragments; imports `components/kpi-card.css` and `../dashboard.css` |
| `dns.css`, `peers.css`, `traffic.css`, `users.css`, `login.css` | Wrappers: only `@import` lines (kpi-card / responsive-table / wb-state plus `../<page>.css`) |
| `nodes.css` | Nodes page: flag sizing vars, dropdowns escaping table clipping, FQDN layout |
| `settings.css` | Settings tabs (large); more settings CSS is inline in `templates/settings/_css.html` |
| `about.css` | About page cards and changelog markdown styling |
| `change-password.css`, `otp-setup.css`, `passkey-setup.css` | Forced-setup/auth pages built on `auth_base.html`; card width/min-height and inline-style replacements |

## For AI Agents
### Working In This Directory
- When adding a page, create `pages/<name>.css` and link it in the template's `extra_css` block. Note the split: rules for dashboard/dns/peers/traffic/users/login live in `../<name>.css`, not here.
- Page CSS must only compose tokens and components; do not restyle shared components.

### Testing Requirements
`node tools/ui-lint/run-ui-lint.mjs`

### Common Patterns
- Root class per page (`.about-page`, `.dns-page`, `.otp-setup-card`) scopes rules.

## Dependencies
### Internal
- `../components/`, `../utilities/wb-state.css`, `../*.css` page bodies; `../../../templates/`.
### External
- Bootstrap classes.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
