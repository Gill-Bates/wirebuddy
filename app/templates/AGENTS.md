<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# templates

## Purpose
Jinja2 templates rendered server-side: app pages and the onboarding fragment by `../api/frontend_pages.py`, the status pages by `../api/frontend_status.py`; the shared environment and its filters (`utc_iso`, `wbr_ip`, `truncate_ip`) are set up in `../api/frontend_shared.py`. Authenticated pages extend `base.html` (sidebar shell, global CSS/JS); unauthenticated and forced-setup pages extend `auth_base.html`; the public status pages are standalone documents.

## Key Files
| File | Description |
|------|-------------|
| `base.html` | App shell: loads theme.js, Bootstrap, the design-system CSS cascade and shared JS runtime; blocks `title`, `body_class`, `extra_css`, `content`, `extra_js`; `<body data-flag-base-url>`; key-mismatch banner |
| `auth_base.html` | Shared shell for login, change_password, otp_setup, passkey_setup (blocks `title`, `body_attrs`, `extra_css`, `content`, `extra_js`) |
| `dashboard.html`, `traffic.html`, `dns.html`, `peers.html`, `users.html`, `nodes.html`, `about.html` | Main pages; each links its `css/pages/*.css` and page JS. `nodes.html` and `dns.html` define local macros; `dashboard.html` also loads vendored GridStack and carries the widget markup (`gs-*` attributes, `data-widget-id`) |
| `settings.html` | Tabbed settings page; includes `settings/_tab_*.html` and loads settings JS |
| `login.html`, `change_password.html`, `otp_setup.html`, `passkey_setup.html` | Auth and forced-setup pages (extend `auth_base.html`) |
| `status.html`, `status_disabled.html` | Public status page and its disabled placeholder; standalone (own `<head>` loading `core/tokens.css`, `style.css`, `wb-ui-system.css`, `status.css`) |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `fragments/` | Markup fetched on demand; see `fragments/AGENTS.md` |
| `macros/` | Reusable Jinja macros; see `macros/AGENTS.md` |
| `settings/` | Settings tab and modal partials; see `settings/AGENTS.md` |

## For AI Agents
### Working In This Directory
- New page: extend `base.html`, set `title`, put CSS in `extra_css` and scripts in `extra_js`, add the route in `../api/frontend_pages.py`.
- No inline styles, scripts or handlers (CSP, see `../static/AGENTS.md`); use classes from `../static/css/` and JS from `../static/js/`. Do not emit duplicate element IDs.
- Emit datetimes as UTC with `|utc_iso` and let `WBFormat` localise them in the browser; never call `.strftime(` in a template (`tests/test_time.py` enforces this).
- Let Jinja autoescape; only use `|safe` on trusted content.

### Testing Requirements
See `../static/AGENTS.md`. Template-reading tests: `test_time.py` (all templates, `users.html`), `test_peer_stale.py` (`peers.html`), `test_settings_stale_slider.py` and `test_frontend_cleanup.py` (`settings/` tabs), ui-lint `modal-keyboard.spec.js` (`settings/_modals.html`).

### Common Patterns
- `<title>Name – WireBuddy</title>`, `aria-label` on controls, `data-*` hooks for JS.

## Dependencies
### Internal
- `../static/`, `../api/frontend_pages.py` (context variables such as `key_mismatch`).
### External
- Jinja2.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
