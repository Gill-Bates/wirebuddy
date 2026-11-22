<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# configuration

## Purpose
Reference for configuring WireBuddy: environment variables, WireGuard, DNS, monitoring, security and the public status page.

## Key Files
| File | Description |
|------|-------------|
| `environment.md` | Environment variable reference: core app, web server, reverse proxy/origin handling, passkeys, node mode, GeoIP, security and runtime tuning, development/CI switches, settings managed in the UI, precedence, verifying effective configuration |
| `wireguard.md` | Server endpoint, global settings, interfaces, peer routing, IPv6, traffic analysis, related API routes |
| `dns.md` | Resolver settings, blocklists, custom rules, dual-stack, DNSSEC, query logging, ad-blocker mode, per-peer blocklists, WireGuard integration, troubleshooting, API |
| `monitoring.md` | Enabling traffic analysis, dashboard interfaces, host conntrack accounting, sampling, storage paths, retention, GeoIP databases, backups, API, external monitoring, troubleshooting |
| `security.md` | Passwords, sessions and cookies, built-in HTTPS listener, reverse proxies, host validation, CSRF, security headers, rate limiting and lockouts, TOTP/passkeys, Swagger, status page, secrets at rest, container hardening, logging, a "Not Currently Implemented" list |
| `status-page.md` | Enabling the public status page, access model, what it shows, disabled behaviour, security notes, rate limiting, monitoring guidance, troubleshooting |

## For AI Agents

### Working In This Directory
- `environment.md` must match the variables actually read in `app/` (`os.getenv`/`os.environ` across modules, not only `app/utils/config.py`) and set in `docker/docker-compose*.yml`. `WIREBUDDY_BIND_HOST` (set by `app/server.py`) and `WIREBUDDY_LISTENER_STATE` (set by `docker/entrypoint.sh`) are internal hand-offs, not operator settings; names the app does not read belong in the "not read" paragraph at the end of `environment.md`.
- Document defaults and units exactly as in code; note which settings live in the DB (GUI) versus env.
- No real keys or tokens; use placeholders.

### Testing Requirements
- Strict Zensical build, see `../AGENTS.md`.

### Common Patterns
- Setting tables (name, default, description) followed by short examples.

## Dependencies

### Internal
- `../features/` (usage guides), `../security/`, `docker/docker-compose*.yml`, `app/utils/config.py` and the other env-reading modules in `app/`.

### External
- None.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
