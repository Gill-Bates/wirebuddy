<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# configuration

## Purpose
Reference for configuring WireBuddy: environment variables, WireGuard, DNS, monitoring, security and the public status page.

## Key Files
| File | Description |
|------|-------------|
| `environment.md` | Environment variable reference: core app, web server, reverse proxy/origin handling, passkeys, node mode, GeoIP, security and runtime tuning |
| `wireguard.md` | Server endpoint, global settings, interfaces, peer routing, IPv6, traffic analysis, related API routes |
| `dns.md` | Resolver settings, blocklists, custom rules, dual-stack, DNSSEC, query logging, ad-blocker mode |
| `monitoring.md` | Enabling traffic analysis, dashboard interfaces, host conntrack accounting, sampling, storage paths, retention, GeoIP databases, backups |
| `security.md` | Passwords, sessions and cookies, built-in HTTPS listener, reverse proxies, host validation, CSRF, security headers, rate limiting and lockouts |
| `status-page.md` | Enabling the public status page, access model, what it shows, disabled behaviour, security notes, rate limiting |

## For AI Agents

### Working In This Directory
- `environment.md` must match variables actually read in `app/` (config module) and the compose files in `docker/`.
- Document defaults and units exactly as in code; note which settings live in the DB (GUI) versus env.
- No real keys or tokens; use placeholders.

### Testing Requirements
- `mkdocs build -f docs/mkdocs.yml --strict`.

### Common Patterns
- Setting tables (name, default, description) followed by short examples.

## Dependencies

### Internal
- `../features/` (usage guides), `../security/`, `docker/docker-compose*.yml`, `app/config*`.

### External
- None.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
