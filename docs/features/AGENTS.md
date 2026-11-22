<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# features

## Purpose
User guides for each WireBuddy capability: WireGuard management, DNS ad-blocking, monitoring, GeoIP, multi-node clustering, Let's Encrypt, backup/restore, speed tests and user management.

## Key Files
| File | Description |
|------|-------------|
| `wireguard.md` | Interfaces, peers, client configs, routing modes, DNS and isolation, status/traffic, global preshared key, limits and host responsibilities |
| `dns.md` | Unbound ad-blocking: requirements, setup, blocklists, custom rules, query log, DNS-over-TLS, DNSSEC, temporary disable, statistics, troubleshooting |
| `monitoring.md` | Dashboard (draggable per-user GridStack layout, `/api/dashboard/layout`), traffic page, collection intervals, storage/retention, remote nodes, API access, export, troubleshooting |
| `geoip.md` | GeoIP database lifecycle, UI maps, destination traffic analysis, API endpoints, troubleshooting |
| `multi-node.md` | Master/node clustering: architecture, security model, deployment (`docker/docker-compose.node.yml`, enrollment), usage, sync behaviour, configuration, troubleshooting, API, FAQ |
| `acme.md` | Let's Encrypt/ACME: prerequisites, built-in HTTPS listener, requesting/using certificates, renewal, delete vs revoke, endpoints, troubleshooting |
| `backup.md` | Backup and restore: contents (v2: schema + configuration, optional TSDB; signed `.tar.gz`), manual and scheduled backups, restore, API, troubleshooting |
| `speedtest.md` | Speed test via librespeed-cli: how it works, configuration, schedules, running, history/storage, troubleshooting, API |
| `users.md` | Roles, creating users, password policy, editing/deleting, TOTP MFA, passkeys, sessions, login info, admin and current-user API, best practices |

## For AI Agents

### Working In This Directory
- Describe behaviour as implemented; check `app/api/` and templates when in doubt.
- Speed-test execution (librespeed-cli call, run lease) and GeoLite2 download, update and lookup live in the `gillbates-speedtest` and `gillbates-geoip` packages (`app/utils/geoip.py` only builds their configuration); check the version pinned in `pyproject.toml` before documenting their behaviour.
- Backup docs must reflect v2 (config data is restored; an empty restore is a bug).
- Link to `../configuration/` for settings rather than duplicating tables.
- Most pages use `title:` front matter; `monitoring.md`, `multi-node.md`, `speedtest.md`, `users.md` start straight at the `#` heading.

### Testing Requirements
- Strict Zensical build, see `../AGENTS.md`.

### Common Patterns
- Overview, how it works, step-by-step usage, API endpoints, troubleshooting.

## Dependencies

### Internal
- `../configuration/`, `../security/`, `../api/`, `docker/docker-compose.node.yml` (multi-node), `app/` features, the `gillbates-speedtest` and `gillbates-geoip` packages.

### External
- Referenced services: Let's Encrypt, MaxMind GeoLite2, Unbound, librespeed-cli (LibreSpeed servers) as described in the pages.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
