<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# features

## Purpose
User guides for each WireBuddy capability: WireGuard management, DNS ad-blocking, monitoring, GeoIP, multi-node clustering, Let's Encrypt, backup/restore, speed tests and user management.

## Key Files
| File | Description |
|------|-------------|
| `wireguard.md` | Interfaces, peers, client configs, routing modes, DNS and isolation, status/traffic, global preshared key |
| `dns.md` | Unbound ad-blocking: requirements, setup, blocklists, custom rules, query log, DNS-over-TLS |
| `monitoring.md` | Dashboard, traffic page, collection intervals, storage/retention, remote nodes, API access, export, troubleshooting |
| `geoip.md` | GeoIP database lifecycle, UI maps, destination traffic analysis, API endpoints, troubleshooting |
| `multi-node.md` | Master/node clustering: architecture, security model, deployment (compose, enrollment), usage; largest page |
| `acme.md` | Let's Encrypt/ACME: prerequisites, built-in HTTPS listener, requesting/using certificates, renewal, delete vs revoke, endpoints |
| `backup.md` | Backup and restore: contents (v2: schema + configuration, optional TSDB), manual and scheduled backups, restore, API |
| `speedtest.md` | Speed test via librespeed-cli: how it works, configuration, schedules, running, history/storage, troubleshooting, API |
| `users.md` | Roles, creating users, password policy, editing/deleting, TOTP MFA, passkeys, sessions, login info |

## For AI Agents

### Working In This Directory
- Describe behaviour as implemented; check `app/api/` and templates when in doubt. Backup docs must reflect v2 (config data is restored; an empty restore is a bug).
- Link to `../configuration/` for settings rather than duplicating tables.
- Most pages use `title:` front matter; `monitoring.md`, `multi-node.md`, `speedtest.md`, `users.md` start straight at the `#` heading.

### Testing Requirements
- `mkdocs build -f docs/mkdocs.yml --strict`.

### Common Patterns
- Overview, how it works, step-by-step usage, API endpoints, troubleshooting.

## Dependencies

### Internal
- `../configuration/`, `../security/`, `../api/`, `docker/docker-compose.node.yml` (multi-node), `app/` features.

### External
- Referenced services: Let's Encrypt, MaxMind GeoLite2, Unbound, librespeed-cli (LibreSpeed servers) as described in the pages.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
