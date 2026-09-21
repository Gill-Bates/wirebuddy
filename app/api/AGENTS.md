<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->

# api

## Purpose
FastAPI routers for every HTTP surface of WireBuddy: authentication (password, TOTP, passkeys), user management, WireGuard interfaces/peers/settings/statistics, DNS/ad-blocker control, ACME certificates, backup/restore, speedtests, master/node management and node-facing sync endpoints, plus the server-rendered UI pages and public status page. Routers are mounted in `app/main.py`; `wireguard.py` aggregates the WireGuard sub-routers under `/api/wireguard`.

## Key Files
| File | Description |
|------|-------------|
| `auth.py` | Login, MFA verify, logout, `/me`, OTP setup; `get_current_user`, `require_admin`, trusted-proxy client-IP and HTTPS enforcement, IP lockout; in-memory MFA/recovery caches |
| `passkeys.py` | WebAuthn registration/login, passkey listing/deletion/reset, per-user enable/disable |
| `users.py` | User CRUD, password change/reset, admin OTP enable/confirm/disable; `require_self_or_admin` |
| `wireguard.py` | Aggregator router including all `wireguard_*` routers (order matters: CRUD before interfaces) |
| `wireguard_interfaces.py` | List/get/up/down/restart/config for interfaces |
| `wireguard_interfaces_crud.py` | Create/update/delete interfaces, next-subnet suggestion, default firewall rules |
| `wireguard_peers.py` | Peer CRUD, IP allocation, runtime `wg set`, node notification and tag regeneration |
| `wireguard_peers_config.py` | Per-peer stats, QR code and client config download |
| `wireguard_settings.py` | Global WG settings, global PSK (masked/reveal/generate), update check, traffic accounting status |
| `wireguard_config.py` | Writes `wgX.conf` files to `/etc/wireguard` (contains decrypted keys; regenerated from the encrypted DB on each start, not tmpfs), regenerate/sync helpers |
| `wireguard_isolation.py` | Builds/applies/cleans client-isolation iptables/ip6tables rules |
| `wireguard_utils.py` | Helpers: interface-name validation, `wg` command runners with timeouts, `wg show dump` parsing, keypair/PSK generation, blocklist ID filtering |
| `wireguard_stats.py` | Admin traffic and connection statistics from the TSDB |
| `wireguard_stats_country.py` | Traffic by country/ASN from conntrack snapshots + GeoLite2, with TTL cache |
| `wireguard_stats_geo.py` | Peer locations, enriched peer list, TSDB stats/retention/reset/maintenance, peer log deletion |
| `dns.py` | DNS/Unbound control: status, selftest, trend, start/stop/restart, config, blocklist sources/update, custom rules, query logs, top domains, upstream test, ad-blocker mode |
| `acme.py` | Lightweight ACME (Let's Encrypt) client and certificate request/renewal/challenge endpoints |
| `backup.py` | Backup v2 (.tar.gz with schema + config, optional TSDB) download, validate, restore, schedule, HMAC and safe tar extraction |
| `speedtest.py` | Speedtest settings, run (with SSE stream), history, storage and retention |
| `nodes.py` | Admin CRUD for remote nodes, token regeneration, restart, remote speedtest |
| `nodes_sync.py` | Node-facing endpoints (enroll, heartbeat, config, SSE events, metrics, command ack), not user auth. Auth is the bearer session secret alone; the client-cert fingerprint is only additionally enforced when an explicitly trusted mTLS proxy injects it (`WIREBUDDY_TRUSTED_PROXIES`), otherwise self-asserted fingerprint headers are ignored |
| `network_stats.py` | Host/WG interface throughput from `/sys/class/net` with history |
| `frontend_pages.py` | UI page routes (`/ui/...`), `/api/system/status`, about/changelog data |
| `frontend_shared.py` | Shared frontend router primitives: context-aware Jinja templates, redirect helpers, GeoIP lookup, CSRF token, `require_user_or_redirect` |
| `frontend_status.py` | Public status page (`/status`): DNS probe/leak indicators, client IP and geo resolution |
| `sse.py` | Server-Sent Events formatting and queue fan-out helpers |
| `response.py` | `OkResponse`, `ok_response` common envelope |

## For AI Agents

### Working In This Directory
- Python files use **tabs** and start with the standard header block (`#!/usr/bin/env python3`, file path, `Copyright (C) 2026 Gill-Bates`, SPDX MIT); keep that style.
- Router prefixes are set in `app/main.py`, not in the module (e.g. `/api/dns`, `/api/nodes`); `speedtest.py` is mounted under `/api/wireguard`.
- New WireGuard endpoints go in the matching `wireguard_*` module and are picked up by `wireguard.py`; keep static routes (e.g. `/interfaces/next-subnet`) before parameterised ones.
- Node-sync endpoints must not depend on user auth; user endpoints must use `get_current_user`/`require_admin`.
- Never log or return secrets (private keys, PSKs, api secrets) except in explicit reveal/download endpoints.

### Testing Requirements
- Add or extend tests in `/opt/wirebuddy/tests` and run `pytest` (e.g. `test_login_lockout.py`, `test_user_security.py`, `test_backup_schema_only.py`, `test_audit_hardening.py` cover this layer).
- Backup changes must keep the v2 invariant: restore returns schema and configuration.

### Common Patterns
- Endpoints wrap blocking DB/subprocess work with `asyncio.to_thread`/`run_in_threadpool` and short-lived DB connections.
- Responses use the `ok_response` envelope from `response.py`; errors are `HTTPException`.
- Mutating peer/interface endpoints regenerate configs/DNS tags and notify nodes.
- Cookie-auth requests are CSRF-protected by `app/middleware/csrf.py`.

## Dependencies

### Internal
- `app/db`, `app/models`, `app/dns`, `app/node`, `app/utils`, `app/tasks`, `app/runtime`, `app/speedtest`, `app/templates`, `app/middleware`.

### External
- FastAPI, Pydantic, Jinja2, WireGuard tools (`wg`), iptables, WebAuthn library, pyotp, qrcode, cryptography, httpx, GeoLite2 data.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
