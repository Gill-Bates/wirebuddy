<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# utils

## Purpose
Cross-cutting helpers shared by the API, DB, DNS, node and task layers: configuration, crypto and secrets, auth helpers (TOTP, passkeys), TLS material, GeoIP and conntrack traffic analysis, subprocess and scheduling primitives, cross-process locks, migrations and small formatting/time helpers.

## Key Files
| File | Description |
|------|-------------|
| `config.py` | `Config`, `load_dotenv`, `load_config`, `get_config`: environment-driven settings and defaults; `get_mtls_proxy_networks` (`WIREBUDDY_MTLS_PROXIES`), `parse_strict_bool`, `enrollment_accept_v1`, `enrollment_token_version` |
| `deps.py` | FastAPI dependency helpers (`AppState`, `get_conn`, `get_tsdb_dir`, `get_dns_dir`, `get_config`) |
| `key_domains.py` | Key-domain separation for `WIREBUDDY_SECRET_KEY`: derives the backup-HMAC and enrollment-token-HMAC keys from distinct contexts (`derive_backup_hmac_key`, `derive_enrollment_hmac_key`); the enrollment HMAC is legacy (v1 tokens) |
| `vault.py` | Fernet encryption of secrets at rest (private/preshared keys), pepper handling |
| `crypto.py` | Password hashing/verification, session token generation, hashing and expiry |
| `otp.py` | TOTP secrets, provisioning URIs, verification, recovery codes |
| `passkeys.py` | WebAuthn registration/authentication with SQLite-backed challenges |
| `node_token.py` | v1 HMAC and v2 Ed25519 token generation/verification and node cert helpers |
| `enrollment_signing.py` | v2 enrollment token codec (`wb2.<payload>.<signature>`) and Ed25519 primitives |
| `enrollment_keys.py` | Master enrollment signing key (seed vault-encrypted in the `settings` table, fails closed when unreadable), `wbpk2:` public key, `verify_any`, v1 use record |
| `tls.py` | TLS material resolution for the built-in HTTPS listener (Let's Encrypt, else self-signed) |
| `acme_http.py` | Plain-HTTP app on port 80 for ACME HTTP-01 validation |
| `geoip.py` | Thin binding over `gillbates-geoip`: maps the `WIREBUDDY_GEOIP_*` environment and `data/geolite2/` onto the package and keeps the `lat/lon/city/country`/`asn/as_org` result shapes |
| `flags.py` | Country flags over `gillbates-country-flags`: `FLAG_BASE_URL` (`/static/flags`, served by `main.py` from the bundled SVGs) and `local_flag_svg(code)`; templates get `flag_base_url`, JS reads `<body data-flag-base-url>` via `core/flags.js` |
| `logging_setup.py` | `setup_logging` over `gillbates-logging` (`LineLog("wirebuddy")`), aiosqlite humanizing filter, uvicorn logger wiring (their records propagate to the root handler; `server.py` calls `setup_logging` before its first log line), static-file access-log downgrade |
| `conntrack.py` | Reads kernel conntrack to attribute VPN client traffic to countries/ASNs; sampler leadership |
| `migration.py` | Versioned schema migrations (`schema_version` table) |
| `backup_lock.py` | Cross-process POSIX advisory locks for backup/restore |
| `scheduler.py` | Lightweight async periodic-job scheduler (`Scheduler`, `JobStatus`); `next_delay` lets a job follow a calendar rule instead of a fixed interval |
| `fs.py` | `fsync_dir(path)`: fsync a directory so preceding renames survive a crash (used by the node cert, state and WireGuard config writes in `app/node/`) |
| `binaries.py` | `first_executable(candidates)`: first executable regular file from a fixed candidate list, used to resolve `wg`/`ip`/`iptables` without PATH lookup |
| `subprocess.py` | `run_command` with timeout, output limits and graceful shutdown; `ProcResult` |
| `speedtest_window.py` | Night-window timing (02:00-04:00 UTC) shared by master and nodes |
| `socket_peer.py` | `SocketPeerMiddleware` stores the real TCP peer in `scope["wb.socket_peer"]`; `wrap_with_proxy_headers` |
| `rate_limit.py` | In-memory sliding-window rate limiter: `rate_limit(limit)` route dependency, `SlidingWindow`, 429 exception |
| `request_id.py` | Request ID middleware |
| `network.py` | IP parsing and allowed-IPs with DNS routes; `resolve_client_ip(request)` returns the client IP, trusting `X-Forwarded-For`/`X-Real-IP` only when the socket peer is a configured trusted proxy (shared by `rate_limit.py` and `api/auth`) |
| `qrimage.py` | QR PNG generation with optional logo and peer label |
| `version.py` | Version/build info and update check |
| `time.py`, `coerce.py`, `formatting.py`, `async_utils.py`, `tsdb_helpers.py` | Small helpers: UTC clock and parsing (`utcnow`, `ensure_utc`, `parse_utc`, `parse_db_timestamp`, `to_utc_iso`, the source of the `utc_iso` template filter), DB boolean coercion, bandwidth labels for the public status page (`format_optional_bandwidth_mbit`; page templates take raw numbers and `WBFormat` formats them in the browser), interruptible sleep/task cancel, latest-by-node TSDB mapping |
| `banner.py`, `onboarding.py` | Startup banner (once-per-process-tree lock here, drawing by `gillbates-logging`); onboarding step definitions for the modal template |
| `__init__.py` | Package docstring only |

## For AI Agents

### Working In This Directory
- Modules here should stay low-level: avoid importing from `app/api` (only `acme_http.py` does so today, lazily).
- Security-critical files (`vault.py`, `crypto.py`, `node_token.py`, `passkeys.py`, `tls.py`, `backup_lock.py`): never log secrets, keep constant-time comparisons and restrictive file permissions.
- The server works in UTC only and never reads the process time zone (`TZ`, `/etc/localtime`, `zoneinfo`); `tests/test_time.py` fails on `datetime.now()` without a zone, `localtime`, `astimezone()` without argument and similar. Time zone and number format are the browser's concern (`WBFormat`).
- Use `utils/time` (timezone-aware UTC) instead of naive `datetime`, `utils/subprocess` instead of raw subprocess calls, and `utils/binaries.first_executable` instead of PATH lookup for trusted binaries.
- `version.py` resolves the version from `pyproject.toml` (the single source of truth), then installed distribution metadata, then `'dev'`; there is no VERSION file.

### Testing Requirements
- Run `pytest` from the repo root. Module tests: `test_utils_hardening.py` (`network`, `scheduler`, `tsdb_helpers`, `vault`), `test_audit_hardening.py` (security modules, `config`, `conntrack`), `test_async_utils.py`, `test_coerce.py`, `test_config_derivation.py`, `test_conntrack_baseline_commit.py` (`conntrack`), `test_country_flags.py`, `test_geoip_dns_timeout.py`, `test_logging_cleanup.py`, `test_rate_limit.py`, `test_resolve_client_ip.py`, `test_subprocess_limits.py`, `test_time.py`, `test_tls_material.py`, `test_user_security.py`.

### Common Patterns
- Lazy-initialised, thread-safe singletons with explicit reset/close functions for tests.
- Atomic file writes with fsync; POSIX `fcntl` locks for cross-process coordination.

## Dependencies

### Internal
- `app/db/` (`sqlite_runtime`, `sqlite_passkeys`), `app/api/acme`; most modules depend only on each other (`config`, `geoip`, `backup_lock`).

### External
- `cryptography`, `webauthn`, `fastapi`, `qrcode`/`Pillow`, `gillbates-country-flags`/`-geoip`/`-logging`, MaxMind GeoLite2 (via `gillbates-geoip`), `conntrack` kernel table, stdlib `sqlite3`, `fcntl`, `hmac`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
