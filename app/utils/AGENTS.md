<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# utils

## Purpose
Cross-cutting helpers shared by the API, DB, node, runtime and tasks layers: configuration, crypto and secrets, auth helpers (TOTP, passkeys), TLS material, GeoIP and conntrack traffic analysis, subprocess and scheduling primitives, cross-process locks, migrations and small formatting/time helpers.

## Key Files
| File | Description |
|------|-------------|
| `config.py` | `Config`, `load_dotenv`, `load_config`, `get_config`, `reset_config`: environment-driven settings and defaults |
| `deps.py` | FastAPI dependency helpers (`AppState`, `get_conn`, `get_tsdb_dir`, `get_dns_dir`, `get_config`) |
| `vault.py` | Fernet encryption of secrets at rest (private/preshared keys), pepper handling, key rotation |
| `crypto.py` | Password hashing/verification, session token generation, hashing and expiry |
| `otp.py` | TOTP secrets, provisioning URIs, verification, recovery codes |
| `passkeys.py` | WebAuthn registration/authentication with SQLite-backed challenges |
| `node_token.py` | Enrollment token generation/verification (HMAC-SHA256) and node cert helpers |
| `tls.py` | TLS material resolution for the built-in HTTPS listener (Let's Encrypt, else self-signed) |
| `acme_http.py` | Plain-HTTP app on port 80 for ACME HTTP-01 validation |
| `geoip.py` | MaxMind GeoLite2 download/update and thread-safe IP to location/ASN lookup |
| `conntrack.py` | Reads kernel conntrack to attribute VPN client traffic to countries/ASNs; sampler leadership |
| `migration.py` | Versioned schema migrations (`schema_version` table) |
| `backup_lock.py` | Cross-process POSIX advisory locks for backup/restore |
| `scheduler.py` | Lightweight async periodic-job scheduler (`Scheduler`, `JobStatus`) |
| `subprocess.py` | `run_command` with timeout, output limits and graceful shutdown; `ProcResult` |
| `speedtest_window.py` | Night-window timing shared by master and nodes |
| `rate_limit.py` | slowapi limiter configuration and key function |
| `request_id.py` | Request ID middleware |
| `network.py` | IP parsing and allowed-IPs with DNS routes |
| `qrimage.py` | QR PNG generation with optional logo and peer label |
| `version.py` | Version/build info and update check |
| `time.py`, `coerce.py`, `formatting.py`, `async_utils.py`, `tsdb_helpers.py` | Small helpers: UTC time parsing, DB boolean coercion, bandwidth formatting, interruptible sleep/task cancel, latest-by-node TSDB mapping |
| `banner.py`, `onboarding.py` | Startup banner; onboarding step definitions for the modal template |
| `__init__.py` | Package docstring only |

## For AI Agents

### Working In This Directory
- Use tabs for indentation and keep the standard file header block (path, copyright, SPDX MIT).
- Modules here should stay low-level: avoid importing from `app/api` (only `acme_http.py` does so today, lazily).
- Security-critical files (`vault.py`, `crypto.py`, `node_token.py`, `passkeys.py`, `tls.py`, `backup_lock.py`): never log secrets, keep constant-time comparisons and restrictive file permissions.
- Use `utils/time` (timezone-aware UTC) instead of naive `datetime`, and `utils/subprocess` instead of raw subprocess calls.
- `version.py` resolves the version from `pyproject.toml` (the single source of truth), then installed distribution metadata, then `'dev'`; there is no VERSION file.

### Testing Requirements
- Tests live in `/opt/wirebuddy/tests` (pytest, run `pytest` from the repo root). Existing: `test_utils_hardening.py`, `test_coerce.py`, `test_time.py`, `test_subprocess_limits.py`, `test_tls_material.py`, `test_user_security.py`, `test_login_lockout.py`.

### Common Patterns
- Lazy-initialised, thread-safe singletons with explicit reset/close functions for tests.
- Atomic file writes with fsync; POSIX `fcntl` locks for cross-process coordination.

## Dependencies

### Internal
- `app/db/` (`sqlite_runtime`, `sqlite_passkeys`), `app/api/acme`; most modules depend only on each other (`config`, `geoip`, `backup_lock`).

### External
- `cryptography`, `webauthn`, `fastapi`, `slowapi`, `qrcode`/`Pillow`, MaxMind GeoLite2, `conntrack` kernel table, stdlib `sqlite3`, `fcntl`, `hmac`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
