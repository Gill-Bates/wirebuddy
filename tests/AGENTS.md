<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# tests

## Purpose
Flat pytest suite for the WireBuddy backend. The tests are focused unit and regression tests for security hardening, persistence boundaries (backup, node and user DB helpers), TLS handling and small utility modules. They use `tmp_path`, in-memory SQLite and monkeypatching rather than a running server.

## Key Files
| File | Description |
|------|-------------|
| `conftest.py` | Shared `conn` fixture: fresh in-memory SQLite with the full schema and the app's datetime adapters |
| `test_audit_hardening.py` | Audit-driven hardening: server-generated request IDs, password/node-secret length limits, canonical https expected origin, private lock/config dirs, ACME redirect uses configured origin, exclusive application lock and conntrack-sampler leadership, shared rate-limit backend requirement for multiple workers, absolute paths for privileged binaries, DNS ingestion backoff overflow |
| `test_async_utils.py` | `spawn_tracked_task`: task held until done then released, failures logged under the caller's logger, cancellation not reported |
| `test_backup_schema_only.py` | Backup archive format v2 (schema + data, optional TSDB filtered by range): range override validation, DDL-only schema export, data export tables, tar member validation, schema/data SQL validators (reject row data, non-INSERT, mismatched tables), manifest checks, restore preserves configuration, scheduled backups use persisted options |
| `test_coerce.py` | Central persisted-boolean coercion: truthy/falsy sets, fail-closed handling of non-canonical ints and unknown types, `coerce_db_bool` re-export from auth, settings helpers share the sets |
| `test_config_derivation.py` | Env-var consolidation in `app/utils/config.py`: trusted proxies default to loopback, explicit/invalid values, `WIREBUDDY_PUBLIC_ORIGIN` derivation of hostname, `force_https` and allowed hosts |
| `test_csrf_middleware.py` | `CSRFMiddleware` characterisation: token cookie issue/reuse, Origin/Referer and token checks, cookie-only API enforcement (bearer and exempt login paths pass), form token, multipart/oversized/invalid-length rejection, configured origins |
| `test_dns_run_exec.py` | `run_exec` never raises: success, non-zero exit, missing binary and timeout all come back as `(code, stdout, stderr)` |
| `test_dns_listen_preflight.py` | Unbound listen-socket preflight: parsing IPv4/IPv6 addresses and ports from config, default port 53, busy TCP/UDP port detection, unassigned/invalid addresses ignored, `ss` process/pid regex |
| `test_frontend_shared_geoip.py` | GeoIP frontend adapter `lookup_ip_cached`: returns None for missing record and copies the mapping |
| `test_login_lockout.py` | Login throttling incl. username-wide policy: distributed failures from distinct IPs lock, below-threshold does not, cap bound, success clears, other users unaffected |
| `test_node_db.py` | Node/auth DB helpers: command payload serialisation rejects non-finite values, heartbeat status transitions (pending/offline/error), enroll then heartbeat, claim limit clamping, invalid hours/thresholds rejected |
| `test_passkey_login_session.py` | Passkey login issues its session through `_issue_session`: HTTPS policy rejection rolls back token and sign count together; cookie flags match the password login |
| `test_peer_tags.py` | One peer-tag policy for every trigger: disabled global ad-blocker writes empty tags, enabled writes per-peer tags |
| `test_speedtest_guard.py` | Speedtest run guard hardening: cooldown file read rejects symlinks, non-regular files (fstat) and oversized files; a sync `with` on an async-acquired `SpeedtestRunLease` raises but still releases the module-level `asyncio.Lock` |
| `test_status_dns_leak.py` | Status-page DNS leak indicator: a recent query from the client is verified, none yields a warning (never `None`) |
| `test_subprocess_limits.py` | Async subprocess helper: captured stdout/stderr/returncode, output size limits on both streams, timeouts (including SIGTERM-ignoring children), runaway output, cancellation, empty command and non-positive timeout rejected, missing binary |
| `test_time.py` | Timezone-aware time utilities: `parse_utc`, `parse_db_timestamp`, `ensure_utc` with Z/offset/naive/semi-aware tzinfo and unsupported types |
| `test_tls_material.py` | TLS material selection for the built-in HTTPS listener: hostname normalisation (IDN, IP literals, path escape), preferring valid Let's Encrypt pairs, fallback on unparseable/expired/mismatched certs, self-signed reuse and regeneration |
| `test_user_security.py` | User-management invariants: user listing omits stored secrets, recovery-code update requires current value, last admin cannot be deleted at DB layer, OTP setup confirm requires self |
| `test_utils_hardening.py` | Utility regressions: node metric point selection (timestamp precedence, latest per node), token encrypt/decrypt and pepper checks, version comparison and immutable update-check cache, scheduler job argument validation |

## For AI Agents

### Working In This Directory
- One `test_<area>.py` per area; files start with the project header block (path, copyright, SPDX) and use tabs like the app code.
- Add a regression test alongside any security or persistence fix; name it after the behaviour.
- Keep tests hermetic: use `tmp_path`, `monkeypatch`, in-memory SQLite; no network, no real WireGuard/Unbound.
- Never put real secrets in fixtures.

### Testing Requirements
- Run `pytest` from the repo root (Python 3.13 venv with dev extras); use `pytest tests/test_x.py -k name` to narrow.
- A backup-related change must keep `test_backup_schema_only.py` green (restore must retain configuration data).

### Common Patterns
- The shared `conn` fixture in `conftest.py` builds a fresh SQLite schema per test; use it rather than redefining one; `pytest.mark.parametrize` for bad inputs; async helpers driven with `asyncio.run`-style wrappers.

## Dependencies

### Internal
- `app/` modules: backup, db (auth, nodes, users), utils (time, coerce, subprocess, crypto, scheduler), tls, dns preflight, frontend shared helpers, runtime locks.

### External
- `pytest`, `cryptography` (cert generation in TLS tests), stdlib `sqlite3`, `socket`, `asyncio`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
