<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# tests

## Purpose
Flat pytest suite for the WireBuddy backend. The tests are focused unit and regression tests for security hardening, persistence boundaries (backup, node and user DB helpers), TLS handling and small utility modules. They use `tmp_path`, in-memory SQLite and monkeypatching rather than a running server.

## Key Files
| File | Description |
|------|-------------|
| `conftest.py` | Shared `conn` fixture (fresh in-memory SQLite with the full schema and the app's datetime adapters) and `threadsafe_conn` (same, `check_same_thread=False`, for handlers that hop to threadpool threads) |
| `test_audit_hardening.py` | Audit-driven hardening: server-generated request IDs, password/node-secret length limits, canonical https expected origin, private lock/config dirs, ACME redirect uses configured origin, exclusive application lock and conntrack-sampler leadership, shared rate-limit backend requirement for multiple workers, absolute paths for privileged binaries, DNS ingestion backoff overflow |
| `test_async_utils.py` | `spawn_tracked_task`: task held until done then released, failures logged under the caller's logger, cancellation not reported |
| `test_auth_session_hardening.py` | Mandatory password-change gate, cookie auth paths and TOTP replay regressions |
| `test_backup_fk_check.py` | Backup validate/restore run an explicit `PRAGMA foreign_key_check`, rejecting orphaned references even when the archive passes `integrity_check` (FK enforcement is off during import) |
| `test_bootstrap_admin.py` | `ensure_default_admin` prints the one-time password once to stdout, never to a log record and never to a file in the data dir; a second call prints nothing |
| `test_backup_schema_only.py` | Backup archive format v2 (schema + data, optional TSDB filtered by range): range override validation, DDL-only schema export, data export tables, tar member validation, schema/data SQL validators (reject row data, non-INSERT, mismatched tables), manifest checks, restore preserves configuration, scheduled backups use persisted options |
| `test_dashboard_layout.py` | Per-user dashboard layout endpoint: Pydantic bounds, cross-field validation (unknown/duplicate id, `x+w>12`, `y+h>MAX_Y` → 422, oversize → 400), `dashboard_layouts` table (round-trip, atomic replace, CHECK bounds, user-delete cascade, settings-key migration incl. invalid/orphaned rows, backup round trip), direct-handler round-trip/delete/isolation, and HTTP-layer auth (401 unauthenticated, 422 bad body, two-session isolation, cookie-auth PUT without CSRF → 403) |
| `test_dashboard_widget_registry.py` | Anti-drift guard: the JS widget registry (`dashboard_widgets.js`) and the Python allowlist (`_DASHBOARD_WIDGETS`) stay in sync (regex-based, no Node.js needed) |
| `test_client_isolation_failclosed.py` | Client isolation classifies iptables failures per operation: a failed rule-install (`-I`/`-A`) fails closed, while a pre-existing chain on `-N` or a missing chain/rule on cleanup stays benign; the sync input loader returns the seeded isolated-peer IPs |
| `test_coerce.py` | Central persisted-boolean coercion: truthy/falsy sets, fail-closed handling of non-canonical ints and unknown types, `coerce_db_bool` re-export from auth, settings helpers share the sets |
| `test_config_derivation.py` | Env-var consolidation in `app/utils/config.py`: trusted proxies default to loopback, explicit/invalid values, `WIREBUDDY_PUBLIC_ORIGIN` derivation of hostname, `force_https` and allowed hosts |
| `test_conntrack_baseline_commit.py` | Conntrack sampling advances its baseline only after a durable write: `prepare_country_traffic()` leaves it untouched, a failed persist re-delivers the identical delta, `commit_country_traffic()` rejects stale, reset and empty checkpoints, the single-phase wrapper still commits at once |
| `test_country_flags.py` | Flags served locally from `gillbates-country-flags`: `local_flag_svg` accepts a valid bundled code and rejects invalid or unbundled ones, the `/static/flags/<code>.svg` route answers without a session and 404s otherwise, and the CSP `img-src` names no CDN origin |
| `test_csrf_middleware.py` | `CSRFMiddleware` characterisation: token cookie issue/reuse, cookie lifetime extension on safe responses and a time-shifted long session, Origin/Referer and token checks, cookie-only API enforcement (bearer and exempt login paths pass), form token, multipart/oversized/invalid-length rejection, configured origins |
| `test_docker_geolite2_dir.py` | `docker/entrypoint.sh` prepares `/app/data/geolite2` in master and node mode without touching existing files or following symlinks; the Dockerfile creates the directory and ships no `.mmdb` |
| `test_enrollment_token_v2.py` | v1 and v2 enrollment tokens, downgrade and cross-version refusal, signing key custody and rotation, `/enroll` and key routes |
| `test_dns_blocked_flag.py` | `DnsQueryPoint.blocked` mirrors exactly what Unbound refused, so the DNS page filter, blockrate KPIs and Top Blocked Domains stay correct |
| `test_dns_custom_rule_precedence.py` | `resolve_effective_action` is the single source of truth for "ALLOW wins": the config generator and the log parser share it so the resolver's decision cannot disagree with what it enforces; also covers the regex-grammar reduction that rejects catastrophic-backtracking patterns structurally |
| `test_dns_dot_upstream.py` | The DoT upstream test (`_test_dot_server`) accepts a TCP length prefix that arrives across separate reads |
| `test_dns_ingestion_durability.py` | DNS ingestion stays consistent across partial write failures: a minute-bucket aggregate is not left skewed when one per-bucket counter fails (retry re-adds nothing for an already-written counter), and a failed forced offset save is surfaced so the writer retries instead of advancing past undurable data |
| `test_dns_ingestion_shutdown.py` | A crashed DNS writer must not wedge the tailer thread: the daemon sets the shared `stop_event` before cancelling the `to_thread` tailer so `_put_with_shutdown` unblocks on a full queue and `run_dns_ingestion` returns promptly |
| `test_dns_run_exec.py` | `run_exec` never raises: success, non-zero exit, missing binary and timeout all come back as `(code, stdout, stderr)` |
| `test_dns_trend_tsdb.py` | DNS trend covers the whole requested window through `tsdb.query_bucketed()` (no `MAX_QUERY_POINTS` clamp); short ranges keep producing the same buckets |
| `test_dns_listen_preflight.py` | Unbound listen-socket preflight: parsing IPv4/IPv6 addresses and ports from config, default port 53, busy TCP/UDP port detection, unassigned/invalid addresses ignored, `ss` process/pid regex |
| `test_frontend_cleanup.py` | Regression coverage for the retained Settings frontend helpers: locks the retention-slider mapping and template wiring (skips without Node.js) |
| `test_frontend_shared_geoip.py` | GeoIP frontend adapter `lookup_ip_cached`: None for a missing record or a failed lookup, and no local cache that keeps a cold-start miss once the database exists; `extract_geo_fields` passes only a two-letter ASCII country code (via `gillbates-country-flags`), so it is safe as a flag file name |
| `test_geo_inflight_cleanup.py` | A cancelled GeoIP lookup must clear its per-IP in-flight dedup entry (the cancellation is a `BaseException`), so a later lookup for the same IP succeeds instead of hanging |
| `test_geoip_dns_timeout.py` | Contract of the `app.utils.geoip` binding over `gillbates-geoip`: environment mapping into `GeoIPConfig`, result shapes, failed-download fallback (timeouts are tested in the package) |
| `test_https_auth_enforcement.py` | Opt-in `WIREBUDDY_REQUIRE_HTTPS_AUTH` upgrades the plaintext-auth warning to a hard rejection with a loopback exemption; default (flag off, GUI HTTPS off) stays a warning |
| `test_interface_delete_staging.py` | Interface delete keeps the config file until the DB transaction committed |
| `test_logging_cleanup.py` | aiosqlite message humanizing and the idempotent filter setup in `app.utils.logging_setup`; uvicorn loggers routed through the root handler by `app.server`'s log config |
| `test_mtls_proxies.py` | `WIREBUDDY_MTLS_PROXIES` trust (default none, independent of trusted proxies), real-peer capture by `SocketPeerMiddleware`, IPv6 and IPv4-mapped peers |
| `test_rate_limit.py` | In-memory rate limiter: limit-string parser, sliding window with fake clock, separate counters per route, IPv6 /64 bundling, MAX_KEYS fail-closed, thread safety, 429 body/headers, limiter counts before the auth dependency (also on the real app) |
| `test_login_lockout.py` | Login throttling incl. username-wide policy: distributed failures from distinct IPs lock, below-threshold does not, cap bound, success clears, other users unaffected |
| `test_mfa_code_normalization.py` | Preserves MFA code normalisation and Pydantic validation (whitespace/format handling) during cleanup |
| `test_network_stats.py` | `_counter_delta`: a falling interface counter is a reset and yields 0, never a fabricated spike |
| `test_node_db.py` | Node/auth DB helpers: command payload serialisation rejects non-finite values, heartbeat status transitions (pending/offline/error), enroll then heartbeat, claim limit clamping, invalid hours/thresholds rejected |
| `test_node_delete.py` | Node-deletion durability: after the irreversible removal signal, a failed final DB delete flags the node `error` instead of leaving it shown as online |
| `test_node_metrics_sync.py` | Reliable node-metric ingestion in `_process_heartbeat`: sequence-gap handling, per-metric idempotent checkpoint (no double-count on retry) and node-supplied observation timestamp threading |
| `test_passkey_login_session.py` | Passkey login issues its session through `_issue_session`: HTTPS policy rejection rolls back token and sign count together; cookie flags match the password login |
| `test_peer_create_keys.py` | `PeerCreate` key consistency matches the create-endpoint contract: both keys import an existing pair, a lone key is rejected, neither generates a fresh pair ("both or neither"); `preshared_key` stays independent |
| `test_peer_dns_resolution.py` | Per-interface DNS precedence when building peer configs: with the ad-blocker off, a generated `.conf`/QR uses the interface `dns` when set, else the global default; with it on, the internal resolver (gateway IP) is returned unchanged |
| `test_peer_policy_invariants.py` | Peer policy invariants hold against the effective persisted state, not just the fields present in a single `PeerUpdate` (partial updates cannot silently combine into an invalid policy) |
| `test_peer_runtime_consistency.py` | `_wg_add_peer_runtime()` raises `HTTPException(503)` when `wg set` exits non-zero, so an enable/migration cannot claim success while the peer never reached the running interface; the peer-create contract: 409 on pool exhaustion, no `wg` stderr in the response, rollback including a failed remove |
| `test_peer_stale.py` | Stale peer marker: calendar-month cutoff, persisted `peer_stale_months` threshold with default fallback, stale state derived only (never stored), admin settings update/clear |
| `test_peer_stale_recovery.py` | `peer_stale_months` alternate-DB recovery: valid value adopted, out-of-range/non-numeric rejected, local value never overwritten, absent source key creates nothing; `insert_default_settings` never persists the threshold (no key means default 6) |
| `test_peer_tags.py` | One peer-tag policy for every trigger: disabled global ad-blocker writes empty tags, enabled writes per-peer tags |
| `test_retention_options.py` | TSDB retention option set rejects keep-nothing (any value below 1 day coerces to 1, so 0 is not offered), while DNS-log and speedtest retention legitimately keep 0 |
| `test_resolve_client_ip.py` | `resolve_client_ip()` walks `X-Forwarded-For` right-to-left against the trusted-proxy allowlist; an untrusted peer can never inject the client IP via the header |
| `test_server_startup.py` | Shared `app.server` start path: the runtime listener state the Docker health check reads, and validation keeping the optional plaintext ACME listener from colliding with the GUI port; the lifespan's `chain_signal_handlers` wiring (SIGTERM sets `app.state.shutdown_signal_event`, still reaches the previous uvicorn handler, which is restored on exit) |
| `test_settings_stale_slider.py` | Static wiring checks: the peer stale threshold is a range slider on the Settings page that sends real months |
| `test_session_revocation.py` | Changing an auth factor or account status invalidates sessions: a token issued before MFA enable, passkey reset or account disable must stop working (asserts `auth_tokens` rows directly) |
| `test_sqlite_passkeys.py` | Passkey storage: only a credential-ID conflict is reported as "already registered"; challenge round trip per ceremony type, invalid ceremony types rejected |
| `test_speedtest_api.py` | Manual speedtest runs: a successful run started through the API records the `gillbates-speedtest` run-guard cooldown, so the next start returns 429; a failed run leaves no cooldown |
| `test_status_dns_leak.py` | Status page: DNS leak indicator (a recent query from the client is verified, none yields a warning, never `None`), public client IP selection, and the outbound IP probe over `gillbates-public-ip` (IPv6 preferred, IPv4 fallback, unavailable detail) |
| `test_subprocess_limits.py` | Async subprocess helper: captured stdout/stderr/returncode, output size limits on both streams, timeouts (including SIGTERM-ignoring children), runaway output, cancellation, empty command and non-positive timeout rejected, missing binary |
| `test_time.py` | Timezone-aware time utilities: `parse_utc`, `parse_db_timestamp`, `ensure_utc` with Z/offset/naive/semi-aware tzinfo and unsupported types; `to_utc_iso` / `utc_iso` filter wire format, a guard that templates never format datetimes server-side, and an AST guard that no code under `app/` depends on the process time zone (`now()`/`fromtimestamp()` without zone, `localtime`, `astimezone()`, `TZ`, `zoneinfo`; the guard has its own self-test) |
| `test_traffic_truncation.py` | Country/ASN traffic totals cover the whole requested window via `tsdb.query_bucketed()` (no `MAX_QUERY_POINTS` cap, so more snapshots than the cap are still summed completely); short ranges match the plain raw aggregation; peer filter and ASN names; `effective_hours` equals the requested range |
| `test_tsdb_query.py` | TSDB query honesty: strict mode raises on an over-cap limit while the default path still clamps but warns; `query_bucketed()` streams raw points into fixed-width buckets, unbound by `MAX_QUERY_POINTS` |
| `test_tls_material.py` | TLS material selection for the built-in HTTPS listener: hostname normalisation (IDN, IP literals, path escape), preferring valid Let's Encrypt pairs, fallback on unparseable/expired/mismatched certs, self-signed reuse and regeneration |
| `test_user_security.py` | User-management invariants: user listing omits stored secrets, recovery-code update requires current value, last admin cannot be deleted at DB layer, OTP setup confirm requires self, re-running OTP enable on an already-enabled account is rejected (409) without clearing the secret/recovery codes |
| `test_unbound_binaries.py` | `is_unbound_installed()` resolves `unbound`/`unbound-checkconf` to absolute paths from a fixed allowlist and stores them; detection fails closed when no trusted binary exists, so the resolver is never started by a bare name through a manipulated PATH |
| `test_utils_hardening.py` | Utility regressions: node metric point selection (timestamp precedence, latest per node), token encrypt/decrypt and pepper checks, version comparison and immutable update-check cache, scheduler job argument validation, next-delay and failure recording of scheduled tasks, domain-lock fd release, WireGuard key validation, SSRF address checks (also for DoT upstreams), private secret/PSK temp files removed on failure, banner release link |
| `test_wireguard_hook_validation.py` | PostUp/PostDown hook validation: size and charset limits (`_validate_hook`) |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `e2e/` | Browser E2E drivers (Node + Playwright) against an isolated server; local only, not collected by pytest (see `e2e/AGENTS.md`) |
| `js/` | Node tests for `app/static/js/core/format.js` (`format.test.mjs`, per locale and time zone) and `el()` URL-scheme filtering in `dom.js` (`dom.test.mjs`); also checks that first-party JS pins no locale or time zone and formats numbers through `WBFormat`; run with `npm run test:js` (`node --test "tests/js/*.test.mjs"`, Node built-ins only), not collected by pytest; CI runs it in the `manifest` job |
| `layout/` | Playwright regression suite for the rendered UI (pages x viewports x themes, navigation, auth, modals, axe); repository-local Playwright install, run by the `layout` job in `ci.yml`, not collected by pytest (see `layout/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- One `test_<area>.py` per area; files follow the Python rules of the root `AGENTS.md` (tabs, header block).
- Add a regression test alongside any security or persistence fix; name it after the behaviour.
- Keep tests hermetic: use `tmp_path`, `monkeypatch`, in-memory SQLite; no network, no real WireGuard/Unbound.
- Never put real secrets in fixtures.

### Testing Requirements
- Run `pytest` from the repo root (Python 3.14 venv with dev extras); use `pytest tests/test_x.py -k name` to narrow.
- A change to `app/static/js/core/format.js` or to JS that formats dates or numbers runs `npm run test:js`; a change to server-side time handling keeps `test_time.py` green.
- A backup-related change must keep `test_backup_schema_only.py` green (restore must retain configuration data).

### Common Patterns
- The shared `conn` / `threadsafe_conn` fixtures in `conftest.py` build a fresh SQLite schema per test; use them rather than redefining one; tests that call `create_app()` or `load_config()` must set `WIREBUDDY_DATA_DIR` to `tmp_path` first; `pytest.mark.parametrize` for bad inputs; async helpers driven with `asyncio.run`-style wrappers.

## Dependencies

### Internal
- `app/` modules: backup, db (auth, nodes, users), utils (time, coerce, subprocess, crypto, scheduler), tls, dns preflight, frontend shared helpers, application lock and `backup_lock` (`app.main` and `app.utils.logging_setup` internals are imported directly, e.g. `test_logging_cleanup.py`).

### External
- `pytest`, `cryptography` (cert generation in TLS tests), stdlib `sqlite3`, `socket`, `asyncio`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
