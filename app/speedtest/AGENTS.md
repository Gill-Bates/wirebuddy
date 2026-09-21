<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# speedtest

## Purpose
Lightweight bandwidth measurement for VPN server monitoring. `tester.py` wraps the `librespeed-cli` binary (`--json`) and normalises download, upload, ping and jitter results; `guard.py` guarantees only one speedtest runs at a time across tasks, threads and processes and enforces a cooldown.

## Key Files
| File | Description |
|------|-------------|
| `tester.py` | `run_speedtest()` runs librespeed-cli with validated tunables, emits `ProgressEvent`s (real or simulated), resolves server country via GeoIP, returns a normalised result dict or an error result |
| `guard.py` | `SpeedtestRunLease` and `acquire_speedtest_run_lease[_async]`: layered `asyncio.Lock`, `threading.Lock` and `fcntl.flock` locking plus on-disk cooldown timestamp; raises `SpeedtestBusyError` / `SpeedtestCooldownError` |
| `__init__.py` | Package docstring only |

## For AI Agents

### Working In This Directory
- Use tabs for indentation and keep the standard file header block (path, copyright, SPDX MIT).
- Always acquire a lease from `guard.py` before calling `run_speedtest`; the async acquire is shielded and cleans up orphaned leases on cancellation, so preserve that behaviour.
- Lock and cooldown files are opened descriptor-first with `O_NOFOLLOW` and verified via `fstat()` (rejects symlinks, non-regular files, and - for the cooldown file - anything over `_MAX_COOLDOWN_FILE_SIZE`); keep that hardening rather than reintroducing a separate `is_symlink()` check followed by a read, which reopens the TOCTOU window. Server URLs are normalised and bounded before use.
- Cooldown reads fail open by design: any unreadable/invalid on-disk state returns `None` (no cooldown), since this is a UX throttle, not a hard resource limit.

### Testing Requirements
- Tests live in `/opt/wirebuddy/tests` (pytest, run `pytest` from the repo root). `test_speedtest_guard.py` covers the cooldown-file hardening and lease-misuse cleanup in `guard.py` directly; mock the subprocess helper for anything exercising `tester.py`.

### Common Patterns
- Failures are returned via `_error_result` (logged plus error progress event) instead of raised.
- Metrics are converted with `_safe_float`/`_round_metric` so missing values persist as 0.0.

## Dependencies

### Internal
- `app/utils/subprocess`, `app/utils/geoip`, `app/utils/formatting`. Consumed by `app/tasks/scheduled` and `app/node/daemon`.

### External
- `librespeed-cli` binary; stdlib `asyncio`, `fcntl`, `json`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
