<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->

# dns

## Purpose
Integrated Unbound DNS ad-blocker. Generates Unbound configuration, supervises the Unbound process, downloads and compiles blocklists into tagged local-zone files, evaluates AdGuard-style custom rules, and ingests Unbound query logs into the TSDB with crash-safe tailing and retention. `__init__.py` re-exports the modules and a backwards-compatible `unbound` namespace.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Aliases `blocklist`, `config`, `constants`, `process` and the `unbound` compatibility namespace |
| `unbound_constants.py` | Blocklist registry (`BLOCKLIST_REGISTRY`), file path getters, `QUERY_LOG`, `run_exec`, atomic writes |
| `unbound_config.py` | `generate_config` (threads/cache sizing, DoT upstreams, DNSSEC, listen IPs), write of config, per-client rules, peer tags, local-data overrides |
| `unbound_process.py` | Start/stop/restart/reload, PID handling, supervisor task, watchdog, listen-socket preflight, resolv.conf handling |
| `unbound_blocklist.py` | SSRF-safe blocklist download, domain extraction, size caps, tag files, counts, blocked-domain cache |
| `custom_rules.py` | AdGuard-compatible rule parser (`||domain^`, `@@` allow, wildcards, regex, client scopes) and evaluation |
| `ingestion.py` | Facade documenting the ingestion split |
| `ingestion_daemon.py` | `run_dns_ingestion` orchestrator with queue-pressure monitoring |
| `ingestion_tailer.py` | `UnboundLogTailer` with offset tracking and crash recovery |
| `ingestion_parser.py` | `parse_unbound_line` into `DnsQueryPoint` |
| `ingestion_writer.py` | `DnsTsdbWriter` batching to TSDB and `read_recent_queries` |
| `ingestion_retention.py` | DNS log retention normalization and enforcement |

## For AI Agents

### Working In This Directory
- Python files use **tabs** and start with the standard header block (`#!/usr/bin/env python3`, file path, `Copyright (C) 2026 Gill-Bates`, SPDX MIT); keep that style.
- Unbound is an external binary; config values are validated/quoted (`_safe_unbound_value`, `_quote_unbound_path`) to prevent config injection.
- Blocklist URLs must pass the SSRF checks (`_is_safe_url`); do not bypass them.
- Config and list files are written atomically via `atomic_write`.

### Testing Requirements
- `pytest` in `/opt/wirebuddy/tests` (`test_dns_listen_preflight.py`, `test_subprocess_limits.py`); Unbound itself need not be installed for unit tests.
- Custom-rule parser changes should be tested with representative AdGuard syntax.

### Common Patterns
- Subprocesses run through helpers with timeouts; process state is cached and invalidated via `invalidate_running_cache`.
- Ingestion uses bounded queues and shutdown-aware puts.
- Public API is accessed through `app.dns.unbound` or the submodule aliases.

## Dependencies

### Internal
- `app/db` (settings, tsdb), `app/api/dns.py` (consumer), `app/utils`.

### External
- Unbound, httpx for downloads, stdlib asyncio.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
