#!/usr/bin/env python3
#
# app/dns/unbound.py
# Copyright (C) 2025-2026 Gill-Bates http://github.com/Gill-Bates
#

"""Unbound DNS resolver management.

Handles:
- Starting / stopping / restarting unbound
- Generating unbound.conf with ad-blocking
- Downloading and updating blocklists
- Reading the query log for the UI
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import shutil
import signal
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
	import httpx
except ImportError:
	httpx = None  # type: ignore

from ..utils.config import get_config

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

UNBOUND_CONF_DIR = Path("/etc/unbound")
UNBOUND_CONF = UNBOUND_CONF_DIR / "unbound.conf"
QUERY_LOG = Path("/var/log/unbound/queries.log")


def get_blocklist_file() -> Path:
	"""Return the path to the blocklist file in data/dns directory."""
	return get_config().dns_dir / "blocklist.conf"


UNBOUND_PID_FILE = Path("/var/run/unbound.pid")
DNSSEC_ROOT_KEY = Path("/var/lib/unbound/root.key")

# Blocklist definitions with stable IDs for per-peer tagging
BLOCKLIST_REGISTRY: dict[str, dict] = {
	"ads": {
		"id": "ads",
		"name": "Ads & Trackers",
		"description": "StevenBlack unified hosts (ads, malware, trackers)",
		"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
	},
	"porn": {
		"id": "porn",
		"name": "Adult Content",
		"description": "StevenBlack porn-only hosts",
		"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
	},
	"easylist": {
		"id": "easylist",
		"name": "EasyList",
		"description": "EasyList ad domains",
		"url": "https://easylist.to/easylist/easylist.txt",
	},
}

# Default blocklists for new installations
# Adult content list ("porn") is available, but disabled by default.
DEFAULT_BLOCKLIST_IDS = ["ads", "easylist"]

# Legacy compatibility
DEFAULT_BLOCKLISTS = [BLOCKLIST_REGISTRY[bid]["url"] for bid in DEFAULT_BLOCKLIST_IDS]

BLOCKLIST_MAX_BYTES = 25 * 1024 * 1024
BLOCKLIST_MAX_LINES = 2_000_000
BLOCKLIST_MAX_DOMAINS = 1_000_000
MAX_TAIL_BYTES = 8 * 1024 * 1024
MAX_QUERY_LOG_LINES = 50_000

_ALLOWED_BLOCKLIST_CONTENT_TYPES = {
	"",
	"text/plain",
	"text/hosts",
	"application/octet-stream",
}
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9_-]{1,63}$")  # Allow underscores (_dmarc, _acme-challenge)
_HOST_LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")
_UPSTREAM_ADDR_RE = re.compile(r"^([^@#]+)(?:@(\d{1,5}))?#(.+)$")
# NOTE: Thread safety relies on CPython's GIL for atomic assignments.
# If moving to free-threaded Python (3.13t+), add a threading.Lock.
_BLOCKED_DOMAINS_CACHE: frozenset[str] | None = None
_BLOCKED_DOMAINS_CACHE_MTIME_NS: int | None = None

# Process handle for unbound daemon (to prevent zombie processes)
_unbound_proc: asyncio.subprocess.Process | None = None

# Regex for unbound query log line:
# [timestamp] unbound[pid:tid] info: ip client @0x... query: domain. type class
# (Parsed inline - no compiled regex needed)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class DnsQuery:
	"""Parsed DNS query log entry."""
	timestamp: str
	client: str
	domain: str
	qtype: str
	status: str = ""  # NOERROR, NXDOMAIN, SERVFAIL, etc.
	blocked: bool = False
	resolver: str = ""  # Upstream resolver that answered (best effort)


@dataclass
class DnsStats:
	"""Aggregated DNS statistics."""
	total_queries: int = 0
	blocked_queries: int = 0
	unique_domains: int = 0
	unique_clients: int = 0
	blocklist_size: int = 0
	is_running: bool = False


# ---------------------------------------------------------------------------
# Unbound Process Management
# ---------------------------------------------------------------------------

_EXEC_TIMEOUT = 5  # seconds – prevents subprocess from blocking the event loop


async def _run_exec(*cmd: str, timeout: float = _EXEC_TIMEOUT) -> tuple[int, str, str]:
	"""Run a command and return (code, stdout, stderr). Uses exec, not shell.

	A timeout (default 5 s) prevents hung subprocesses from blocking the
	FastAPI event loop – which was the root cause of UI freezes.
	"""
	proc: asyncio.subprocess.Process | None = None
	try:
		proc = await asyncio.create_subprocess_exec(
			*cmd,
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.PIPE,
		)
		stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
		return proc.returncode or 0, stdout.decode(), stderr.decode()
	except asyncio.TimeoutError:
		_log.warning("DNS_EXEC_TIMEOUT command timed out after %.1fs: %s", timeout, cmd)
		if proc and proc.returncode is None:
			try:
				proc.kill()
				await proc.wait()
			except Exception:
				pass
		return -1, "", f"Command timed out after {timeout}s"
	except Exception as exc:
		_log.warning("DNS_EXEC_ERROR command failed: %s – %s", cmd, exc)
		return -1, "", str(exc)


def _atomic_write_text(path: Path, content: str) -> None:
	"""Atomically write UTF-8 text to a file in the same directory."""
	path.parent.mkdir(parents=True, exist_ok=True)
	fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
	try:
		with os.fdopen(fd, "w", encoding="utf-8") as f:
			f.write(content)
			f.flush()
			os.fsync(f.fileno())
		os.replace(tmp_path, path)
	finally:
		try:
			if os.path.exists(tmp_path):
				os.unlink(tmp_path)
		except Exception:
			pass


async def _reap_managed_proc() -> None:
	"""Wait for managed unbound proc and clear the handle."""
	global _unbound_proc
	if _unbound_proc is None:
		return
	try:
		await _unbound_proc.wait()
	except Exception:
		pass
	_unbound_proc = None


async def _kill_pid(pid: int, *, timeout: float = 3.0) -> bool:
	"""SIGTERM then SIGKILL a PID; returns True when no longer running."""
	try:
		os.kill(pid, signal.SIGTERM)
	except ProcessLookupError:
		return True
	except Exception as exc:
		_log.debug("DNS_STOP failed to SIGTERM pid=%s: %s", pid, exc)

	deadline = time.monotonic() + timeout
	while time.monotonic() < deadline:
		if not _pid_is_running(pid):
			return True
		await asyncio.sleep(0.15)

	try:
		os.kill(pid, signal.SIGKILL)
	except ProcessLookupError:
		return True
	except Exception as exc:
		_log.debug("DNS_STOP failed to SIGKILL pid=%s: %s", pid, exc)
	await asyncio.sleep(0.3)
	return not _pid_is_running(pid)


def _read_unbound_pid() -> int | None:
	"""Read and parse unbound PID file."""
	try:
		raw = UNBOUND_PID_FILE.read_text(encoding="utf-8").strip()
		if not raw.isdigit():
			return None
		return int(raw)
	except Exception:
		return None


def _pid_is_running(pid: int) -> bool:
	"""Return True if the PID currently exists."""
	if pid <= 0:
		return False
	try:
		os.kill(pid, 0)
		return True
	except ProcessLookupError:
		return False
	except PermissionError:
		# Process exists but cannot be signaled by current user.
		return True
	except Exception:
		return False


def _remove_stale_pid_file() -> None:
	"""Delete unbound PID file when it points to a dead process."""
	pid = _read_unbound_pid()
	if pid and _pid_is_running(pid):
		return
	try:
		UNBOUND_PID_FILE.unlink(missing_ok=True)
	except Exception:
		pass


# Cache for is_running() — avoids spawning pgrep on every request
_IS_RUNNING_CACHE_TTL = 5.0  # seconds
_is_running_last_check: float = 0.0
_is_running_last_result: bool = False


def invalidate_running_cache() -> None:
	"""Force the next is_running() call to re-check (after start/stop)."""
	global _is_running_last_check
	_is_running_last_check = 0.0


async def is_running() -> bool:
	"""Check if unbound is running (cached for 5 s to avoid subprocess spam).

	Fast path: PID file + os.kill(pid, 0) — no subprocess, ~0 ms.
	Slow path (fallback): pgrep — only when PID file is missing/stale.
	Both results are cached for ``_IS_RUNNING_CACHE_TTL`` seconds so that
	parallel requests (dashboard, peer list, QR, config) don't each spawn
	their own pgrep subprocess.
	"""
	global _is_running_last_check, _is_running_last_result

	now = time.monotonic()
	if now - _is_running_last_check < _IS_RUNNING_CACHE_TTL:
		return _is_running_last_result

	# Fast path: PID file check (pure syscall, no subprocess)
	pid = _read_unbound_pid()
	if pid and _pid_is_running(pid):
		_is_running_last_result = True
		_is_running_last_check = now
		return True

	# Slow path: pgrep fallback (only when PID file is absent/stale)
	_remove_stale_pid_file()
	code, _, _ = await _run_exec("pgrep", "-x", "unbound")
	_is_running_last_result = code == 0
	_is_running_last_check = now
	return _is_running_last_result


async def start() -> tuple[bool, str]:
	"""Start unbound."""
	global _unbound_proc
	invalidate_running_cache()
	if await is_running():
		return True, "Unbound is already running"
	_remove_stale_pid_file()
	
	# Ensure config exists
	if not UNBOUND_CONF.exists():
		write_config()
	
	# First check config is valid
	code, _, stderr = await _run_exec("unbound-checkconf", "/etc/unbound/unbound.conf")
	if code != 0:
		return False, f"Config check failed: {stderr}"
	
	# Start unbound in foreground mode and supervise via PID file.
	try:
		_unbound_proc = await asyncio.create_subprocess_exec(
			"unbound", "-d", "-c", "/etc/unbound/unbound.conf",
			stdout=asyncio.subprocess.DEVNULL,
			stderr=asyncio.subprocess.DEVNULL,
			start_new_session=True,
		)

		for _ in range(20):
			invalidate_running_cache()
			if await is_running():
				_log.info("DNS_START unbound started")
				return True, "Unbound started"
			if _unbound_proc.returncode is not None:
				return False, f"Failed to start (exit code {_unbound_proc.returncode})"
			await asyncio.sleep(0.15)

		return False, "Unbound failed to start (timeout waiting for PID)"
	except Exception as e:
		return False, f"Failed to start: {e}"


async def stop() -> tuple[bool, str]:
	"""Stop unbound."""
	invalidate_running_cache()
	pid = _read_unbound_pid()
	if pid and _pid_is_running(pid):
		if await _kill_pid(pid):
			_remove_stale_pid_file()
			await _reap_managed_proc()
			_log.info("DNS_STOP unbound stopped")
			return True, "Unbound stopped"

	# Fallback: force-stop any remaining unbound process by name.
	await _run_exec("pkill", "-9", "-x", "unbound")
	await asyncio.sleep(0.3)
	invalidate_running_cache()
	running = await is_running()
	if not running:
		_remove_stale_pid_file()
		await _reap_managed_proc()
		_log.info("DNS_STOP unbound stopped")
		return True, "Unbound stopped (forced)"
	return False, "Failed to stop unbound"


async def restart() -> tuple[bool, str]:
	"""Restart unbound."""
	invalidate_running_cache()
	await stop()
	return await start()


async def reload_config() -> tuple[bool, str]:
	"""Send SIGHUP to unbound to reload configuration."""
	pid = _read_unbound_pid()
	if pid and _pid_is_running(pid):
		try:
			os.kill(pid, signal.SIGHUP)
			_log.info("DNS_RELOAD config reloaded (pid=%d)", pid)
			return True, "Configuration reloaded"
		except Exception as e:
			return False, f"Reload failed: {e}"

	code, _, stderr = await _run_exec("pkill", "-HUP", "-x", "unbound")
	if code == 0:
		_log.info("DNS_RELOAD config reloaded")
		return True, "Configuration reloaded"
	return False, f"Reload failed: {stderr}"


# ---------------------------------------------------------------------------
# Configuration Generation
# ---------------------------------------------------------------------------

def _read_total_memory_mb() -> int | None:
	"""Best-effort detection of total system memory in MB."""
	try:
		with Path("/proc/meminfo").open("r", encoding="utf-8") as f:
			for line in f:
				if line.startswith("MemTotal:"):
					parts = line.split()
					if len(parts) >= 2 and parts[1].isdigit():
						return int(parts[1]) // 1024
	except Exception:
		return None
	return None


def _auto_num_threads() -> int:
	"""Choose a sane default thread count for Unbound."""
	cpu = os.cpu_count() or 1
	return max(1, min(cpu, 8))


def _auto_cache_sizes() -> tuple[str, str]:
	"""Choose msg/rrset cache sizes based on memory."""
	mem_mb = _read_total_memory_mb()
	if mem_mb is None:
		return ("32m", "64m")
	if mem_mb < 1024:
		return ("16m", "32m")
	if mem_mb < 2048:
		return ("32m", "64m")
	return ("64m", "128m")


def is_dnssec_available() -> bool:
	"""Return True if Unbound root trust anchor exists on disk."""
	return DNSSEC_ROOT_KEY.exists()


def _normalize_hostname(hostname: str) -> str:
	"""Validate and normalize a hostname to ASCII (IDNA)."""
	value = hostname.strip().strip(".").lower()
	if not value:
		raise ValueError("hostname is required")
	try:
		ascii_host = value.encode("idna").decode("ascii")
	except UnicodeError as exc:
		raise ValueError(f"invalid hostname: {hostname!r}") from exc
	if len(ascii_host) > 253:
		raise ValueError(f"hostname too long: {hostname!r}")
	for label in ascii_host.split("."):
		if not _HOST_LABEL_RE.fullmatch(label):
			raise ValueError(f"invalid hostname label: {label!r}")
		if label.startswith("-") or label.endswith("-"):
			raise ValueError(f"invalid hostname label: {label!r}")
	return ascii_host


def _validate_upstream_dot(addr: str) -> str:
	"""Validate one DoT upstream address and normalize to ip@port#hostname."""
	match = _UPSTREAM_ADDR_RE.fullmatch(addr.strip())
	if not match:
		raise ValueError("expected format <ip>@<port>#<hostname>")
	ip_part = match.group(1).strip()
	port_part = match.group(2)
	hostname_part = match.group(3).strip()
	ipaddress.ip_address(ip_part)
	port = int(port_part) if port_part else 853
	if not 1 <= port <= 65535:
		raise ValueError(f"invalid port: {port}")
	hostname = _normalize_hostname(hostname_part)
	return f"{ip_part}@{port}#{hostname}"


def generate_config(
	listen_addr: str = "0.0.0.0",
	listen_port: int = 53,
	enable_logging: bool = True,
	upstream_dns: list[str] | None = None,
	enable_blocklist: bool = True,
	enable_dnssec: bool = True,
	cache_min_ttl: int = 60,
) -> str:
	"""Generate unbound.conf content.
	
	Args:
		cache_min_ttl: Minimum TTL for cached entries. Some CDNs use low TTLs
		              for fast failover; override with care.
	"""
	try:
		ipaddress.ip_address(listen_addr)
	except ValueError as exc:
		raise ValueError(f"Invalid listen address: {listen_addr!r}") from exc
	try:
		port_num = int(listen_port)
	except (TypeError, ValueError) as exc:
		raise ValueError(f"Invalid listen port: {listen_port!r}") from exc
	if not 1 <= port_num <= 65535:
		raise ValueError(f"Invalid listen port: {listen_port!r}")
	try:
		cache_min_ttl_num = int(cache_min_ttl)
	except (TypeError, ValueError) as exc:
		raise ValueError(f"cache_min_ttl must be an integer: {cache_min_ttl!r}") from exc
	if not 0 <= cache_min_ttl_num <= 86400:
		raise ValueError(f"cache_min_ttl out of range: {cache_min_ttl_num}")

	upstream = upstream_dns or [
		"1.1.1.1@853#cloudflare-dns.com",
		"9.9.9.9@853#dns.quad9.net",
		"91.239.100.100@853#unicast.censurfridns.dk",
		"45.90.28.0@853#dns.nextdns.io",
		"194.242.2.2@853#dns.mullvad.net",
	]
	valid: list[str] = []
	invalid: list[str] = []
	for addr in upstream:
		addr = addr.strip()
		if not addr:
			continue
		try:
			valid.append(_validate_upstream_dot(addr))
		except Exception:
			invalid.append(addr)
			_log.warning("DNS_CONFIG upstream %r dropped (invalid DoT format)", addr)
	
	if invalid and not valid:
		raise ValueError(f"All upstream DNS entries invalid: {invalid}")
	upstream = valid or [
		"1.1.1.1@853#cloudflare-dns.com",
		"9.9.9.9@853#dns.quad9.net",
		"91.239.100.100@853#unicast.censurfridns.dk",
		"45.90.28.0@853#dns.nextdns.io",
		"194.242.2.2@853#dns.mullvad.net",
	]
	
	# Check if DNSSEC root key is available
	dnssec_available = is_dnssec_available() and enable_dnssec
	num_threads = _auto_num_threads()
	msg_cache_size, rrset_cache_size = _auto_cache_sizes()

	conf = f"""# WireBuddy Unbound Configuration
# Auto-generated – do not edit manually

server:
    interface: {listen_addr}
    port: {port_num}

    # Access control – only allow private/internal networks
    access-control: 127.0.0.0/8 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow
    access-control: ::1/128 allow
    access-control: fc00::/7 allow
    do-ip6: yes
    prefer-ip6: no

    # Blocklist tags for per-peer filtering
    define-tag: "{' '.join(BLOCKLIST_REGISTRY.keys())}"

    # Per-peer tag assignments (generated separately)
    include: {UNBOUND_CONF_DIR / "peer-tags.conf"}

    # Performance
    num-threads: {num_threads}
    msg-cache-slabs: 4
    rrset-cache-slabs: 4
    infra-cache-slabs: 4
    key-cache-slabs: 4
    msg-cache-size: {msg_cache_size}
    rrset-cache-size: {rrset_cache_size}
    cache-min-ttl: {cache_min_ttl_num}
    cache-max-ttl: 86400
    prefetch: yes
    prefetch-key: yes

    # Upstream server selection (round-robin with failover)
    # infra-host-ttl: how long to remember server RTT/status
    # infra-cache-min-rtt: minimum jitter for RTT-based selection (enables load distribution)
    # infra-lame-ttl: how long to avoid a non-responding/timeout server
    infra-host-ttl: 300
    infra-cache-min-rtt: 50
    infra-lame-ttl: 120

    # Privacy & Security
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    aggressive-nsec: {"yes" if dnssec_available else "no"}
    harden-glue: yes
    harden-dnssec-stripped: {"yes" if dnssec_available else "no"}
    harden-referral-path: yes
    use-caps-for-id: yes

    # TLS upstream
    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt
    username: "unbound"
    chroot: ""
    pidfile: /var/run/unbound.pid
"""
	
	# Add DNSSEC trust anchor only if enabled and root.key exists
	if dnssec_available:
		conf += """
    # DNSSEC
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
"""

	if enable_logging:
		conf += """
    # Query logging
    use-syslog: no
    log-queries: yes
    log-replies: yes
    log-tag-queryreply: yes
    logfile: /var/log/unbound/queries.log
    log-time-ascii: no
    verbosity: 1
"""

	if enable_blocklist:
		conf += f"""
    # Ad-blocking
    include: {get_blocklist_file()}
"""

	conf += """
# Upstream DNS (round-robin with automatic failover)
# Queries distributed across servers based on RTT; timeout servers avoided for infra-lame-ttl
forward-zone:
    name: "."
    forward-tls-upstream: yes
"""
	for dns in upstream:
		conf += f"    forward-addr: {dns}\n"

	return conf


def write_config(**kwargs) -> None:
	"""Write unbound.conf to disk."""
	UNBOUND_CONF_DIR.mkdir(parents=True, exist_ok=True)
	QUERY_LOG.parent.mkdir(parents=True, exist_ok=True)
	UNBOUND_PID_FILE.parent.mkdir(parents=True, exist_ok=True)
	QUERY_LOG.touch(exist_ok=True)
	
	# Fix permissions: unbound runs as 'unbound' user and needs to write logs
	try:
		shutil.chown(QUERY_LOG, user="unbound", group="unbound")
		shutil.chown(QUERY_LOG.parent, user="unbound", group="unbound")
	except (OSError, LookupError) as exc:
		_log.debug("Could not chown query log to unbound user: %s", exc)
	
	# Ensure blocklist file exists (even if empty) so config include doesn't fail
	blocklist_path = get_blocklist_file()
	if not blocklist_path.exists():
		_atomic_write_text(blocklist_path, "# Empty blocklist - will be populated on update\n")
	
	# Ensure peer-tags.conf exists (even if empty)
	peer_tags_path = UNBOUND_CONF_DIR / "peer-tags.conf"
	if not peer_tags_path.exists():
		_atomic_write_text(peer_tags_path, "# Per-peer blocklist tags - auto-generated\n")

	content = generate_config(**kwargs)
	_atomic_write_text(UNBOUND_CONF, content)
	_log.info("DNS_CONFIG written to %s", UNBOUND_CONF)


def write_peer_tags(peers: list[dict]) -> None:
	"""Generate peer-tags.conf for per-peer blocklist filtering.
	
	Args:
		peers: List of peer dicts with 'peer_address' and 'blocklist_ids' keys.
		       peer_address: e.g., "10.13.13.2/32, fd13:13:13::2/128"
		       blocklist_ids: list of enabled blocklist IDs, or None for all
	"""
	UNBOUND_CONF_DIR.mkdir(parents=True, exist_ok=True)
	peer_tags_path = UNBOUND_CONF_DIR / "peer-tags.conf"
	
	all_tags = list(BLOCKLIST_REGISTRY.keys())
	lines = [
		"# Per-peer blocklist tag assignments",
		f"# Auto-generated – {datetime.now(timezone.utc).isoformat()}",
		"",
	]
	
	for peer in peers:
		peer_address = peer.get("peer_address")
		use_adblocker = peer.get("use_adblocker", True)
		blocklist_ids = peer.get("blocklist_ids")
		
		if not peer_address or not use_adblocker:
			continue
		
		# Determine which tags this peer should have
		if blocklist_ids is None:
			# None = all blocklists enabled
			tags = all_tags
		else:
			# Filter to only valid tags
			tags = [bid for bid in blocklist_ids if bid in BLOCKLIST_REGISTRY]
		
		if not tags:
			continue
		
		# Parse peer_address (may contain multiple addresses: "10.x.x.x/32, fd13::x/128")
		for addr_part in peer_address.split(","):
			addr = addr_part.strip()
			if not addr:
				continue
			try:
				network = ipaddress.ip_network(addr, strict=False)
			except ValueError:
				_log.warning("DNS_PEER_TAGS invalid address %r, skipping", addr)
				continue
			lines.append(f'    access-control-tag: {network} "{" ".join(tags)}"')
	
	_atomic_write_text(peer_tags_path, "\n".join(lines) + "\n")
	_log.info("DNS_PEER_TAGS written %d entries to %s", len([l for l in lines if l.startswith("    access")]), peer_tags_path)


# ---------------------------------------------------------------------------
# Blocklist Management
# ---------------------------------------------------------------------------

def _normalize_domain(raw: str) -> str | None:
	"""Normalize and validate a domain; returns ASCII IDNA domain or None."""
	domain = raw.strip().strip(".").lower()
	if not domain or domain == "localhost" or len(domain) > 253:
		return None
	try:
		ascii_domain = domain.encode("idna").decode("ascii")
	except UnicodeError:
		return None

	labels = ascii_domain.split(".")
	if len(labels) < 2:
		return None
	for label in labels:
		if not _DOMAIN_LABEL_RE.fullmatch(label):
			return None
		if label.startswith("-") or label.endswith("-"):
			return None
	return ascii_domain


def _extract_domain_from_hosts_line(line: str) -> str | None:
	"""Extract a normalized domain from a hosts-format line."""
	line = line.strip()
	if not line or line.startswith("#"):
		return None
	if "#" in line:
		line = line.split("#", 1)[0].strip()
	if not line:
		return None

	parts = line.split()
	if len(parts) == 1:
		# Also support simple "domain.tld" list format.
		return _normalize_domain(parts[0])
	if len(parts) < 2:
		return None

	try:
		ipaddress.ip_address(parts[0])
	except ValueError:
		return None

	return _normalize_domain(parts[1])


def _invalidate_blocked_domains_cache() -> None:
	"""Invalidate cached blocked-domain set after blocklist changes."""
	global _BLOCKED_DOMAINS_CACHE
	global _BLOCKED_DOMAINS_CACHE_MTIME_NS
	_BLOCKED_DOMAINS_CACHE = None
	_BLOCKED_DOMAINS_CACHE_MTIME_NS = None


async def _download_hosts_domains(
	client: "httpx.AsyncClient",
	url: str,
	existing_domains: set[str],
) -> tuple[int, set[str]]:
	"""Stream and parse domains from one hosts list URL."""
	line_count = 0
	size_bytes = 0
	parsed_domains: set[str] = set()

	async with client.stream("GET", url) as resp:
		resp.raise_for_status()
		content_type = resp.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
		if content_type not in _ALLOWED_BLOCKLIST_CONTENT_TYPES and not content_type.startswith("text/"):
			raise ValueError(f"Unsupported content type: {content_type!r}")

		content_length = resp.headers.get("Content-Length")
		if content_length and content_length.isdigit() and int(content_length) > BLOCKLIST_MAX_BYTES:
			raise ValueError(f"Blocklist too large ({content_length} bytes)")

		async for raw_line in resp.aiter_lines():
			line_count += 1
			size_bytes += len(raw_line.encode("utf-8", errors="ignore")) + 1
			if line_count > BLOCKLIST_MAX_LINES:
				raise ValueError(f"Blocklist line limit exceeded ({BLOCKLIST_MAX_LINES})")
			if size_bytes > BLOCKLIST_MAX_BYTES:
				raise ValueError(f"Blocklist size limit exceeded ({BLOCKLIST_MAX_BYTES} bytes)")

			domain = _extract_domain_from_hosts_line(raw_line)
			if not domain:
				continue
			parsed_domains.add(domain)
			if len(existing_domains) + len(parsed_domains) > BLOCKLIST_MAX_DOMAINS:
				raise ValueError(f"Domain cap exceeded ({BLOCKLIST_MAX_DOMAINS})")

	return line_count, parsed_domains


def _url_to_blocklist_id(url: str) -> str | None:
	"""Map a blocklist URL to its registry ID."""
	for bid, meta in BLOCKLIST_REGISTRY.items():
		if meta["url"] == url:
			return bid
	return None


async def update_blocklists(
	urls: list[str] | None = None,
) -> tuple[int, str]:
	"""Download blocklists and generate tagged local-zone entries.

	Each domain is tagged with its source blocklist ID(s) for per-peer filtering.
	Domains that appear in multiple lists get multiple tags.

	Returns:
		(count_of_blocked_domains, status_message)
	"""
	if httpx is None:
		raise RuntimeError("httpx required for blocklist updates: pip install httpx")

	urls = urls or DEFAULT_BLOCKLISTS
	
	# Track domains and their source tags: domain -> set of blocklist IDs
	domain_tags: dict[str, set[str]] = {}
	
	# Validate URL schemes first (prevent file:// or other attacks).
	safe_urls: list[str] = []
	for url in urls:
		parsed = urllib.parse.urlparse(url)
		if parsed.scheme not in ("http", "https") or not parsed.netloc:
			_log.warning("DNS_BLOCKLIST rejected non-HTTP URL: %s", url)
			continue
		safe_urls.append(url)
	if not safe_urls:
		return 0, "No valid blocklist URLs provided"
	known_sources: list[tuple[str, str]] = []
	for url in safe_urls:
		blocklist_id = _url_to_blocklist_id(url)
		if not blocklist_id:
			_log.warning("DNS_BLOCKLIST unknown URL (not in registry): %s", url)
			continue
		known_sources.append((url, blocklist_id))
	if not known_sources:
		return 0, "No supported blocklist URLs provided"
	loaded_any = False

	async with httpx.AsyncClient(
		timeout=30,
		follow_redirects=True,
		headers={"User-Agent": "WireBuddy/1.0 DNS-Blocker"},
	) as client:
		for url, blocklist_id in known_sources:
			# Retry up to 3 times with exponential backoff
			for attempt in range(3):
				try:
					existing_domains = set(domain_tags.keys())
					line_count, parsed = await _download_hosts_domains(client, url, existing_domains)
					added = 0
					for domain in parsed:
						if domain not in domain_tags:
							if len(domain_tags) >= BLOCKLIST_MAX_DOMAINS:
								raise ValueError(f"Domain cap exceeded ({BLOCKLIST_MAX_DOMAINS})")
							domain_tags[domain] = set()
							added += 1
						domain_tags[domain].add(blocklist_id)
					loaded_any = True
					_log.info("DNS_BLOCKLIST loaded %s [%s] (%d lines, +%d domains)", url, blocklist_id, line_count, added)
					break  # Success, move to next URL
				except Exception as e:
					if attempt < 2:
						wait = 2 ** attempt  # 1s, 2s
						_log.debug("DNS_BLOCKLIST retry %d for %s in %ds: %s", attempt + 1, url, wait, e)
						await asyncio.sleep(wait)
					else:
						_log.warning("DNS_BLOCKLIST failed to load %s: %s", url, e)
	if not loaded_any:
		return 0, "No blocklist could be downloaded; existing blocklist kept"
	if not domain_tags:
		return 0, "Downloaded blocklists contained no domains; existing blocklist kept"

	# Write unbound local-zone file with tags (atomic replace)
	blocklist_path = get_blocklist_file()
	blocklist_path.parent.mkdir(parents=True, exist_ok=True)
	fd, tmp_path = tempfile.mkstemp(dir=str(blocklist_path.parent), prefix=f".{blocklist_path.name}.", suffix=".tmp")
	try:
		with os.fdopen(fd, "w", encoding="utf-8") as f:
			f.write(f"# Auto-generated blocklist – {len(domain_tags)} domains\n")
			f.write(f"# Updated: {datetime.now(timezone.utc).isoformat()}\n")
			f.write(f"# Tags: {' '.join(BLOCKLIST_REGISTRY.keys())}\n\n")
			for domain in sorted(domain_tags.keys()):
				tags = domain_tags[domain]
				tag_str = " ".join(sorted(tags))
				# tagged local-zone: domain is blocked only for clients with matching tag
				f.write(f'local-zone: "{domain}." always_nxdomain\n')
				f.write(f'local-zone-tag: "{domain}." "{tag_str}"\n')
			f.flush()
			os.fsync(f.fileno())
		os.replace(tmp_path, blocklist_path)
	finally:
		try:
			if os.path.exists(tmp_path):
				os.unlink(tmp_path)
		except Exception:
			pass

	_invalidate_blocked_domains_cache()
	_log.info("DNS_BLOCKLIST wrote %d tagged domains to %s", len(domain_tags), blocklist_path)
	return len(domain_tags), f"Blocklist updated: {len(domain_tags)} domains"


def get_blocklist_count() -> int:
	"""Return number of domains in the current blocklist."""
	blocklist_path = get_blocklist_file()
	if not blocklist_path.exists():
		return 0

	# Fast path: parse precomputed count from header.
	try:
		with blocklist_path.open("r", encoding="utf-8") as f:
			first = f.readline()
			match = re.search(r"(\d+)\s+domains", first)
			if match:
				return int(match.group(1))
	except Exception:
		return 0

	# Fallback: stream file and count local-zone entries.
	count = 0
	try:
		with blocklist_path.open("r", encoding="utf-8") as f:
			for line in f:
				if line.startswith("local-zone:"):
					count += 1
	except Exception:
		return 0
	return count


def get_blocklist_source_counts() -> dict[str, int]:
	"""Return per-source domain counts from the generated blocklist file.

	Counts are derived from ``local-zone-tag`` entries in ``blocklist.conf``.
	Each tag corresponds to a blocklist source ID from ``BLOCKLIST_REGISTRY``.
	"""
	blocklist_path = get_blocklist_file()
	counts: dict[str, int] = {bid: 0 for bid in BLOCKLIST_REGISTRY}
	if not blocklist_path.exists():
		return counts

	tag_re = re.compile(r'^local-zone-tag:\s+"[^"]+"\s+"([^"]+)"')
	try:
		with blocklist_path.open("r", encoding="utf-8", errors="replace") as f:
			for line in f:
				if not line.startswith("local-zone-tag:"):
					continue
				match = tag_re.match(line.strip())
				if not match:
					continue
				for tag in set(match.group(1).split()):
					if tag in counts:
						counts[tag] += 1
	except Exception:
		_log.debug("Could not read blocklist source counts", exc_info=True)

	return counts


# ---------------------------------------------------------------------------
# Query Log Parsing
# ---------------------------------------------------------------------------

def _load_blocked_domains() -> frozenset[str]:
	"""Load the set of blocked domains for fast lookup."""
	global _BLOCKED_DOMAINS_CACHE
	global _BLOCKED_DOMAINS_CACHE_MTIME_NS

	blocklist_path = get_blocklist_file()
	blocked: set[str] = set()
	if not blocklist_path.exists():
		_BLOCKED_DOMAINS_CACHE = frozenset()
		_BLOCKED_DOMAINS_CACHE_MTIME_NS = None
		return _BLOCKED_DOMAINS_CACHE
	try:
		mtime_ns = blocklist_path.stat().st_mtime_ns
	except OSError:
		return frozenset()

	if (
		_BLOCKED_DOMAINS_CACHE is not None
		and _BLOCKED_DOMAINS_CACHE_MTIME_NS == mtime_ns
	):
		return _BLOCKED_DOMAINS_CACHE

	try:
		with blocklist_path.open("r", encoding="utf-8") as f:
			for line in f:
				if not line.startswith("local-zone:"):
					continue
				# local-zone: "example.com." always_nxdomain
				parts = line.split('"')
				if len(parts) >= 2:
					domain = _normalize_domain(parts[1])
					if domain:
						blocked.add(domain)
	except Exception:
		return frozenset()
	_BLOCKED_DOMAINS_CACHE = frozenset(blocked)
	_BLOCKED_DOMAINS_CACHE_MTIME_NS = mtime_ns
	return _BLOCKED_DOMAINS_CACHE


def get_blocked_domains() -> frozenset[str]:
	"""Public API: Get the set of currently blocked domains.
	
	Internally cached - safe to call frequently. Cache invalidates
	when blocklist.conf file changes (based on mtime).
	
	Returns:
		Set of blocked domain names (normalized, without trailing dots)
	"""
	return _load_blocked_domains()


def _is_domain_blocked(domain: str, blocked_domains: set[str] | frozenset[str]) -> bool:
	"""Check exact and parent-domain matches for block status."""
	norm = _normalize_domain(domain)
	if not norm:
		return False
	if norm in blocked_domains:
		return True

	labels = norm.split(".")
	for i in range(1, len(labels) - 1):
		parent = ".".join(labels[i:])
		if parent in blocked_domains:
			return True
	return False


def tail_query_log(lines: int = 500) -> list[DnsQuery]:
	"""Read the last N lines of the unbound query log.

	Deduplicates query/reply pairs by (client, domain, qtype) to avoid
	double-counting in statistics. Reply status takes precedence.
	"""
	if not QUERY_LOG.exists():
		return []
	try:
		lines = int(lines)
	except (TypeError, ValueError):
		lines = 500
	lines = min(max(lines, 1), MAX_QUERY_LOG_LINES)

	blocked_domains = _load_blocked_domains()
	# Deduplicate by (client, domain, qtype) - reply overwrites query
	seen: dict[tuple[str, str, str], DnsQuery] = {}
	upstream_hint = "upstream"

	def _detect_upstream_hint() -> str:
		"""Best-effort label for resolver column when log lacks upstream details."""
		try:
			if not UNBOUND_CONF.exists():
				return "upstream"
			forward_addrs: list[str] = []
			with UNBOUND_CONF.open("r", encoding="utf-8", errors="replace") as f:
				for line in f:
					line = line.strip()
					if line.startswith("forward-addr:"):
						addr = line.split(":", 1)[1].strip()
						if addr:
							forward_addrs.append(addr)
			if not forward_addrs:
				return "upstream"
			if len(forward_addrs) == 1:
				return forward_addrs[0]
			return "upstream-pool"
		except Exception:
			return "upstream"

	upstream_hint = _detect_upstream_hint()

	# Read last N lines efficiently
	raw_lines = _tail_file(QUERY_LOG, lines)

	def _extract_reply_resolver(raw_line: str) -> str:
		"""Best-effort extraction of upstream resolver from a reply log line."""
		# Known variants include "... reply from 1.1.1.1#853 ..."
		# or "... from 1.1.1.1@853 ...".
		match = re.search(
			r"\b(?:reply\s+from|from|upstream)\s+([A-Za-z0-9:\.\-\[\]]+)(?:[@#](\d{1,5}))?",
			raw_line,
		)
		if not match:
			return ""
		host = (match.group(1) or "").strip()
		port = (match.group(2) or "").strip()
		if host.startswith("[") and host.endswith("]"):
			host = host[1:-1]
		if not host:
			return ""
		return f"{host}@{port}" if port else host

	for raw in raw_lines:
		raw = raw.strip()
		if not raw:
			continue

		# Parse line type and extract payload
		# Format: [epoch] unbound[pid:tid] <type>: <client> <domain>. <qtype> IN [<status> ...]
		line_type = ""
		if "query: " in raw:
			parts = raw.split("query: ", 1)
			line_type = "query"
		elif "reply: " in raw:
			parts = raw.split("reply: ", 1)
			line_type = "reply"
		else:
			continue

		if len(parts) < 2:
			continue

		# Extract timestamp
		ts_match = re.search(r"\[(\d+)\]", parts[0])
		ts_str = ""
		if ts_match:
			try:
				ts = datetime.fromtimestamp(int(ts_match.group(1)), timezone.utc)
				ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
			except (ValueError, OSError):
				ts_str = ""

		query_part = parts[1].strip()
		tokens = query_part.split()
		if len(tokens) < 3:
			continue

		client = tokens[0]

		# Validate client is a valid IP address (IPv4 or IPv6)
		try:
			ipaddress.ip_address(client)
		except ValueError:
			continue

		domain = tokens[1].rstrip(".")
		qtype = tokens[2]

		# Extract status from reply lines
		# Reply format: <client> <domain>. <qtype> IN <status> <time> <cached> <size>
		status = ""
		resolver = ""
		if line_type == "reply" and len(tokens) >= 5:
			# tokens[3] = "IN", tokens[4] = status
			status = tokens[4] if tokens[3] == "IN" else ""
			resolver = _extract_reply_resolver(raw)

		# Blocked = domain in our blocklist (not just any NXDOMAIN)
		is_blocked = _is_domain_blocked(domain, blocked_domains)

		# Deduplicate: key by (client, domain, qtype)
		key = (client, domain, qtype)

		if line_type == "query":
			if key not in seen:
				seen[key] = DnsQuery(
					timestamp=ts_str,
					client=client,
					domain=domain,
					qtype=qtype,
					status="",
					blocked=is_blocked,
					resolver="",
				)
		elif line_type == "reply":
			if key in seen:
				# Update existing query with reply status
				seen[key].status = status
				seen[key].blocked = is_blocked
				if resolver:
					seen[key].resolver = resolver
				if ts_str:
					seen[key].timestamp = ts_str
			else:
				# Reply without query (e.g., cached response)
				seen[key] = DnsQuery(
					timestamp=ts_str,
					client=client,
					domain=domain,
					qtype=qtype,
					status=status,
					blocked=is_blocked,
					resolver=resolver,
				)

	# Fill resolver fallback so UI column is never empty.
	for item in seen.values():
		if item.resolver:
			continue
		item.resolver = "local-blocklist" if item.blocked else upstream_hint

	return list(seen.values())


async def get_stats(recent_lines: int = 5000) -> DnsStats:
	"""Compute statistics from query log."""
	running = await is_running()  # Use cached check instead of spawning pgrep

	# Heavy log/blocklist parsing runs in a worker thread to avoid event-loop stalls.
	queries = await asyncio.to_thread(tail_query_log, recent_lines)
	blocklist_size = await asyncio.to_thread(get_blocklist_count)

	all_domains: set[str] = set()
	all_clients: set[str] = set()
	blocked_count = 0

	for q in queries:
		all_domains.add(q.domain)
		all_clients.add(q.client)
		if q.blocked:
			blocked_count += 1

	return DnsStats(
		total_queries=len(queries),
		blocked_queries=blocked_count,
		unique_domains=len(all_domains),
		unique_clients=len(all_clients),
		blocklist_size=blocklist_size,
		is_running=running,
	)


def _tail_file(path: Path, n: int) -> list[str]:
	"""Read the last n lines of a file.
	
	Uses adaptive chunk sizing to ensure we get enough lines even
	if they're longer than the 512-byte estimate.
	"""
	try:
		n = max(1, int(n))
		with path.open("rb") as f:
			f.seek(0, 2)
			size = f.tell()
			if size == 0:
				return []

			# Start with estimated chunk, grow if needed
			chunk_size = min(size, max(n * 512, 1024), MAX_TAIL_BYTES)
			while True:
				start = max(0, size - chunk_size)
				f.seek(start)
				data = f.read().decode("utf-8", errors="replace")
				lines = data.splitlines()
				# If we started mid-file, the first line is usually partial.
				if start > 0 and lines:
					lines = lines[1:]
				if len(lines) >= n or chunk_size >= size or chunk_size >= MAX_TAIL_BYTES:
					return lines[-n:]
				# Double chunk size and retry
				chunk_size = min(size, chunk_size * 2, MAX_TAIL_BYTES)
	except Exception:
		return []


__all__ = [
	"DnsQuery",
	"DnsStats",
	"invalidate_running_cache",
	"is_running",
	"start",
	"stop",
	"restart",
	"reload_config",
	"is_dnssec_available",
	"generate_config",
	"write_config",
	"write_peer_tags",
	"update_blocklists",
	"get_blocklist_count",
	"get_blocklist_source_counts",
	"get_blocked_domains",
	"tail_query_log",
	"get_stats",
]
