import re

def refactor():
    with open('/opt/wirebuddy/app/main.py', 'r') as f:
        code = f.read()

    # We will inject the new phase functions right before _lifespan
    
    phases_code = """
async def _phase_bootstrap(ctx: LifespanContext) -> None:
	cfg, app = ctx.cfg, ctx.app
	is_leader, interfaces_to_start, key_mismatch = await asyncio.to_thread(_bootstrap_sync, cfg)
	ctx.is_leader = is_leader
	ctx.interfaces_to_start = interfaces_to_start
	app.state.key_mismatch = key_mismatch
	if key_mismatch:
		_log.critical("Aborting startup: WIREBUDDY_SECRET_KEY does not match database encryption key")
		await _do_shutdown(ctx)
		import sys
		sys.exit(1)
	from .db import tsdb
	tsdb.init_tsdb(cfg.tsdb_dir)
	if ctx.is_leader:
		_log.info("GeoIP init scheduled in background (startup is non-blocking)")

async def _phase_dns_config(ctx: LifespanContext) -> None:
	from .dns import unbound
	if not ctx.is_leader or not unbound.is_unbound_installed():
		return
	try:
		dns_data = await asyncio.to_thread(_load_dns_startup_data_sync, ctx.cfg.db_path)
		ctx.dns_service_enabled = bool(dns_data.get("dns_service_enabled", True))
		listen_addrs_ipv4, listen_addrs_ipv6 = [], []
		interfaces = dns_data.get("interfaces", [])
		for iface in interfaces:
			addr4 = _get_addr_field(iface, "address")
			if addr4 and addr4.split("/")[0] not in listen_addrs_ipv4:
				listen_addrs_ipv4.append(addr4.split("/")[0])
			addr6 = _get_addr_field(iface, "address6")
			if addr6 and addr6.split("/")[0] not in listen_addrs_ipv6:
				listen_addrs_ipv6.append(addr6.split("/")[0])
		if not listen_addrs_ipv4:
			_log.info("DNS init skipped: no WireGuard interfaces configured yet")
		else:
			await asyncio.to_thread(
				unbound.write_config,
				enable_logging=bool(dns_data.get("enable_logging", True)),
				enable_blocklist=bool(dns_data.get("enable_blocklist", True)),
				upstream_dns=dns_data.get("upstream_dns", []),
				enable_dnssec=bool(dns_data.get("enable_dnssec", True)),
				listen_addrs_ipv4=listen_addrs_ipv4,
				listen_addrs_ipv6=listen_addrs_ipv6 if listen_addrs_ipv6 else None,
			)
			await asyncio.to_thread(unbound.write_local_data_overrides, interfaces, dns_data.get("wg_fqdn"))
			peer_count = await asyncio.to_thread(_regenerate_peer_tags_sync, ctx.cfg.db_path)
			_log.debug("DNS peer tags regenerated for %d peers", peer_count)
			dns_retention_days = _safe_int(dns_data.get("dns_retention_days"), DEFAULT_DNS_LOG_RETENTION_DAYS)
			from .dns import ingestion as dns_ingestion
			await asyncio.to_thread(dns_ingestion.enforce_dns_log_retention, ctx.cfg.dns_dir, dns_retention_days)
			_log.info("DNS config written (IPv4: %s, IPv6: %s)", ", ".join(listen_addrs_ipv4) if listen_addrs_ipv4 else "none", ", ".join(listen_addrs_ipv6) if listen_addrs_ipv6 else "none")
			from .dns.unbound_blocklist import check_and_reset_stale_blocklist
			if check_and_reset_stale_blocklist():
				_log.info("Blocklist reset due to tag migration - triggering immediate update")
				try:
					bl_urls, bl_custom_rules = await asyncio.to_thread(_load_blocklist_update_inputs_sync, ctx.cfg.db_path)
					_, msg = await unbound.update_blocklists(bl_urls, custom_rules_text=bl_custom_rules)
					_log.info("BLOCKLIST_MIGRATION %s", msg)
				except Exception as exc:
					_log.warning("BLOCKLIST_MIGRATION update failed: %s", exc)
			ctx.dns_config_ready = True
	except FileNotFoundError as exc:
		_log.warning("DNS init skipped: unbound tools not found! Use Docker Image for full experience! (%s)", exc)
	except Exception:
		_log.exception("DNS config failed")

async def _phase_wireguard_start(ctx: LifespanContext) -> None:
	if not ctx.is_leader:
		return
	removed_stale = await _cleanup_stale_interfaces()
	if removed_stale:
		_log.info("Cleaned up %d stale interface(s): %s", len(removed_stale), removed_stale)
	if not ctx.interfaces_to_start:
		return
	async def _start_one(iface_name: str) -> str | None:
		try:
			check_proc = await asyncio.create_subprocess_exec("wg", "show", iface_name, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
			await _communicate_with_timeout(check_proc, timeout_seconds=_WG_CHECK_TIMEOUT_SECONDS)
			if check_proc.returncode == 0:
				_log.info("WireGuard interface %s already running", iface_name)
				return None
			proc = await asyncio.create_subprocess_exec("wg-quick", "up", iface_name, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
			_, stderr = await _communicate_with_timeout(proc, timeout_seconds=_WG_UP_TIMEOUT_SECONDS)
			if proc.returncode == 0:
				_log.info("WireGuard interface %s started", iface_name)
				return iface_name
			else:
				_log.warning("Failed to start interface %s: %s", iface_name, stderr.decode("utf-8", errors="replace"))
				return None
		except asyncio.TimeoutError:
			_log.warning("Timeout while starting/checking interface %s", iface_name)
			return None
		except Exception as e:
			_log.warning("Failed to start interface %s: %s", iface_name, e)
			return None
	sem = asyncio.Semaphore(_WG_STARTUP_CONCURRENCY)
	async def _start_guarded(iface_name: str) -> str | None:
		async with sem:
			return await _start_one(iface_name)
	results = await asyncio.gather(*[_start_guarded(name) for name in ctx.interfaces_to_start])
	ctx.started_interfaces = [r for r in results if r]

async def _phase_dns_start(ctx: LifespanContext) -> None:
	from .dns import unbound
	if ctx.is_leader and unbound.is_unbound_installed() and ctx.dns_config_ready:
		try:
			unbound_running = await unbound.is_running()
			if ctx.dns_service_enabled:
				if not unbound_running:
					ok, msg = await unbound.start()
					if ok:
						_log.info("Unbound DNS started")
						await asyncio.sleep(2)
					else:
						_log.warning("Failed to start Unbound: %s", msg)
			else:
				if unbound_running:
					ok, msg = await unbound.stop()
					if ok:
						_log.info("Unbound DNS kept stopped (persisted user preference)")
					else:
						_log.warning("Failed to keep Unbound stopped on startup: %s", msg)
				else:
					_log.info("Unbound autostart disabled; resolver remains stopped")
		except Exception:
			_log.exception("DNS start failed")

async def _phase_scheduler(ctx: LifespanContext) -> None:
	if not ctx.is_leader:
		return
	scheduler = Scheduler()
	ctx.scheduler = scheduler
	ctx.app.state.scheduler = scheduler
	from .dns import unbound
	from .tasks import scheduled as scheduled_tasks
	import os
	unbound_installed = unbound.is_unbound_installed()
	blocklist_enabled_startup = unbound_installed and await asyncio.to_thread(_read_blocklist_enabled_sync, ctx.cfg.db_path)
	blocklist_interval_seconds = 86400.0
	blocklist_jitter_pct = 0.1
	blocklist_run_on_start = False
	if blocklist_enabled_startup:
		try:
			blocklist_run_on_start = unbound.get_blocklist_count() <= 0
		except Exception:
			_log.warning("BLOCKLIST_STARTUP could not inspect local blocklist; scheduling startup update")
			blocklist_run_on_start = True
		if blocklist_run_on_start:
			_log.info("BLOCKLIST_STARTUP no cached blocklist found - scheduling immediate update")
		else:
			min_delay_h = (blocklist_interval_seconds * (1.0 - blocklist_jitter_pct)) / 3600.0
			max_delay_h = (blocklist_interval_seconds * (1.0 + blocklist_jitter_pct)) / 3600.0
			_log.info("BLOCKLIST_STARTUP cached blocklist found - deferring first update to %.1f-%.1f hours (interval=24h, jitter=±10%%)", min_delay_h, max_delay_h)
	else:
		if unbound_installed:
			_log.info("BLOCKLIST_STARTUP skipped: ad-blocker is disabled")
		else:
			_log.info("BLOCKLIST_STARTUP skipped: Unbound not installed")
	if unbound_installed:
		blocklist_initial_delay = 15.0 if blocklist_run_on_start else 0.0
		async def _update_blocklists() -> None:
			await scheduled_tasks.update_blocklists(ctx)
		scheduler.add("blocklist-update", interval_seconds=blocklist_interval_seconds, func=_update_blocklists, run_on_start=blocklist_run_on_start, initial_delay=blocklist_initial_delay, jitter_pct=blocklist_jitter_pct)
	async def _maintain_tsdb() -> None:
		await scheduled_tasks.maintain_tsdb(ctx)
	scheduler.add("tsdb-maintenance", interval_seconds=21600, func=_maintain_tsdb, run_on_start=True, initial_delay=30.0)
	async def _sample_tsdb_metrics() -> None:
		await scheduled_tasks.sample_tsdb_metrics(ctx)
	scheduler.add("tsdb-sample", interval_seconds=30.0, func=_sample_tsdb_metrics, run_on_start=True, initial_delay=10.0)
	try:
		from .utils.conntrack import init_conntrack_accounting
		await asyncio.to_thread(init_conntrack_accounting)
	except Exception as exc:
		_log.warning("COUNTRY_TRAFFIC could not enable conntrack accounting: %s", exc)
	async def _sample_country_traffic() -> None:
		await scheduled_tasks.sample_country_traffic(ctx)
	scheduler.add("country-traffic", interval_seconds=30.0, func=_sample_country_traffic, run_on_start=True, initial_delay=15.0)
	async def _sample_network_stats() -> None:
		await scheduled_tasks.sample_network_stats(ctx)
	scheduler.add("network-stats", interval_seconds=30, func=_sample_network_stats, run_on_start=True, initial_delay=12.0)
	async def _update_geoip() -> None:
		await scheduled_tasks.update_geoip(ctx)
	scheduler.add("geoip-update", interval_seconds=604800, func=_update_geoip, run_on_start=True, initial_delay=20.0)
	from .tasks.maintenance import sqlite_maintenance, sqlite_integrity_check, tsdb_retention_cleanup, cleanup_stale_sessions
	scheduler.add("sqlite-maintenance", interval_seconds=21600, func=sqlite_maintenance, run_on_start=True, initial_delay=60.0, timeout=60.0)
	scheduler.add("sqlite-integrity", interval_seconds=604800, func=sqlite_integrity_check, run_on_start=False, timeout=300.0)
	scheduler.add("tsdb-retention", interval_seconds=86400, func=tsdb_retention_cleanup, run_on_start=True, initial_delay=90.0, timeout=120.0)
	scheduler.add("session-cleanup", interval_seconds=3600, func=cleanup_stale_sessions, run_on_start=True, initial_delay=120.0, timeout=30.0)
	if unbound_installed:
		async def _dns_watchdog() -> None:
			await scheduled_tasks.dns_watchdog(ctx)
		scheduler.add("dns-watchdog", interval_seconds=30, func=_dns_watchdog, run_on_start=True, initial_delay=60.0, timeout=30.0)
		async def _check_adblocker_timer() -> None:
			await scheduled_tasks.check_adblocker_timer(ctx)
		scheduler.add("adblocker-timer-check", interval_seconds=15, func=_check_adblocker_timer, run_on_start=False, timeout=30.0)
	initial_speedtest_delay = scheduled_tasks._seconds_until_night_window()
	if initial_speedtest_delay > 0:
		from datetime import datetime as dt, timedelta
		scheduled_time = dt.now() + timedelta(seconds=initial_speedtest_delay)
		_log.info("SPEEDTEST_SCHEDULER first run in %.1f hours (at ~%s)", initial_speedtest_delay / 3600, scheduled_time.strftime("%H:%M"))
	async def _run_scheduled_speedtest() -> None:
		await scheduled_tasks.run_scheduled_speedtest(ctx)
	scheduler.add("speedtest", interval_seconds=86400, func=_run_scheduled_speedtest, run_on_start=True, initial_delay=initial_speedtest_delay, timeout=7500.0, jitter_pct=0.05)
	initial_backup_delay = _seconds_until_backup_time(os.environ.get("TZ", "UTC"))
	_log.info("SCHEDULED_BACKUP first run in %.1f hours (at ~%02d:00)", initial_backup_delay / 3600, _BACKUP_NIGHT_HOUR)
	async def _run_scheduled_backup() -> None:
		await scheduled_tasks.run_scheduled_backup(ctx)
	scheduler.add("scheduled-backup", interval_seconds=86400, func=_run_scheduled_backup, run_on_start=True, initial_delay=initial_backup_delay, timeout=300.0, jitter_pct=0.05)
	async def _run_node_health() -> None:
		await scheduled_tasks.monitor_node_health(ctx)
	scheduler.add("node-health", interval_seconds=60, func=_run_node_health, run_on_start=False, timeout=15.0)
	await scheduler.start()

async def _phase_dns_ingestion(ctx: LifespanContext) -> None:
	from .dns import unbound
	from .dns import ingestion as dns_ingestion
	if not unbound.is_unbound_installed():
		_log.info("DNS_INGESTION skipped: Unbound not installed")
		return
	retry_count = 0
	dns_retention_days_cache = DEFAULT_DNS_LOG_RETENTION_DAYS
	while True:
		should_run = await asyncio.to_thread(_should_unbound_run_sync, ctx.cfg.db_path)
		if not should_run:
			await asyncio.sleep(30.0)
			continue
		for attempt in range(15):
			if await unbound.is_running():
				break
			delay = min(2.0 ** attempt, 30.0)
			_log.debug("DNS_INGESTION waiting for Unbound (attempt %d, retry in %.0fs)", attempt + 1, delay)
			await asyncio.sleep(delay)
		else:
			_log.warning("DNS_INGESTION Unbound not ready after probes; starting ingestion anyway")
		def _current_dns_retention_days() -> int:
			return dns_retention_days_cache
		try:
			dns_retention_days_cache = await asyncio.to_thread(_read_dns_retention_days_sync, ctx.cfg.db_path)
			offset_path = ctx.cfg.data_dir / "dns" / "dns_tail.offset"
			offset_path.parent.mkdir(parents=True, exist_ok=True)
			legacy_offset_path = ctx.cfg.data_dir / "runtime" / "dns_tail.offset"
			if not offset_path.exists() and legacy_offset_path.exists():
				try:
					offset_path.write_text(legacy_offset_path.read_text(encoding="utf-8"), encoding="utf-8")
					legacy_offset_path.unlink(missing_ok=True)
					legacy_runtime_dir = legacy_offset_path.parent
					if legacy_runtime_dir.exists() and not any(legacy_runtime_dir.iterdir()):
						legacy_runtime_dir.rmdir()
					_log.info("DNS_INGESTION migrated offset file from %s to %s", legacy_offset_path, offset_path)
				except Exception as exc:
					_log.warning("DNS_INGESTION failed to migrate legacy offset file: %s", exc)
			await dns_ingestion.run_dns_ingestion(
				log_path=unbound.QUERY_LOG,
				offset_path=offset_path,
				dns_dir=ctx.cfg.dns_dir,
				blocked_domains_func=unbound.get_blocked_domains,
				retention_days_func=_current_dns_retention_days,
			)
			retry_count = 0
			_log.warning("DNS_INGESTION stopped unexpectedly; restarting in 5s")
			await asyncio.sleep(5.0)
		except asyncio.CancelledError:
			_log.info("DNS_INGESTION shutdown requested")
			raise
		except Exception as exc:
			retry_count += 1
			delay = min(_DNS_INGESTION_RESTART_BASE_DELAY_SECONDS ** retry_count, _DNS_INGESTION_RESTART_MAX_DELAY_SECONDS)
			_log.error("DNS_INGESTION crashed (retry #%d in %.0fs): %s", retry_count, delay, exc)
			await asyncio.sleep(delay)

@asynccontextmanager
async def _lifespan(app: FastAPI):
	\"\"\"Application lifespan manager.\"\"\"
	import os
	await _verify_host_network_mode()
	cfg = app.state.cfg
	ctx = LifespanContext(
		cfg=cfg,
		app=app,
		peer_connection_state=app.state.peer_connection_state,
	)
	try:
		await _phase_bootstrap(ctx)
		await _phase_dns_config(ctx)
		await _phase_wireguard_start(ctx)
		await _phase_dns_start(ctx)
		await _phase_scheduler(ctx)
		ctx.dns_task = asyncio.create_task(_phase_dns_ingestion(ctx))
		app.state.dns_task = ctx.dns_task
		app.state.is_leader = ctx.is_leader
		app.state.started_interfaces = ctx.started_interfaces
		_log.info("WireBuddy started successfully (leader=%s, pid=%d)", ctx.is_leader, os.getpid())
		yield
	finally:
		await _do_shutdown(ctx)
"""

    start_idx = code.find('@asynccontextmanager\nasync def _lifespan(')
    end_idx = code.find('\ndef create_app', start_idx)

    # Replace everything between the start of _lifespan and create_app with our phases
    if start_idx != -1 and end_idx != -1:
        new_code = code[:start_idx] + phases_code + code[end_idx:]
        with open('/opt/wirebuddy/app/main.py', 'w') as out:
            out.write(new_code)
        print("Refactoring successful.")
    else:
        print("Indexes not found!")

if __name__ == '__main__':
    refactor()
