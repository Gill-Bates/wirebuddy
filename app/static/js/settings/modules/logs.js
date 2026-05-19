//
// app/static/js/settings/modules/logs.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//
// Logs/Metrics settings module.
// Handles TSDB, DNS metrics, peer metrics, and speedtest retention.
//

SettingsApp.registerModule('logs', (function () {
    'use strict';

    const { api, toast, confirm, formatBytes } = SettingsApp;

    // Slider instances
    let tsdbSlider = null;
    let dnsMetricsSlider = null;
    let speedtestSlider = null;

    // ========================================================================
    // Utilities
    // ========================================================================

    /**
     * Update path display with tooltip.
     * @param {string} elementId
     * @param {string} path
     */
    function setMetricPath(elementId, path) {
        const el = document.getElementById(elementId);
        if (!el) return;
        el.textContent = path || '—';
        if (path) {
            el.title = path;
            el.setAttribute('aria-label', path);
        } else {
            el.removeAttribute('title');
            el.removeAttribute('aria-label');
        }
    }

    // ========================================================================
    // TSDB (Traffic Metrics)
    // ========================================================================

    async function loadTsdbStats() {
        try {
            const stats = await api('GET', '/api/wireguard/stats/tsdb');

            const size = stats.size_bytes || 0;
            const compressedSize = stats.compressed_size_bytes || 0;
            const archiveCount = stats.archive_count || 0;

            setMetricPath('tsdb-path', stats.path);

            const sizeEl = document.getElementById('tsdb-size');
            if (sizeEl) sizeEl.textContent = formatBytes(size);

            const peersEl = document.getElementById('tsdb-peers');
            if (peersEl) peersEl.textContent = stats.peer_count || 0;

            const filesEl = document.getElementById('tsdb-files');
            if (filesEl) filesEl.textContent = stats.file_count || 0;

            const archivesEl = document.getElementById('tsdb-archives');
            if (archivesEl) {
                archivesEl.textContent = `${archiveCount} (${formatBytes(compressedSize)})`;
            }

            // Update retention slider
            if (tsdbSlider && stats.retention_days != null) {
                tsdbSlider.setValue(stats.retention_days);
            }
        } catch (e) {
            console.error('Failed to load TSDB stats:', e);
        }
    }

    async function saveTsdbRetention(days) {
        if (days === 0) {
            const ok = await confirm(
                '"No Logs" disables traffic logging and deletes existing data. Dashboard charts will show "Logging disabled". Continue?',
                'warning'
            );
            if (!ok) {
                loadTsdbStats(); // Revert slider
                return;
            }
        }

        await api('PATCH', '/api/wireguard/stats/tsdb/retention', { retention_days: days });
        toast(`Traffic retention set to ${tsdbSlider.getValue() === 0 ? 'No Logs' : days + ' days'}`, 'success');
    }

    async function purgeTsdbLogs() {
        if (!await confirm('Delete all traffic metric data? This cannot be undone.', 'danger')) return;

        try {
            const res = await api('DELETE', '/api/wireguard/stats/tsdb');
            toast(res.message || 'Traffic metrics deleted', 'success');
            loadTsdbStats();
        } catch (e) {
            toast('Failed to delete traffic metrics: ' + e.message, 'danger');
        }
    }

    // ========================================================================
    // DNS Metrics
    // ========================================================================

    async function loadDnsMetricsStats() {
        try {
            const stats = await api('GET', '/api/dns/storage');

            setMetricPath('dns-metrics-path', stats.path);

            const sizeEl = document.getElementById('dns-metrics-size');
            if (sizeEl) sizeEl.textContent = formatBytes(stats.size_bytes || 0);

            const filesEl = document.getElementById('dns-metrics-files');
            if (filesEl) filesEl.textContent = stats.file_count || 0;

            // Update retention slider
            if (dnsMetricsSlider && stats.retention_days != null) {
                dnsMetricsSlider.setValue(stats.retention_days);
            }
        } catch (e) {
            console.error('Failed to load DNS metrics stats:', e);
        }
    }

    async function saveDnsMetricsRetention(days) {
        if (days === 0) {
            const ok = await confirm(
                '"No Logs" disables DNS logging and deletes existing DNS data. Continue?',
                'warning'
            );
            if (!ok) {
                loadDnsMetricsStats(); // Revert slider
                return;
            }
        }

        await api('POST', '/api/dns/config', { log_retention_days: days });
        toast(`DNS retention set to ${days === 0 ? 'No Logs' : days + ' days'}`, 'success');
    }

    async function purgeDnsLogs() {
        if (!await confirm('Delete all DNS query data? This cannot be undone.', 'danger')) return;

        try {
            const res = await api('DELETE', '/api/dns/logs');
            toast(res.message || 'DNS metrics deleted', 'success');
            loadDnsMetricsStats();
        } catch (e) {
            toast('Failed to delete DNS metrics: ' + e.message, 'danger');
        }
    }

    // ========================================================================
    // Peer Metrics
    // ========================================================================

    async function loadPeerMetricsStats() {
        try {
            const stats = await api('GET', '/api/wireguard/stats/peer-metrics');

            setMetricPath('peer-metrics-path', stats.full_path || stats.path);

            const sizeEl = document.getElementById('peer-metrics-size');
            if (sizeEl) sizeEl.textContent = formatBytes(stats.size_bytes || 0);

            const totalEl = document.getElementById('peer-metrics-total');
            if (totalEl) totalEl.textContent = stats.total_peers || 0;

            const hsEl = document.getElementById('peer-metrics-handshake');
            if (hsEl) hsEl.textContent = stats.peers_with_handshake || 0;
        } catch (e) {
            console.error('Failed to load peer metrics stats:', e);
        }
    }

    async function purgePeerLogs() {
        if (!await confirm('Reset all peer connection tracking data? This cannot be undone.', 'danger')) return;

        try {
            const res = await api('DELETE', '/api/wireguard/stats/peer-logs');
            toast(res.message || 'Peer metrics reset', 'success');
            loadPeerMetricsStats();
        } catch (e) {
            toast('Failed to reset peer metrics: ' + e.message, 'danger');
        }
    }

    // ========================================================================
    // Speedtest Metrics
    // ========================================================================

    async function loadSpeedtestStats() {
        try {
            const stats = await api('GET', '/api/wireguard/speedtest/storage');

            setMetricPath('speedtest-metrics-path', stats.path);

            const sizeEl = document.getElementById('speedtest-metrics-size');
            if (sizeEl) sizeEl.textContent = formatBytes(stats.size_bytes || 0);

            const recordsEl = document.getElementById('speedtest-metrics-records');
            if (recordsEl) recordsEl.textContent = stats.record_count || 0;

            // Update retention slider
            if (speedtestSlider && stats.retention_days != null) {
                speedtestSlider.setValue(stats.retention_days);
            }
        } catch (e) {
            console.error('Failed to load speedtest stats:', e);
        }
    }

    async function saveSpeedtestRetention(days) {
        if (days === 0) {
            const ok = await confirm(
                '"No Logs" disables speedtest logging and deletes existing data. Bandwidth history chart will be empty. Continue?',
                'warning'
            );
            if (!ok) {
                loadSpeedtestStats(); // Revert slider
                return;
            }
        }

        await api('PATCH', '/api/wireguard/speedtest/storage/retention', { retention_days: days });
        toast(`Speedtest retention set to ${days === 0 ? 'No Logs' : days + ' days'}`, 'success');
    }

    async function purgeSpeedtestLogs() {
        if (!await confirm('Delete all speedtest data? Bandwidth history chart will be empty. This cannot be undone.', 'danger')) return;

        try {
            const res = await api('DELETE', '/api/wireguard/speedtest/storage');
            toast(res.message || 'Speedtest data deleted', 'success');
            loadSpeedtestStats();
            // Notify dashboard to refresh speedtest chart
            document.dispatchEvent(new CustomEvent('speedtest-completed'));
        } catch (e) {
            toast('Failed to delete speedtest data: ' + e.message, 'danger');
        }
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    function initSliders() {
        // TSDB retention slider
        if (document.getElementById('tsdb-retention-slider')) {
            tsdbSlider = RetentionSlider({
                sliderId: 'tsdb-retention-slider',
                badgeId: 'tsdb-retention-value',
                defaultIndex: 5, // 365 days
                onSave: saveTsdbRetention
            });
        }

        // DNS metrics retention slider
        if (document.getElementById('dns-metrics-retention-slider')) {
            dnsMetricsSlider = RetentionSlider({
                sliderId: 'dns-metrics-retention-slider',
                badgeId: 'dns-metrics-retention-value',
                defaultIndex: 2, // 30 days
                onSave: saveDnsMetricsRetention
            });
        }

        // Speedtest retention slider
        if (document.getElementById('speedtest-retention-slider')) {
            speedtestSlider = RetentionSlider({
                sliderId: 'speedtest-retention-slider',
                badgeId: 'speedtest-retention-value',
                defaultIndex: 5, // 365 days
                onSave: saveSpeedtestRetention
            });
        }
    }

    function bindPurgeListeners() {
        // Purge buttons
        const purgeTsdbBtn = document.getElementById('btn-purge-tsdb');
        if (purgeTsdbBtn) purgeTsdbBtn.addEventListener('click', purgeTsdbLogs);

        const purgeDnsBtn = document.getElementById('btn-purge-dns-logs');
        if (purgeDnsBtn) purgeDnsBtn.addEventListener('click', purgeDnsLogs);

        const purgePeerBtn = document.getElementById('btn-purge-peer-logs');
        if (purgePeerBtn) purgePeerBtn.addEventListener('click', purgePeerLogs);

        const purgeSpeedtestBtn = document.getElementById('btn-purge-speedtest');
        if (purgeSpeedtestBtn) purgeSpeedtestBtn.addEventListener('click', purgeSpeedtestLogs);
    }

    // ========================================================================
    // Module API
    // ========================================================================

    return {
        init() {
            initSliders();
            bindPurgeListeners();
        },

        async load() {
            await Promise.all([
                loadTsdbStats(),
                loadDnsMetricsStats(),
                loadPeerMetricsStats(),
                loadSpeedtestStats()
            ]);
        },

        // Expose for external use
        loadTsdbStats,
        loadDnsMetricsStats,
        loadPeerMetricsStats,
        loadSpeedtestStats
    };
})());
