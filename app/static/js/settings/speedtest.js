//
// app/static/js/settings/speedtest.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Extracted speedtest runtime for the Settings page.
// Owns speedtest settings, retention, streaming execution, and history rendering.
//

(function () {
    'use strict';

    const formatBandwidthMetric = window.WBShared?.formatBandwidthMetric;
    if (typeof formatBandwidthMetric !== 'function') {
        console.error('[SettingsSpeedtest] WBShared.formatBandwidthMetric not available');
        return;
    }

    const state = {
        running: false,
        retentionSaving: false,
        activeEventSource: null,
        requestController: null,
    };

    const elements = {
        enabledToggle: null,
        runBtn: null,
        running: null,
        result: null,
        status: null,
        progress: null,
        download: null,
        upload: null,
        rtt: null,
        server: null,
        date: null,
        inlineDate: null,
        retentionSlider: null,
        retentionValue: null,
        purgeLogsBtn: null,
    };

    const FLAG_ICON_BASE_URL = '/static/vendor/flag-icons/flags/4x3';
    const SPEEDTEST_RETENTION_VALUES = [0, 7, 30, 90, 180, 365];
    const VALID_COUNTRY_CODE = /^[a-z]{2}$/;

    function getRequestController() {
        if (!state.requestController || state.requestController.signal.aborted) {
            state.requestController = new AbortController();
        }
        return state.requestController;
    }

    function abortRequests() {
        if (state.requestController) {
            state.requestController.abort();
            state.requestController = null;
        }
    }

    function isAbortError(error) {
        return error?.code === 'ABORTED' || error?.name === 'AbortError';
    }

    function refreshElements() {
        elements.enabledToggle = document.getElementById('speedtest-enabled');
        elements.runBtn = document.getElementById('btn-speedtest-run');
        elements.running = document.getElementById('speedtest-running');
        elements.result = document.getElementById('speedtest-result');
        elements.status = document.getElementById('speedtest-status');
        elements.progress = document.getElementById('speedtest-progress');
        elements.download = document.getElementById('speedtest-result-dl');
        elements.upload = document.getElementById('speedtest-result-ul');
        elements.rtt = document.getElementById('speedtest-result-rtt');
        elements.server = document.getElementById('speedtest-result-server');
        elements.date = document.getElementById('speedtest-result-date');
        elements.inlineDate = document.getElementById('speedtest-result-date-inline');
        elements.retentionSlider = document.getElementById('speedtest-retention-slider');
        elements.retentionValue = document.getElementById('speedtest-retention-value');
        elements.purgeLogsBtn = document.getElementById('btn-purge-speedtest-logs');
    }

    function speedtestRetentionLabel(days) {
        const value = Number(days);
        if (value === 0) return 'No Logs';
        if (value === 365) return '1 Year';
        return `${value} Days`;
    }

    function speedtestRetentionIndexForDays(days) {
        const idx = SPEEDTEST_RETENTION_VALUES.indexOf(Number(days));
        return idx >= 0 ? idx : 5;
    }

    function speedtestRetentionDaysFromSlider(rawValue) {
        const parsed = Number.parseInt(String(rawValue), 10);
        const idx = Number.isFinite(parsed)
            ? Math.max(0, Math.min(SPEEDTEST_RETENTION_VALUES.length - 1, parsed))
            : 5;
        return SPEEDTEST_RETENTION_VALUES[idx];
    }

    function updateSpeedtestRetentionPreview(rawValue) {
        const days = speedtestRetentionDaysFromSlider(rawValue);
        if (elements.retentionValue) {
            elements.retentionValue.textContent = speedtestRetentionLabel(days);
            elements.retentionValue.className = days === 0
                ? 'badge text-bg-danger'
                : 'badge text-bg-secondary';
        }
        return days;
    }

    function createCountryFlagElement(countryCode) {
        const code = String(countryCode || '').trim().toLowerCase();
        if (!VALID_COUNTRY_CODE.test(code)) return null;

        const img = document.createElement('img');
        img.className = 'peer-flag';
        img.alt = `Country flag: ${code.toUpperCase()}`;
        img.loading = 'lazy';
        img.decoding = 'async';
        img.src = `${FLAG_ICON_BASE_URL}/${code}.svg`;
        img.addEventListener('error', () => img.remove(), { once: true });
        return img;
    }

    function setSpeedtestStatusMessage(statusEl, rawMessage) {
        if (!statusEl) return;
        statusEl.replaceChildren();

        const message = String(rawMessage || 'Running…');
        const parts = message.split(/\((https?:\/\/[^)]+)\)/g);
        for (let index = 0; index < parts.length; index++) {
            const part = parts[index];
            if (!part) continue;
            if (index % 2 === 1) {
                const code = document.createElement('code');
                code.className = 'small';
                code.textContent = part;
                statusEl.append('(', code, ')');
            } else {
                statusEl.append(document.createTextNode(part));
            }
        }
    }

    function reportSpeedtestError(message) {
        wbToast(`Speed test failed: ${message || 'Unknown error'}`, 'danger');
    }

    function handleSpeedtestResult(data) {
        if (data?.status === 'busy') {
            wbToast('Network appears busy - measurement skipped', 'warning');
            return;
        }

        showSpeedtestResult(data);
        wbToast('Speed test completed', 'success');
        document.dispatchEvent(new CustomEvent('speedtest-completed'));
    }

    function createReportedError(message) {
        const error = new Error(message || 'Unknown error');
        error.speedtestReported = true;
        return error;
    }

    function formatSpeedtestMeasuredLabel(timestamp) {
        const date = new Date(timestamp);
        const diffMs = Date.now() - date.getTime();
        const diffMins = Math.floor(diffMs / 60000);

        if (diffMins >= 0 && diffMins < 1) {
            return 'Just now';
        }
        if (diffMins < 0) {
            return date.toLocaleString(undefined, {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
            });
        }
        if (diffMins < 60) {
            return `${diffMins} min ago`;
        }
        if (diffMins < 1440) {
            return `${Math.floor(diffMins / 60)}h ago`;
        }

        return date.toLocaleString(undefined, {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        });
    }

    function showSpeedtestResult(data) {
        if (!data || data.status === 'busy' || data.status === 'error') {
            console.warn('[speedtest] showSpeedtestResult called with non-ok result:', data?.status);
            return;
        }

        const {
            result: resultEl,
            download: dlEl,
            upload: ulEl,
            rtt: rttEl,
            server: serverEl,
            date: dateEl,
            inlineDate: inlineDateEl,
        } = elements;

        if (!resultEl) {
            console.debug('showSpeedtestResult: #speedtest-result not found in DOM');
            return;
        }

        resultEl.classList.remove('d-none');
        if (dlEl) dlEl.textContent = formatBandwidthMetric(data.download_mbit, 2);
        if (ulEl) ulEl.textContent = formatBandwidthMetric(data.upload_mbit, 2);
        if (rttEl) rttEl.textContent = data.rtt_ms != null ? `${data.rtt_ms.toFixed(2)} ms (±${(data.jitter_ms || 0).toFixed(2)})` : '–';

        if (serverEl) {
            serverEl.title = data.server || '';

            const flag = createCountryFlagElement(data.country_code);
            const fragment = document.createDocumentFragment();
            if (flag) {
                fragment.appendChild(flag);
                fragment.appendChild(document.createTextNode(' '));
            }
            fragment.appendChild(document.createTextNode(data.server || '–'));
            serverEl.replaceChildren(fragment);
        }

        if (inlineDateEl) {
            inlineDateEl.textContent = '';
            inlineDateEl.removeAttribute('aria-label');
        }

        if (!dateEl) return;
        if (!data.ts) {
            dateEl.textContent = '–';
            if (inlineDateEl) {
                inlineDateEl.textContent = '';
                inlineDateEl.removeAttribute('aria-label');
            }
            dateEl.title = '';
            return;
        }

        const date = new Date(data.ts);
        if (Number.isNaN(date.getTime())) {
            dateEl.textContent = '–';
            if (inlineDateEl) {
                inlineDateEl.textContent = '';
                inlineDateEl.removeAttribute('aria-label');
            }
            dateEl.title = '';
            return;
        }

        const label = formatSpeedtestMeasuredLabel(data.ts);
        dateEl.textContent = label;
        if (inlineDateEl) {
            inlineDateEl.textContent = label;
            inlineDateEl.setAttribute('aria-label', label);
        }
        dateEl.title = date.toLocaleString();
    }

    function initSpeedtestUI() {
        refreshElements();
        if (!document.getElementById('speedtest-enabled') && !document.getElementById('btn-speedtest-run')) {
            return;
        }

        const initTarget = elements.runBtn || elements.enabledToggle || elements.retentionSlider || elements.purgeLogsBtn;
        if (initTarget?.dataset.speedtestBound === 'true') {
            return;
        }

        if (initTarget) {
            initTarget.dataset.speedtestBound = 'true';
        }

        elements.enabledToggle?.addEventListener('change', saveSettings);
        elements.runBtn?.addEventListener('click', runSpeedtest);
        elements.retentionSlider?.addEventListener('input', function () {
            updateSpeedtestRetentionPreview(this.value);
        });
        elements.retentionSlider?.addEventListener('change', () => {
            void saveRetention();
        });
        elements.purgeLogsBtn?.addEventListener('click', () => {
            void purgeLogs();
        });
    }

    async function loadSettings() {
        refreshElements();
        const controller = getRequestController();
        try {
            const data = await api('GET', '/api/wireguard/speedtest/settings', null, {
                signal: controller.signal,
            });

            const { enabledToggle } = elements;
            if (enabledToggle) {
                const toggleWrap = enabledToggle.closest('.form-check') || enabledToggle.parentElement || enabledToggle;
                toggleWrap?.classList.add('no-transitions');
                enabledToggle.checked = !!data.enabled;
                window.requestAnimationFrame(() => {
                    toggleWrap?.classList.remove('no-transitions');
                });
            }

            if (data.last_result && typeof data.last_result === 'object') {
                showSpeedtestResult(data.last_result);
            } else {
                await loadLastSpeedtest();
            }
        } catch (error) {
            if (isAbortError(error)) return;
            console.error('Failed to load speedtest settings:', error);
            wbToast('Failed to load speedtest settings', 'danger');
        }
    }

    async function loadLastSpeedtest() {
        const controller = getRequestController();
        try {
            const data = await api('GET', '/api/wireguard/speedtest/history?limit=1', null, {
                signal: controller.signal,
            });
            if (data.history && data.history.length > 0) {
                showSpeedtestResult(data.history[0]);
            }
        } catch (error) {
            if (isAbortError(error)) return;
            console.debug('No speedtest history available:', error);
        }
    }

    async function saveSettings() {
        if (!document.getElementById('speedtest-enabled')) return;
        const enabledToggle = elements.enabledToggle || document.getElementById('speedtest-enabled');
        const payload = { enabled: !!enabledToggle?.checked };
        const controller = getRequestController();

        try {
            await api('PATCH', '/api/wireguard/speedtest/settings', payload, {
                signal: controller.signal,
            });
            wbToast(`Speedtest ${payload.enabled ? 'enabled' : 'disabled'}`, 'success');
        } catch (error) {
            if (isAbortError(error)) return;
            console.error('Speedtest settings save failed:', error);
            wbToast('Failed to save speedtest settings', 'danger');
        }
    }

    async function runSpeedtest() {
        if (state.running || window.isAdmin !== true) return;
        state.running = true;

        refreshElements();
        const { runBtn, running, result, status, progress } = elements;

        if (runBtn) runBtn.disabled = true;
        if (running) running.classList.remove('d-none');
        if (result) result.classList.add('d-none');
        if (status) status.textContent = 'Initializing…';
        if (progress) progress.textContent = '0%';

        try {
            await runSpeedtestWithSSE(status, progress);
        } catch (error) {
            if (!error?.speedtestReported) {
                reportSpeedtestError(error.message);
            }
        } finally {
            state.running = false;
            if (runBtn) runBtn.disabled = false;
            if (running) running.classList.add('d-none');
        }
    }

    function runSpeedtestWithSSE(statusEl, progressEl) {
        return new Promise((resolve, reject) => {
            const es = new EventSource('/api/wireguard/speedtest/run/stream');
            state.activeEventSource = es;
            let completed = false;
            let safetyTimer = null;

            function finish(callback) {
                if (completed) return;
                completed = true;
                if (safetyTimer !== null) {
                    clearTimeout(safetyTimer);
                    safetyTimer = null;
                }
                if (state.activeEventSource === es) {
                    state.activeEventSource = null;
                }
                es.close();
                callback();
            }

            es.addEventListener('progress', (e) => {
                try {
                    const data = JSON.parse(e.data);
                    setSpeedtestStatusMessage(statusEl, data.message);
                    const progress = Number(data.progress);
                    if (progressEl && Number.isFinite(progress)) {
                        const percent = Math.max(0, Math.min(100, Math.round(progress * 100)));
                        progressEl.textContent = `${percent}%`;
                    }
                } catch (error) {
                    console.warn('Failed to parse progress event:', error);
                }
            });

            es.addEventListener('result', (e) => {
                finish(() => {
                    try {
                        const data = JSON.parse(e.data);
                        handleSpeedtestResult(data);
                        resolve(data);
                    } catch (error) {
                        reject(error);
                    }
                });
            });

            es.addEventListener('error', (e) => {
                if (!e.data) return;
                finish(() => {
                    try {
                        const data = JSON.parse(e.data);
                        reportSpeedtestError(data.reason || 'Unknown error');
                        reject(createReportedError(data.reason || 'Unknown error'));
                    } catch (error) {
                        reject(error);
                    }
                });
            });

            es.onerror = () => {
                if (completed || state.activeEventSource !== es) return;
                finish(() => reject(new Error('SSE connection lost')));
            };

            safetyTimer = window.setTimeout(() => {
                finish(() => reject(new Error('Timeout')));
            }, 180000);
        });
    }

    async function loadStats() {
        refreshElements();
        const controller = getRequestController();
        try {
            const stats = await api('GET', '/api/wireguard/speedtest/storage', null, {
                signal: controller.signal,
            });

            setMetricPath('speedtest-metrics-path', stats.path);

            const sizeEl = document.getElementById('speedtest-metrics-size');
            if (sizeEl) sizeEl.textContent = formatBytes(stats.size_bytes || 0);

            const recordsEl = document.getElementById('speedtest-metrics-records');
            if (recordsEl) recordsEl.textContent = stats.record_count || 0;

            if (elements.retentionSlider && stats.retention_days != null) {
                elements.retentionSlider.value = String(speedtestRetentionIndexForDays(stats.retention_days));
                updateSpeedtestRetentionPreview(elements.retentionSlider.value);
            }
        } catch (error) {
            if (isAbortError(error)) return;
            console.error('Failed to load speedtest stats:', error);
        }
    }

    async function saveRetention() {
        if (state.retentionSaving) return;
        state.retentionSaving = true;
        const controller = getRequestController();

        refreshElements();
        const slider = elements.retentionSlider || document.getElementById('speedtest-retention-slider');
        const days = speedtestRetentionDaysFromSlider(slider?.value ?? 5);

        if (days === 0) {
            const ok = await wbConfirm(
                '"No Logs" disables speedtest logging and deletes existing data. Bandwidth history chart will be empty. Continue?',
                'warning'
            );
            if (!ok) {
                await loadStats();
                state.retentionSaving = false;
                return;
            }
        }

        try {
            await api('PATCH', '/api/wireguard/speedtest/storage/retention', { retention_days: days }, {
                signal: controller.signal,
            });
            wbToast(`Speedtest retention set to ${speedtestRetentionLabel(days)}`, 'success');
        } catch (error) {
            if (isAbortError(error)) return;
            console.error('Retention update failed:', error);
            wbToast('Failed to update speedtest retention', 'danger');
        } finally {
            state.retentionSaving = false;
        }
    }

    async function purgeLogs() {
        if (!await wbConfirm('Delete all speedtest data? Bandwidth history chart will be empty. This cannot be undone.', 'danger')) return;
        const controller = getRequestController();

        try {
            const res = await api('DELETE', '/api/wireguard/speedtest/storage', null, {
                signal: controller.signal,
            });
            wbToast(res.message || 'Speedtest data deleted', 'success');
            await loadStats();
            document.dispatchEvent(new CustomEvent('speedtest-completed'));
        } catch (error) {
            if (isAbortError(error)) return;
            console.error('Speedtest data purge failed:', error);
            wbToast('Failed to delete speedtest data', 'danger');
        }
    }

    function cleanup() {
        state.running = false;
        state.retentionSaving = false;
        abortRequests();

        if (state.activeEventSource) {
            state.activeEventSource.close();
            state.activeEventSource = null;
        }
    }

    window.addEventListener('pagehide', cleanup);
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
            cleanup();
        }
    });

    window.WB = window.WB || {};
    window.WB.settingsSpeedtest = {
        init: initSpeedtestUI,
        loadSettings,
        loadLastSpeedtest,
        saveSettings,
        runSpeedtest,
        loadStats,
        saveRetention,
        purgeLogs,
        showSpeedtestResult,
        formatSpeedtestMeasuredLabel,
        speedtestRetentionLabel,
        updateSpeedtestRetentionPreview,
    };

    initSpeedtestUI();
})();
