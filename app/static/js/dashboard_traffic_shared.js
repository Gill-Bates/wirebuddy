//
// app/static/js/dashboard_traffic_shared.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

/*
 * Shared helpers for dashboard/traffic pages.
 */
(function (window) {
    'use strict';

    if (window.WBShared !== undefined) {
        console.error('WBShared already defined — refusing to overwrite');
        return;
    }

    /**
     * Build a scoped debug logger.
     * @param {string} scope
     * @param {boolean} enabled
     * @returns {(...args: any[]) => void}
     */
    function createDebugLogger(scope, enabled) {
        return function (...args) {
            if (!enabled) return;
            console.log(`[${scope}]`, ...args);
        };
    }

    /**
     * Remove all child nodes from an element.
     * @param {Element | null | undefined} el
     */
    function clearElement(el) {
        if (el) el.replaceChildren();
    }

    /**
     * Detect whether an error represents an aborted request.
     * @param {any} err
     * @returns {boolean}
     */
    function isAbortError(err) {
        return err?.name === 'AbortError' || err?.code === 'ABORTED';
    }

    const SIZE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'];

    function formatScaledSize(value, startUnitIndex) {
        if (!Number.isFinite(value) || value <= 0) return '0 B';

        let unitIndex = Math.max(0, Math.min(startUnitIndex, SIZE_UNITS.length - 1));
        let scaledValue = value;

        while (unitIndex < SIZE_UNITS.length - 1 && scaledValue >= 1024) {
            scaledValue /= 1024;
            unitIndex += 1;
        }

        while (unitIndex > 0 && scaledValue > 0 && scaledValue < 1) {
            scaledValue *= 1024;
            unitIndex -= 1;
        }

        const unit = SIZE_UNITS[unitIndex];
        const decimals = unitIndex === 0 ? 0 : 1;
        return `${Number(scaledValue.toFixed(decimals))} ${unit}`;
    }

    /**
     * Format a byte count into a human-readable string.
     * Uses iterative division to avoid floating-point precision issues at exact
     * power-of-1024 boundaries.
     * @param {number} bytes
     * @returns {string}
     */
    function formatBytes(bytes) {
        if (bytes < 0) {
            console.warn('formatBytes: negative value', bytes);
        }
        return formatScaledSize(Math.max(0, Number(bytes) || 0), 0);
    }

    /**
     * Format traffic metrics in API display units with automatic unit scaling.
     * @param {number | string | null | undefined} value
     * @param {string} unit
     * @returns {string}
     */
    function formatTrafficMetric(value, unit) {
        const parsed = Number(value);
        const unitToExp = { B: 0, KB: 1, MB: 2, GB: 3, TB: 4, PB: 5, EB: 6 };
        const normalizedUnit = String(unit).toUpperCase();
        const exp = unitToExp[normalizedUnit];
        if (exp === undefined) {
            console.warn('formatTrafficMetric: unknown unit', unit);
            return '0 B';
        }
        return formatScaledSize(parsed, exp);
    }

    function formatBandwidthMetric(valueMbit, gbitDigits = 1, mbitDigits = gbitDigits) {
        const numericValue = Number(valueMbit);
        if (!Number.isFinite(numericValue)) return '–';

        const isGbit = numericValue >= 1000;
        const scaled = isGbit ? numericValue / 1000 : numericValue;
        const digits = Math.max(Number(isGbit ? gbitDigits : mbitDigits) || 0, 0);
        return `${scaled.toFixed(digits)} ${isGbit ? 'Gbit/s' : 'Mbit/s'}`;
    }

    const chartColorCache = { dark: null, light: null };

    function invalidateChartColorCache() {
        chartColorCache.dark = null;
        chartColorCache.light = null;
    }

    function getChartColors() {
        const isDark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
        const cacheKey = isDark ? 'dark' : 'light';
        const cached = chartColorCache[cacheKey];
        if (cached) return cached;

        const root = getComputedStyle(document.documentElement);
        const primaryColor = root.getPropertyValue('--wb-accent-red').trim() || '#ff6384';
        const accentRgb = root.getPropertyValue('--wb-accent-red-rgb').trim() || '255, 99, 132';
        const colors = {
            textColor: isDark ? '#b7c2d0' : '#6c757d',
            gridColor: isDark ? 'rgba(148,163,184,0.12)' : 'rgba(0,0,0,0.08)',
            primaryColor,
            accentRgb,
            dlColor: primaryColor,
            dlBg: isDark ? 'rgba(255,99,132,0.12)' : 'rgba(255,99,132,0.10)',
            ulColor: isDark ? '#6edff6' : '#0dcaf0',
            ulBg: isDark ? 'rgba(110,223,246,0.12)' : 'rgba(13,202,240,0.12)',
            rttColor: 'rgba(255, 193, 7, 0.85)',
        };
        chartColorCache[cacheKey] = colors;
        return colors;
    }

    if (typeof MutationObserver !== 'undefined') {
        new MutationObserver(() => invalidateChartColorCache()).observe(document.documentElement, {
            attributes: true,
            attributeFilter: ['data-bs-theme'],
        });
    }

    /**
     * @typedef {Object} RefreshSchedulerOptions
     * @property {number} [autoRefreshMs]
     * @property {number} [maxBackoffMs]
     * @property {(signal: AbortSignal) => Promise<boolean>} refreshFn
     * Must return `true` if at least one data source succeeded, `false` if all failed.
     * @property {(...args: any[]) => void} [log]
     * @property {(ctx: {consecutiveFailures: number, backoffMs: number}) => void} [onAllFailed]
     * @property {() => void} [onRecovered]
     */

    const MIN_RETRY_DELAY_MS = 50;

    /**
     * Refresh orchestration with cancellation and exponential backoff.
     */
    class RefreshScheduler {
        /**
         * @param {RefreshSchedulerOptions} opts
         */
        constructor(opts) {
            const refreshFn = opts?.refreshFn;
            if (typeof refreshFn !== 'function') {
                throw new Error('RefreshScheduler requires refreshFn(signal)');
            }

            this.autoRefreshMs = Number(opts?.autoRefreshMs) > 0 ? Number(opts.autoRefreshMs) : 30000;
            this.maxBackoffMs = Number(opts?.maxBackoffMs) > 0 ? Number(opts.maxBackoffMs) : 300000;
            this.refreshFn = refreshFn;
            this.log = typeof opts?.log === 'function' ? opts.log : console.warn.bind(console);
            this.onAllFailed = typeof opts?.onAllFailed === 'function' ? opts.onAllFailed : null;
            this.onRecovered = typeof opts?.onRecovered === 'function' ? opts.onRecovered : null;

            this.autoRefreshTimer = null;
            this.isRefreshing = false;
            this.activeRefreshController = null;
            this.pendingRefresh = false;
            this.consecutiveFailures = 0;
            this.currentRefreshInterval = this.autoRefreshMs;
            this._destroyed = false;
            this._timerId = 0;
        }

        get isActive() {
            return this.autoRefreshTimer !== null;
        }

        get failures() {
            return this.consecutiveFailures;
        }

        get refreshing() {
            return this.isRefreshing;
        }

        /**
         * Start periodic refresh.
         * @param {number} [intervalMs]
         */
        start(intervalMs) {
            if (this._destroyed) return;
            this.stop();

            const ms = Number(intervalMs) > 0 ? Number(intervalMs) : this.currentRefreshInterval;
            this._timerId += 1;
            const timerId = this._timerId;

            this.autoRefreshTimer = setTimeout(() => {
                if (this._destroyed || timerId !== this._timerId) return;
                this.autoRefreshTimer = null;
                void this.refresh().finally(() => {
                    if (!this._destroyed && timerId === this._timerId) {
                        this.start(ms);
                    }
                });
            }, ms);
        }

        /**
         * Refresh now and then start periodic refresh.
         * @param {number} [intervalMs]
         */
        async startWithImmediateRefresh(intervalMs) {
            if (this._destroyed) return;
            await this.refresh();
            this.start(intervalMs);
        }

        /**
         * Stop periodic refresh.
         */
        stop() {
            this._timerId += 1;
            if (this.autoRefreshTimer !== null) {
                clearTimeout(this.autoRefreshTimer);
            }
            this.autoRefreshTimer = null;
        }

        /**
         * Abort the currently active refresh request.
         */
        abortActive() {
            if (this.activeRefreshController) this.activeRefreshController.abort();
        }

        /**
         * Stop refreshing and abort active request, preventing further starts.
         */
        destroy() {
            this.stop();
            this.abortActive();
            this.pendingRefresh = false;
            this._destroyed = true;
        }

        /**
         * Perform a single refresh, orchestrating backoff and retries.
         */
        async refresh() {
            if (this._destroyed) return;
            if (this.isRefreshing) {
                this.pendingRefresh = true;
                if (this.activeRefreshController && !this.activeRefreshController.signal.aborted) {
                    this.activeRefreshController.abort();
                }
                return;
            }

            this.isRefreshing = true;
            const controller = new AbortController();
            this.activeRefreshController = controller;
            let allFailed = true;

            try {
                const success = Boolean(await this.refreshFn(controller.signal));
                allFailed = !success;
            } catch (err) {
                if (controller.signal.aborted) {
                    allFailed = false;
                } else {
                    this.log('Refresh cycle failed unexpectedly:', err);
                    allFailed = true;
                }
            } finally {
                if (this._destroyed) {
                    this.isRefreshing = false;
                    if (this.activeRefreshController === controller) this.activeRefreshController = null;
                    return;
                }

                if (this.activeRefreshController === controller) this.activeRefreshController = null;
                this.isRefreshing = false;

                let nextInterval = this.autoRefreshMs;

                if (allFailed) {
                    this.consecutiveFailures = Math.min(this.consecutiveFailures + 1, 100);
                    const jitter = Math.random() * 0.2 + 0.9;
                    const backoffMs = Math.min(
                        this.autoRefreshMs * Math.pow(2, this.consecutiveFailures) * jitter,
                        this.maxBackoffMs,
                    );
                    this.currentRefreshInterval = backoffMs;
                    if (this.onAllFailed) {
                        this.onAllFailed({
                            consecutiveFailures: this.consecutiveFailures,
                            backoffMs: this.currentRefreshInterval,
                        });
                    }
                    nextInterval = this.currentRefreshInterval;
                } else if (this.consecutiveFailures > 0) {
                    this.consecutiveFailures = 0;
                    this.currentRefreshInterval = this.autoRefreshMs;
                    if (this.onRecovered) this.onRecovered();
                    nextInterval = this.currentRefreshInterval;
                }

                if (this.pendingRefresh) {
                    this.pendingRefresh = false;
                    nextInterval = MIN_RETRY_DELAY_MS;
                }

                this.start(nextInterval);
            }
        }
    }

    /**
     * Create empty-state placeholder element.
     * @param {string} text
     * @returns {HTMLDivElement}
     */
    function chartEmptyState(text = 'No Data Available') {
        const wrapper = document.createElement('div');
        wrapper.className = 'chart-empty-state';
        const icon = document.createElement('span');
        icon.className = 'material-icons';
        icon.textContent = 'show_chart';
        icon.setAttribute('aria-hidden', 'true');
        const msg = document.createElement('span');
        msg.className = 'chart-empty-state-text';
        msg.textContent = text;
        wrapper.append(icon, msg);
        return wrapper;
    }

    /**
     * Convert time range filter value to hours.
     * @param {string} value
     * @param {number} [defaultHours=168]
     * @returns {number}
     */
    function parseTimeRangeToHours(value, defaultHours = 168) {
        const rangeMap = {
            '6h': 6,
            '24h': 24,
            '7d': 168,
            '30d': 720,
            '90d': 2160,
            '180d': 4320,
            'y1': 8760,
        };
        return rangeMap[value] ?? defaultHours;
    }

    window.WBShared = Object.freeze({
        createDebugLogger,
        clearElement,
        isAbortError,
        formatBytes,
        formatTrafficMetric,
        formatBandwidthMetric,
        getChartColors,
        parseTimeRangeToHours,
        RefreshScheduler,
        chartEmptyState,
    });
})(window);