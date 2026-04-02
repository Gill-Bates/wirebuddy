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
        if (err?.name === 'AbortError') return true;
        if (err instanceof DOMException && err.name === 'AbortError') return true;
        if (err?.code === 'ABORTED') return true; // App-specific api() abort code
        return false;
    }

    function getDecimals(unit) {
        if (unit === 'B') return 0;
        if (unit === 'KB') return 1;
        return 1; // MB, GB, TB, PB, EB
    }

    const SIZE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'];

    function formatScaledSize(value, startUnitIndex) {
        if (!Number.isFinite(value) || value === 0) return '0 B';

        let unitIndex = startUnitIndex;
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
        const decimals = getDecimals(unit);
        return Number(scaledValue.toFixed(decimals)) + ' ' + unit;
    }

    /**
     * Format a byte count into a human-readable string.
     * Uses iterative division to avoid floating-point precision issues at exact
     * power-of-1024 boundaries (e.g., 1024^5 would produce "1024 TB" instead of "1 PB"
     * with log-based calculation due to Math.log(1024**5)/Math.log(1024) ≈ 4.9999...).
     * @param {number} bytes
     * @returns {string}
     */
    function formatBytes(bytes) {
        if (bytes < 0) {
            console.warn('formatBytes: negative value', bytes);
            return '0 B';
        }
        return formatScaledSize(bytes, 0);
    }

    /**
     * Format traffic metrics in API display units with automatic unit scaling.
     * Normalizes to bytes first, then delegates to formatBytes for consistent handling.
     * This eliminates incomplete unit chains (PB/EB were missing) and duplicated logic.
     * @param {number | string | null | undefined} value
     * @param {string} unit
     * @returns {string}
     */
    function formatTrafficMetric(value, unit) {
        const parsed = Number(value);
        if (!Number.isFinite(parsed) || parsed <= 0) return '0 B';
        if (parsed < 0) {
            console.warn('formatTrafficMetric: negative value', parsed);
            return '0 B';
        }

        // Convert input value to bytes (case-insensitive unit matching)
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
        const normalizedGbitDigits = Math.max(Number(gbitDigits) || 0, 0);
        const normalizedMbitDigits = Math.max(
            mbitDigits === undefined ? normalizedGbitDigits : (Number(mbitDigits) || 0),
            0,
        );

        if (numericValue >= 1000) {
            return `${(numericValue / 1000).toFixed(normalizedGbitDigits)} Gbit/s`;
        }
        return `${numericValue.toFixed(normalizedMbitDigits)} Mbit/s`;
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

    // Constants for RefreshScheduler
    const MIN_RETRY_DELAY_MS = 50;
    const BACKOFF_RETRY_DELAY_MS = 1000;

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
            this._pendingRetryTimer = null;
            this._timerId = 0; // Generation token to prevent timer race conditions
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
         * Uses setTimeout instead of setInterval to prevent abort storms when refresh
         * takes longer than the interval. The next refresh is scheduled only after the
         * previous one completes, ensuring proper spacing between refreshes.
         * Call refresh() first for immediate data, or use startWithImmediateRefresh().
         * @param {number} [intervalMs]
         */
        start(intervalMs) {
            if (this._destroyed) return;
            this.stop();
            const ms = Number(intervalMs) > 0 ? Number(intervalMs) : this.currentRefreshInterval;

            // Increment timer generation to prevent race conditions
            this._timerId = (this._timerId || 0) + 1;
            const timerId = this._timerId;

            this.autoRefreshTimer = setTimeout(() => {
                // Check if this timer is still valid (not superseded by stop/start)
                if (this._destroyed || timerId !== this._timerId) return;

                this.refresh().finally(() => {
                    // Schedule next refresh only if not destroyed and timer still valid
                    if (!this._destroyed && timerId === this._timerId && this.autoRefreshTimer !== null) {
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
            if (this.autoRefreshTimer === null) return;
            clearTimeout(this.autoRefreshTimer);
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
         * Also clears any pending retry timeout to prevent stray tasks on event loop.
         */
        destroy() {
            this.stop();
            this.abortActive();
            this.pendingRefresh = false;
            if (this._pendingRetryTimer !== null) {
                clearTimeout(this._pendingRetryTimer);
                this._pendingRetryTimer = null;
            }
            this._destroyed = true;
        }

        /**
         * Perform a single refresh, orchestrating backoff and retries.
         */
        async refresh() {
            if (this._destroyed) return;
            if (this.isRefreshing) {
                this.pendingRefresh = true;
                // Only abort if not already aborted
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
                // Early exit if destroyed to prevent callbacks
                if (this._destroyed) {
                    this.isRefreshing = false;
                    if (this.activeRefreshController === controller) this.activeRefreshController = null;
                    return;
                }

                if (this.activeRefreshController === controller) this.activeRefreshController = null;
                this.isRefreshing = false;

                if (allFailed) {
                    this.consecutiveFailures = Math.min(this.consecutiveFailures + 1, 100);
                    // Exponential backoff with jitter to prevent thundering herd
                    const jitter = Math.random() * 0.2 + 0.9; // 0.9–1.1
                    const backoffMs = Math.min(
                        this.autoRefreshMs * Math.pow(2, this.consecutiveFailures) * jitter,
                        this.maxBackoffMs,
                    );
                    if (backoffMs !== this.currentRefreshInterval) {
                        this.currentRefreshInterval = backoffMs;
                        this.start(backoffMs);
                    }
                    if (this.onAllFailed) {
                        this.onAllFailed({
                            consecutiveFailures: this.consecutiveFailures,
                            backoffMs: this.currentRefreshInterval,
                        });
                    }
                } else {
                    if (this.consecutiveFailures > 0) {
                        this.consecutiveFailures = 0;
                        this.currentRefreshInterval = this.autoRefreshMs;
                        this.start(this.autoRefreshMs);
                        if (this.onRecovered) this.onRecovered();
                    }
                }

                if (this.pendingRefresh) {
                    this.pendingRefresh = false;
                    const retryDelayMs = Math.max(
                        MIN_RETRY_DELAY_MS,
                        this.currentRefreshInterval > this.autoRefreshMs ? BACKOFF_RETRY_DELAY_MS : MIN_RETRY_DELAY_MS,
                    );
                    // Track timeout to clear in destroy()
                    this._pendingRetryTimer = setTimeout(() => {
                        this._pendingRetryTimer = null;
                        void this.refresh();
                    }, retryDelayMs);
                }
            }
        }
    }

    /**
     * Create empty-state placeholder element.
     * Requires CSS classes: .chart-empty-state, .chart-empty-state-text
     * Requires Material Icons font for the icon element.
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
     * Convert time range filter value (e.g., "7d", "30d", "y1") to hours.
     * Supports: 6h, 24h, 7d, 30d, 90d, 180d, y1 (1 year).
     * Used by DNS trend chart and potentially other pages.
     * @param {string} value - The range filter value
     * @param {number} [defaultHours=168] - Fallback value (default: 7 days)
     * @returns {number} Hours corresponding to the range value
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

    Object.freeze(RefreshScheduler.prototype);
    window.WBShared = Object.freeze({
        createDebugLogger,
        clearElement,
        isAbortError,
        formatBytes,
        formatTrafficMetric,
        formatBandwidthMetric,
        parseTimeRangeToHours,
        RefreshScheduler,
        chartEmptyState,
        // Note: getDecimals removed from exports (internal implementation detail)
    });
})(window);
