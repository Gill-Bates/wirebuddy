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
        if (err instanceof DOMException && err.code === DOMException.ABORT_ERR) return true;
        if (err?.code === 'ABORTED') return true; // App-specific api() abort code
        return false;
    }

    function getDecimals(unit) {
        if (unit === 'B') return 0;
        if (unit === 'KB') return 1;
        return 1; // MB, GB, TB, PB, EB
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
        if (!Number.isFinite(bytes) || bytes === 0) return '0 B';
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'];
        let i = 0;
        let value = bytes;
        while (i < sizes.length - 1 && value >= 1024) {
            value /= 1024;
            i++;
        }
        const decimals = getDecimals(sizes[i]);
        return Number(value.toFixed(decimals)) + ' ' + sizes[i];
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

        // Convert input value to bytes
        const unitToExp = { B: 0, KB: 1, MB: 2, GB: 3, TB: 4, PB: 5, EB: 6 };
        const exp = unitToExp[unit];
        if (exp === undefined) {
            console.warn('formatTrafficMetric: unknown unit', unit);
            return '0 B';
        }

        const bytes = parsed * Math.pow(1024, exp);
        return formatBytes(bytes);
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

            // Validate that refreshFn accepts signal parameter (by checking function.length)
            // This is a hint only - doesn't guarantee the signal is actually used
            if (refreshFn.length === 0) {
                console.warn('RefreshScheduler: refreshFn ignores signal parameter — abort will be ineffective');
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
            this.autoRefreshTimer = setTimeout(() => {
                this.refresh().finally(() => {
                    // Schedule next refresh only if not destroyed and timer still active
                    if (!this._destroyed && this.autoRefreshTimer !== null) {
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
                this.abortActive();
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
                if (this.activeRefreshController === controller) this.activeRefreshController = null;
                this.isRefreshing = false;
                if (this._destroyed) return;

                if (allFailed) {
                    this.consecutiveFailures = Math.min(this.consecutiveFailures + 1, 100);
                    // Standard exponential backoff: 1st failure → 2x, 2nd → 4x, 3rd → 8x
                    // (removed -1 so first failure triggers backoff immediately)
                    const backoffMs = Math.min(
                        this.autoRefreshMs * Math.pow(2, this.consecutiveFailures),
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
                        50,
                        this.currentRefreshInterval > this.autoRefreshMs ? 1000 : 50,
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

    Object.freeze(RefreshScheduler.prototype);
    window.WBShared = Object.freeze({
        createDebugLogger,
        clearElement,
        isAbortError,
        formatBytes,
        formatTrafficMetric,
        RefreshScheduler,
        chartEmptyState,
        // Note: getDecimals removed from exports (internal implementation detail)
    });
})(window);
