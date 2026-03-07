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
        console.warn('WBShared already defined — overwriting');
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
     * @param {number} bytes
     * @returns {string}
     */
    function formatBytes(bytes) {
        if (bytes < 0) {
            console.warn('formatBytes: negative value', bytes);
            return '0 B';
        }
        if (!Number.isFinite(bytes) || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'];
        const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
        const unit = sizes[i];
        const decimals = getDecimals(unit);
        return Number((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + unit;
    }

    /**
     * Format traffic metrics in API display units with automatic unit scaling.
     * @param {number | string | null | undefined} value
     * @param {string} unit
     * @returns {string}
     */
    function formatTrafficMetric(value, unit) {
        const parsed = Number(value);
        let n;
        if (!Number.isFinite(parsed)) {
            n = 0;
        } else if (parsed < 0) {
            console.warn('formatTrafficMetric: negative value', parsed);
            n = 0;
        } else {
            n = parsed;
        }

        if (n === 0) return '0 B';

        let displayUnit = unit;

        // Auto-scale to larger units if needed
        if (displayUnit === 'B' && n >= 1024) {
            n = n / 1024;
            displayUnit = 'KB';
        }
        if (displayUnit === 'KB' && n >= 1024) {
            n = n / 1024;
            displayUnit = 'MB';
        }
        if (displayUnit === 'MB' && n >= 1024) {
            n = n / 1024;
            displayUnit = 'GB';
        }
        if (displayUnit === 'GB' && n >= 1024) {
            n = n / 1024;
            displayUnit = 'TB';
        }

        if (n > 0 && n < 0.01) {
            if (displayUnit === 'TB') { n *= 1024; displayUnit = 'GB'; }
            if (displayUnit === 'GB' && n < 0.01) { n *= 1024; displayUnit = 'MB'; }
            if (displayUnit === 'MB' && n < 0.01) { n *= 1024; displayUnit = 'KB'; }
            if (displayUnit === 'KB' && n < 0.01) { n *= 1024; displayUnit = 'B'; }
        }

        const decimals = getDecimals(displayUnit);
        return `${Number(n.toFixed(decimals))} ${displayUnit}`;
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
         * Call refresh() first for immediate data, or use startWithImmediateRefresh().
         * Note: Calling start() clears any pending interval and starts a fresh one.
         * @param {number} [intervalMs]
         */
        start(intervalMs) {
            if (this._destroyed) return;
            if (this.autoRefreshTimer !== null) clearInterval(this.autoRefreshTimer);
            const ms = Number(intervalMs) > 0 ? Number(intervalMs) : this.currentRefreshInterval;
            this.autoRefreshTimer = setInterval(() => {
                void this.refresh();
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
            clearInterval(this.autoRefreshTimer);
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
                    const backoffMs = Math.min(
                        this.autoRefreshMs * Math.pow(2, this.consecutiveFailures - 1),
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
                    setTimeout(() => {
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
        getDecimals,
        formatBytes,
        formatTrafficMetric,
        RefreshScheduler,
        chartEmptyState,
    });
})(window);
