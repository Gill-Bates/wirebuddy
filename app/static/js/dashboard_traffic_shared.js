//
// app/static/js/dashboard_traffic_shared.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

/*
 * Shared helpers for dashboard/traffic pages.
 */
(function (window) {
    'use strict';

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
        return err?.code === 'ABORTED' || err?.name === 'AbortError' || err?.message === 'Request cancelled';
    }

    /**
     * Format a byte count into a human-readable string.
     * @param {number} bytes
     * @returns {string}
     */
    function formatBytes(bytes) {
        if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'];
        const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
        const unit = sizes[i];
        const decimals = (unit === 'MB' || unit === 'GB') ? 1 : 2;
        return Number((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + unit;
    }

    /**
     * Format traffic metrics in API display units.
     * @param {number | string | null | undefined} value
     * @param {string} unit
     * @returns {string}
     */
    function formatTrafficMetric(value, unit) {
        const parsed = Number(value);
        const n = Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
        const decimals = (unit === 'MB' || unit === 'GB') ? 1 : 2;
        return `${Number(n.toFixed(decimals))} ${unit}`;
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
            this.log = typeof opts?.log === 'function' ? opts.log : function () { };
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

        stop() {
            if (this.autoRefreshTimer === null) return;
            clearInterval(this.autoRefreshTimer);
            this.autoRefreshTimer = null;
        }

        abortActive() {
            if (this.activeRefreshController) this.activeRefreshController.abort();
        }

        destroy() {
            this.stop();
            this.abortActive();
            this.pendingRefresh = false;
            this._destroyed = true;
        }

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
                this.log('Refresh cycle failed unexpectedly:', err);
                allFailed = true;
            } finally {
                if (this.activeRefreshController === controller) this.activeRefreshController = null;
                this.isRefreshing = false;
                if (this._destroyed) return;

                if (allFailed) {
                    this.consecutiveFailures += 1;
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

    window.WBShared = Object.freeze({
        createDebugLogger,
        clearElement,
        isAbortError,
        formatBytes,
        formatTrafficMetric,
        RefreshScheduler,
    });
})(window);
