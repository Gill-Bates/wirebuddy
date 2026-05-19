//
// app/static/js/core/logger.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Structured frontend logging with levels and optional context.
// Replaces scattered console.error/warn/debug calls.
//

(function () {
    'use strict';

    const LOG_LEVELS = {
        debug: 0,
        info: 1,
        warn: 2,
        error: 3,
        off: 4
    };

    // Default level: warn in production, debug in development
    let currentLevel = window.location.hostname === 'localhost' ? LOG_LEVELS.debug : LOG_LEVELS.warn;

    /**
     * Format log message with optional context.
     * @param {string} level
     * @param {string} module
     * @param {string} message
     * @param {Object} [context]
     * @returns {string}
     */
    function formatMessage(level, module, message, context) {
        const timestamp = new Date().toISOString().slice(11, 23);
        const prefix = `[${timestamp}] [${level.toUpperCase()}] [${module}]`;
        return context
            ? `${prefix} ${message}`
            : `${prefix} ${message}`;
    }

    /**
     * Create a logger instance for a specific module.
     * @param {string} moduleName
     * @returns {Object}
     */
    function createLogger(moduleName) {
        return {
            debug(message, context) {
                if (currentLevel <= LOG_LEVELS.debug) {
                    console.debug(formatMessage('debug', moduleName, message), context || '');
                }
            },

            info(message, context) {
                if (currentLevel <= LOG_LEVELS.info) {
                    console.info(formatMessage('info', moduleName, message), context || '');
                }
            },

            warn(message, context) {
                if (currentLevel <= LOG_LEVELS.warn) {
                    console.warn(formatMessage('warn', moduleName, message), context || '');
                }
            },

            error(message, context) {
                if (currentLevel <= LOG_LEVELS.error) {
                    console.error(formatMessage('error', moduleName, message), context || '');
                }
            },

            /**
             * Log API error with request context.
             * @param {string} operation
             * @param {Error} error
             */
            apiError(operation, error) {
                if (currentLevel <= LOG_LEVELS.error) {
                    const ctx = {
                        operation,
                        code: error.code || 'UNKNOWN',
                        message: error.message,
                        status: error.status
                    };
                    console.error(formatMessage('error', moduleName, `API failed: ${operation}`), ctx);
                }
            },

            /**
             * Log user action for audit trail.
             * @param {string} action
             * @param {Object} [details]
             */
            action(action, details) {
                if (currentLevel <= LOG_LEVELS.info) {
                    console.info(formatMessage('info', moduleName, `Action: ${action}`), details || '');
                }
            },

            /**
             * Time a function execution.
             * @param {string} label
             * @param {Function} fn
             * @returns {*}
             */
            time(label, fn) {
                if (currentLevel <= LOG_LEVELS.debug) {
                    const start = performance.now();
                    const result = fn();
                    const duration = (performance.now() - start).toFixed(2);
                    console.debug(formatMessage('debug', moduleName, `${label} took ${duration}ms`));
                    return result;
                }
                return fn();
            },

            /**
             * Time an async function execution.
             * @param {string} label
             * @param {Function} fn
             * @returns {Promise<*>}
             */
            async timeAsync(label, fn) {
                if (currentLevel <= LOG_LEVELS.debug) {
                    const start = performance.now();
                    const result = await fn();
                    const duration = (performance.now() - start).toFixed(2);
                    console.debug(formatMessage('debug', moduleName, `${label} took ${duration}ms`));
                    return result;
                }
                return fn();
            }
        };
    }

    /**
     * Set global log level.
     * @param {'debug'|'info'|'warn'|'error'|'off'} level
     */
    function setLogLevel(level) {
        if (LOG_LEVELS[level] !== undefined) {
            currentLevel = LOG_LEVELS[level];
        }
    }

    /**
     * Get current log level name.
     * @returns {string}
     */
    function getLogLevel() {
        for (const [name, value] of Object.entries(LOG_LEVELS)) {
            if (value === currentLevel) return name;
        }
        return 'unknown';
    }

    // Expose globally
    window.WBLogger = {
        create: createLogger,
        setLevel: setLogLevel,
        getLevel: getLogLevel,
        LEVELS: LOG_LEVELS
    };
})();
