//
// app/static/js/settings/core.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Settings page core module - provides shared state, utilities, and module registry.
//

const SettingsApp = (function () {
    'use strict';

    const logger = window.WBLogger?.create('Settings') || console;

    // ========================================================================
    // State Management
    // ========================================================================

    const state = {
        isAdmin: false,
        userId: null,
        tabLoaded: {
            general: false,
            wireguard: false,
            letsencrypt: false,
            dns: false,
            logs: false,
            backup: false
        },
        wgSettings: {}
    };

    // ========================================================================
    // DOM Cache
    // ========================================================================

    const dom = {};

    function initDomCache() {
        const cfg = document.getElementById('wb-page-config')?.dataset ?? {};
        state.isAdmin = cfg.isAdmin === 'true';
        state.userId = Number.parseInt(cfg.userId || '', 10);

        if (!Number.isInteger(state.userId)) {
            logger.error('Invalid page config: userId missing or not an integer');
            return false;
        }

        return true;
    }

    // ========================================================================
    // Module Registry
    // ========================================================================

    const modules = new Map();

    /**
     * Register a settings module.
     * @param {string} name - Module name
     * @param {Object} module - Module object with init() method
     */
    function registerModule(name, module) {
        if (typeof module.init !== 'function') {
            logger.warn(`Module ${name} has no init() method`);
        }
        modules.set(name, module);
        logger.debug(`Registered module: ${name}`);
    }

    /**
     * Get a registered module.
     * @param {string} name
     * @returns {Object|undefined}
     */
    function getModule(name) {
        return modules.get(name);
    }

    // ========================================================================
    // Utilities
    // ========================================================================

    /**
     * Type-safe boolean conversion.
     * Handles '1', 1, true, 'true', etc.
     * @param {*} v
     * @returns {boolean}
     */
    function toBool(v) {
        return v === true || v === 1 || v === '1' || String(v).toLowerCase() === 'true';
    }

    /**
     * XSS-safe HTML escaping.
     * @param {string} str
     * @returns {string}
     */
    function escapeHtml(str) {
        const d = document.createElement('div');
        d.textContent = str ?? '';
        return d.innerHTML;
    }

    /**
     * Generate a simple hash for stable DOM IDs.
     * @param {string} str
     * @returns {string}
     */
    function hashId(str) {
        if (!str) return 'empty';
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash |= 0;
        }
        return Math.abs(hash).toString(36);
    }

    /**
     * Detect current hostname (strips IPv6 brackets).
     * @returns {string|null}
     */
    function detectHostname() {
        const hostname = window.location.hostname;
        if (!hostname) return null;
        return hostname.replace(/^\[|\]$/g, '');
    }

    /**
     * Format bytes to human-readable string.
     * @param {number} bytes
     * @returns {string}
     */
    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        const value = bytes / Math.pow(1024, i);
        return `${value.toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
    }

    /**
     * Create a debounced function.
     * @param {Function} fn
     * @param {number} delay
     * @returns {Function}
     */
    function debounce(fn, delay) {
        let timeoutId = null;
        const debounced = function (...args) {
            clearTimeout(timeoutId);
            timeoutId = setTimeout(() => fn.apply(this, args), delay);
        };
        debounced.cancel = () => clearTimeout(timeoutId);
        return debounced;
    }

    // ========================================================================
    // Tab Management
    // ========================================================================

    /**
     * Initialize tab navigation with URL hash support.
     */
    async function initTabs() {
        const hash = window.location.hash.replace('#', '');
        const validTabs = ['general', 'wireguard', 'letsencrypt', 'dns', 'logs', 'backup'];

        if (hash && validTabs.includes(hash)) {
            const tabBtn = document.getElementById(`${hash}-tab`);
            if (tabBtn) {
                const tab = new bootstrap.Tab(tabBtn);
                tab.show();
            }
        }

        // Listen for tab changes
        document.querySelectorAll('#settingsTabs button[data-bs-toggle="tab"]').forEach(tabBtn => {
            tabBtn.addEventListener('shown.bs.tab', async function (e) {
                const tabId = e.target.id.replace('-tab', '');
                history.replaceState(null, '', `#${tabId}`);
                await loadTabData(tabId);
            });
        });

        // Load initial tab data
        const activeTab = document.querySelector('#settingsTabs .nav-link.active');
        if (activeTab) {
            await loadTabData(activeTab.id.replace('-tab', ''));
        }
    }

    /**
     * Load tab data (lazy loading).
     * @param {string} tabId
     */
    async function loadTabData(tabId) {
        if (state.tabLoaded[tabId]) return;

        const module = modules.get(tabId);
        if (module?.load) {
            try {
                await module.load();
                state.tabLoaded[tabId] = true;
                logger.debug(`Tab loaded: ${tabId}`);
            } catch (err) {
                logger.error(`Failed to load tab ${tabId}`, err);
            }
        }
    }

    // ========================================================================
    // API Helpers
    // ========================================================================

    /**
     * Make API call with standard error handling.
     * @param {string} method
     * @param {string} url
     * @param {Object} [data]
     * @param {Object} [opts]
     * @returns {Promise<*>}
     */
    async function apiCall(method, url, data, opts) {
        try {
            return await api(method, url, data, opts);
        } catch (err) {
            logger.apiError(`${method} ${url}`, err);
            throw err;
        }
    }

    /**
     * Show toast notification.
     * @param {string} message
     * @param {'success'|'warning'|'danger'|'info'} type
     */
    function toast(message, type = 'info') {
        if (typeof wbToast === 'function') {
            wbToast(message, type);
        } else {
            logger.warn(`Toast unavailable: ${message}`);
        }
    }

    /**
     * Show confirmation dialog.
     * @param {string} message
     * @param {'warning'|'danger'} type
     * @returns {Promise<boolean>}
     */
    async function confirm(message, type = 'warning') {
        if (typeof wbConfirm === 'function') {
            return wbConfirm(message, type);
        }
        return window.confirm(message);
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    /**
     * Initialize the settings app.
     */
    async function init() {
        if (!initDomCache()) {
            logger.error('Settings initialization failed: invalid config');
            return;
        }

        logger.info('Initializing settings app', { isAdmin: state.isAdmin, userId: state.userId });

        // Initialize all registered modules
        for (const [name, module] of modules) {
            if (typeof module.init === 'function') {
                try {
                    await module.init();
                    logger.debug(`Module initialized: ${name}`);
                } catch (err) {
                    logger.error(`Failed to initialize module ${name}`, err);
                }
            }
        }

        // Initialize tabs
        await initTabs();

        logger.info('Settings app initialized');
    }

    // ========================================================================
    // Public API
    // ========================================================================

    return {
        // State
        state,
        dom,

        // Module management
        registerModule,
        getModule,

        // Utilities
        toBool,
        escapeHtml,
        hashId,
        detectHostname,
        formatBytes,
        debounce,

        // API helpers
        api: apiCall,
        toast,
        confirm,

        // Lifecycle
        init
    };
})();

// Auto-initialize on DOMContentLoaded if modules are loaded via script tags
// For ES modules, call SettingsApp.init() explicitly after module registration
if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
        // Delay initialization to allow modules to register
        setTimeout(() => {
            if (SettingsApp.state.userId === null) {
                SettingsApp.init();
            }
        }, 0);
    });
}
