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
        initialized: false,
        initializing: false,
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

    const VALID_TABS = Object.freeze(['general', 'wireguard', 'letsencrypt', 'dns', 'logs', 'backup']);
    const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
    const tabLoadPromises = new Map();

    // ========================================================================
    // DOM Cache
    // ========================================================================

    const dom = {};

    function initDomCache() {
        const cfg = document.getElementById('wb-page-config')?.dataset ?? {};
        const rawUserId = String(cfg.userId ?? '').trim();

        if (!/^\d+$/.test(rawUserId)) {
            logger.error('Invalid page config: userId missing or malformed');
            return false;
        }

        const userId = Number(rawUserId);
        if (!Number.isSafeInteger(userId) || userId < 1) {
            logger.error('Invalid page config: userId out of range');
            return false;
        }

        state.isAdmin = cfg.isAdmin === 'true';
        state.userId = userId;

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
        const moduleName = typeof name === 'string' ? name.trim() : '';
        if (!VALID_TABS.includes(moduleName)) {
            logger.error('Invalid settings module name', name);
            return false;
        }

        if (!module || typeof module !== 'object') {
            logger.error(`Invalid settings module ${moduleName}: expected object`);
            return false;
        }

        if (modules.has(moduleName)) {
            logger.warn(`Settings module ${moduleName} is already registered; replacing`);
        }

        if (typeof module.init !== 'function') {
            logger.warn(`Module ${moduleName} has no init() method`);
        }
        modules.set(moduleName, module);
        logger.debug(`Registered module: ${moduleName}`);

        // If registration happens after global init, initialize and load active tab lazily.
        if (state.initialized && typeof module.init === 'function') {
            void (async () => {
                try {
                    await module.init();
                    logger.debug(`Late module initialized: ${moduleName}`);
                    const activeTab = document.querySelector('#settingsTabs .nav-link.active');
                    if (activeTab?.id === `${moduleName}-tab` && !state.tabLoaded[moduleName]) {
                        await loadTabData(moduleName);
                    }
                } catch (err) {
                    logger.error(`Failed to initialize late module ${moduleName}`, err);
                }
            })();
        }

        return true;
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
        if (v === true || v === 1) return true;
        const value = String(v ?? '').trim().toLowerCase();
        return value === '1' || value === 'true' || value === 'yes' || value === 'on';
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
        const input = String(str ?? '');
        if (!input) return 'empty';

        // FNV-1a 32-bit: stable, fast, and avoids base64 allocations.
        let hash = 2166136261;
        for (let i = 0; i < input.length; i += 1) {
            hash ^= input.charCodeAt(i);
            hash = Math.imul(hash, 16777619);
        }

        return `h${(hash >>> 0).toString(36)}`;
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
        const value = Number(bytes);
        if (!Number.isFinite(value) || value <= 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const index = Math.min(
            Math.floor(Math.log(value) / Math.log(1024)),
            units.length - 1,
        );
        const normalized = value / Math.pow(1024, index);
        return `${normalized.toFixed(index > 0 ? 1 : 0)} ${units[index]}`;
    }

    function getBootstrapTab(tabBtn) {
        if (!window.bootstrap?.Tab) {
            logger.error('Bootstrap Tab plugin unavailable');
            return null;
        }

        try {
            return new window.bootstrap.Tab(tabBtn);
        } catch (err) {
            logger.error('Failed to initialize Bootstrap tab', err);
            return null;
        }
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
        window.addEventListener('pagehide', debounced.cancel, { once: true });
        return debounced;
    }

    function readCsrfToken() {
        const token = document.querySelector('meta[name="csrf-token"]')?.content
            || document.body?.dataset?.csrfToken
            || '';
        if (!token) {
            logger.error('CSRF token meta tag is missing; state-changing requests may fail.');
        }
        return token;
    }

    function readRequiredCsrfToken() {
        const token = readCsrfToken();
        if (!token) {
            throw new Error('CSRF token is missing');
        }
        return token;
    }

    function getTabIdFromButton(tabBtn) {
        const id = String(tabBtn?.id ?? '');
        if (!id.endsWith('-tab')) {
            return null;
        }

        const tabId = id.slice(0, -4);
        return VALID_TABS.includes(tabId) ? tabId : null;
    }

    function cloneWgSettings() {
        return typeof structuredClone === 'function'
            ? structuredClone(state.wgSettings)
            : { ...state.wgSettings };
    }

    /**
     * Make a same-origin fetch request with shared auth defaults.
     * @param {string} url
     * @param {RequestInit} [options]
     * @returns {Promise<Response>}
     */
    function fetchWithAuth(url, options = {}) {
        const targetUrl = new URL(String(url), window.location.origin);
        if (targetUrl.origin !== window.location.origin) {
            throw new Error('Cannot make requests to external origins');
        }

        const method = String(options.method || 'GET').toUpperCase();
        const headers = new Headers(options.headers || {});
        if (UNSAFE_METHODS.has(method) && !headers.has('X-CSRF-Token')) {
            headers.set('X-CSRF-Token', readRequiredCsrfToken());
        }

        return fetch(targetUrl.toString(), {
            ...options,
            credentials: options.credentials || 'same-origin',
            headers,
        });
    }

    // ========================================================================
    // Tab Management
    // ========================================================================

    /**
     * Initialize tab navigation with URL hash support.
     */
    async function initTabs() {
        const hash = window.location.hash.replace('#', '');

        if (hash && VALID_TABS.includes(hash)) {
            const tabBtn = document.getElementById(`${hash}-tab`);
            const tab = tabBtn ? getBootstrapTab(tabBtn) : null;
            tab?.show();
        }

        // Listen for tab changes
        document.querySelectorAll('#settingsTabs button[data-bs-toggle="tab"]').forEach(tabBtn => {
            if (tabBtn.dataset.wbTabBound === 'true') {
                return;
            }
            tabBtn.dataset.wbTabBound = 'true';
            tabBtn.addEventListener('shown.bs.tab', async function (e) {
                const tabId = getTabIdFromButton(e.target);
                if (!tabId) {
                    logger.warn('Ignoring unknown settings tab button', e.target?.id);
                    return;
                }

                history.replaceState(null, '', `#${tabId}`);
                await loadTabData(tabId);
            });
        });

        // Load initial tab data
        const activeTab = document.querySelector('#settingsTabs .nav-link.active');
        const activeTabId = getTabIdFromButton(activeTab);
        if (activeTabId) {
            await loadTabData(activeTabId);
        }
    }

    /**
     * Load tab data (lazy loading).
     * @param {string} tabId
     */
    async function loadTabData(tabId) {
        if (!Object.hasOwn(state.tabLoaded, tabId)) {
            logger.warn(`Unknown settings tab: ${tabId}`);
            return;
        }

        if (state.tabLoaded[tabId]) {
            return;
        }

        const existingLoad = tabLoadPromises.get(tabId);
        if (existingLoad) {
            await existingLoad;
            return;
        }

        const module = modules.get(tabId);
        if (typeof module?.load !== 'function') {
            state.tabLoaded[tabId] = true;
            return;
        }

        const loadPromise = (async () => {
            try {
                await module.load();
                state.tabLoaded[tabId] = true;
                logger.debug(`Tab loaded: ${tabId}`);
            } catch (err) {
                logger.error(`Failed to load tab ${tabId}`, err);
            } finally {
                tabLoadPromises.delete(tabId);
            }
        })();

        tabLoadPromises.set(tabId, loadPromise);
        await loadPromise;
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
        if (typeof window.api !== 'function') {
            const err = new Error('Global api() helper unavailable');
            logger.error(`${method} ${url}`, err);
            throw err;
        }

        const normalizedMethod = String(method || 'GET').toUpperCase();
        const targetUrl = new URL(String(url), window.location.origin);
        if (targetUrl.origin !== window.location.origin) {
            const err = new Error('Cannot make API calls to external origins');
            logger.error(`${normalizedMethod} ${url}`, err);
            throw err;
        }

        if (UNSAFE_METHODS.has(normalizedMethod)) {
            readRequiredCsrfToken();
        }

        try {
            return await window.api(normalizedMethod, targetUrl.toString(), data, opts);
        } catch (err) {
            if (typeof logger.apiError === 'function') {
                logger.apiError(`${normalizedMethod} ${url}`, err);
            } else {
                logger.error(`${normalizedMethod} ${url}`, err);
            }
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
        logger.warn('wbConfirm unavailable; using blocking fallback dialog');
        return window.confirm(message);
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    /**
     * Initialize the settings app.
     */
    async function init() {
        if (state.initialized || state.initializing) {
            return;
        }

        state.initializing = true;

        try {
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

            state.initialized = true;
            logger.info('Settings app initialized');
        } finally {
            state.initializing = false;
        }
    }

    function getState() {
        return {
            ...state,
            tabLoaded: { ...state.tabLoaded },
            wgSettings: cloneWgSettings(),
        };
    }

    function isInitialized() {
        return state.initialized;
    }

    function isInitializing() {
        return state.initializing;
    }

    // ========================================================================
    // Public API
    // ========================================================================

    const publicApi = {
        // State
        getState,
        isInitialized,
        isInitializing,
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
        fetchWithAuth,
        toast,
        confirm,

        // Lifecycle
        init
    };

    // Backward-compatible read-only state accessor.
    Object.defineProperty(publicApi, 'state', {
        enumerable: true,
        configurable: false,
        get: getState,
    });

    return publicApi;
})();

// Auto-initialize on DOMContentLoaded if modules are loaded via script tags
// For ES modules, call SettingsApp.init() explicitly after module registration
if (typeof document !== 'undefined') {
    const scheduleInit = () => {
        queueMicrotask(() => {
            if (!SettingsApp.isInitialized() && !SettingsApp.isInitializing()) {
                void SettingsApp.init();
            }
        });
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', scheduleInit, { once: true });
    } else {
        scheduleInit();
    }
}
