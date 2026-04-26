//
// app/static/js/api.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

class ApiError extends Error {
    constructor(message, code) {
        super(message);
        this.code = code;
        this.name = 'ApiError';
    }
}

const MAX_API_ERROR_MESSAGE_LENGTH = 500;

function startReconnectModeSafe() {
    if (typeof _startReconnectMode === 'function') {
        _startReconnectMode();
    }
}

function stopReconnectModeSafe() {
    if (typeof _stopReconnectMode === 'function') {
        _stopReconnectMode();
    }
}

function getReconnectStateSafe() {
    if (window.WBReconnect?.isActive?.()) {
        return { active: true };
    }
    return null;
}

// CSRF token helper
function getCsrfToken() {
    const token = document.querySelector('meta[name="csrf-token"]')?.content
        || document.body?.dataset?.csrfToken
        || '';
    if (!token) {
        console.error('CSRF token meta tag is missing; state-changing requests may fail.');
    }
    return token;
}

// Ensure specific session cleanup rather than nuking all sessionStorage
function clearSessionData() {
    sessionStorage.removeItem('wb_onboarding_shown');
    // Add targeted removeItem() calls here in the future
}

// Logout
let _logoutPromise = null;
async function logout() {
    if (_logoutPromise) return _logoutPromise;

    _logoutPromise = (async () => {
        clearSessionData();

        try {
            // Best-effort logout call, don't block redirect on failure
            await fetch('/api/logout', {
                method: 'POST',
                headers: {
                    'X-CSRF-Token': getCsrfToken(),
                },
                credentials: 'same-origin',
            }).catch(() => { });
        } finally {
            window.location.href = '/login';
            // Fallback reset only if redirect did not happen.
            setTimeout(() => {
                _logoutPromise = null;
            }, 3000);
        }
    })();

    return _logoutPromise;
}

// API helper – authentication is handled via HttpOnly cookie (set by server on login).
// No token is stored or sent manually from JavaScript.
/**
 * Make an authenticated API request with CSRF protection.
 *
 * @param {'GET'|'POST'|'PUT'|'PATCH'|'DELETE'} method
 * @param {string} url
 * @param {object|null} [data=null]
 * @param {{timeoutMs?: number|false, signal?: AbortSignal, skipAuthRedirect?: boolean}} [opts={}]
 * @returns {Promise<any>}
 * @throws {ApiError}
 */
async function api(method, url, data = null, opts = {}) {
    const targetUrl = new URL(url, window.location.origin);
    if (targetUrl.origin !== window.location.origin) {
        throw new ApiError('Cannot make API calls to external origins', 'INVALID_URL');
    }

    const headers = {
        'X-CSRF-Token': getCsrfToken(),
    };
    if (data !== null && data !== undefined) {
        headers['Content-Type'] = 'application/json';
    }

    const rawTimeout = opts?.timeoutMs;
    const timeoutMs = (rawTimeout === 0 || rawTimeout === false)
        ? 0
        : (Number.isFinite(Number(rawTimeout)) && Number(rawTimeout) > 0)
            ? Number(rawTimeout)
            : 15000;
    const externalSignal = opts?.signal || null;
    const skipAuthRedirect = opts?.skipAuthRedirect === true;
    const controller = new AbortController();
    let timeoutAbort = false;
    let timeoutId = null;
    let onExternalAbort = null;

    if (externalSignal?.aborted) {
        throw new ApiError('Request cancelled', 'ABORTED');
    }
    if (externalSignal) {
        onExternalAbort = () => controller.abort();
        externalSignal.addEventListener('abort', onExternalAbort, { once: true });
    }
    if (timeoutMs > 0) {
        timeoutId = setTimeout(() => {
            timeoutAbort = true;
            controller.abort();
        }, timeoutMs);
    }

    const options = { method, headers, signal: controller.signal, credentials: 'same-origin' };
    if (data !== null && data !== undefined) options.body = JSON.stringify(data);

    let res;
    try {
        res = await fetch(url, options);
    } catch (err) {
        if (err?.name === 'AbortError' && externalSignal?.aborted && !timeoutAbort) {
            throw new ApiError('Request cancelled', 'ABORTED');
        }
        // Timeout aborts are NOT network failures – don't trigger reconnect
        if (err?.name === 'AbortError' && timeoutAbort) {
            throw new ApiError('Request timed out', 'TIMEOUT');
        }
        // Actual network failure (connection refused, DNS, etc.)
        startReconnectModeSafe();
        throw new ApiError('Trying to reconnect ...', 'NETWORK_ERROR');
    } finally {
        if (timeoutId) clearTimeout(timeoutId);
        if (externalSignal && onExternalAbort) {
            externalSignal.removeEventListener('abort', onExternalAbort);
        }
    }

    if ([502, 503, 504].includes(res.status)) {
        startReconnectModeSafe();
        throw new ApiError('Trying to reconnect ...', 'SERVER_UNAVAILABLE');
    } else if (res.ok) {
        const reconnectState = getReconnectStateSafe();
        if (reconnectState) {
            if (reconnectState.active) {
                stopReconnectModeSafe();
            }
            reconnectState.failCount = 0;
        }
    }

    // Auto-redirect on 401 Unauthorized
    if (res.status === 401 && !skipAuthRedirect) {
        clearSessionData();
        if (!window.location.pathname.startsWith('/login')) {
            window.location.href = '/login';
        }
        throw new ApiError('Session expired', 'AUTH_EXPIRED');
    }

    // Robust content-type check for application/json including character encoding variations
    const isJson = res.headers.get('content-type')?.split(';')[0].trim() === 'application/json';
    const payload = isJson ? await res.json().catch(() => null) : null;

    if (!res.ok) {
        let msg = 'Request failed';
        if (payload?.detail) {
            // FastAPI validation errors return detail as array of objects
            if (Array.isArray(payload.detail)) {
                msg = payload.detail
                    .map(e => e?.msg || e?.message || JSON.stringify(e))
                    .join('; ');
            } else if (typeof payload.detail === 'string') {
                msg = payload.detail;
            } else {
                msg = String(payload.detail);
            }
        } else if (payload?.message) {
            msg = typeof payload.message === 'string' ? payload.message : String(payload.message);
        }
        msg = msg.slice(0, MAX_API_ERROR_MESSAGE_LENGTH);
        const error = new ApiError(msg, `HTTP_${res.status}`);
        error.status = res.status;
        error.retryAfter = res.headers.get('Retry-After');
        throw error;
    }

    if (res.status === 204) return null;

    // Normalize API envelope: {status: "ok", data: ...}
    // Return data if present, otherwise return payload itself (for message-only responses)
    if (payload && payload.status === 'ok') {
        return Object.prototype.hasOwnProperty.call(payload, 'data') ? payload.data : payload;
    }
    return payload;
}
