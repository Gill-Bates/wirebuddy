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

// CSRF token helper
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.content || '';
}

// Ensure specific session cleanup rather than nuking all sessionStorage
function clearSessionData() {
    sessionStorage.removeItem('wb_onboarding_shown');
    // Add targeted removeItem() calls here in the future
}

// Logout
let _logoutInProgress = false;
async function logout() {
    if (_logoutInProgress) return;
    _logoutInProgress = true;

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
    }
}

// API helper – authentication is handled via HttpOnly cookie (set by server on login).
// No token is stored or sent manually from JavaScript.
async function api(method, url, data = null, opts = {}) {
    const headers = {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken(),
    };

    const timeoutMs = Number.isFinite(Number(opts?.timeoutMs)) ? Number(opts.timeoutMs) : 15000;
    const externalSignal = opts?.signal || null;
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
        _startReconnectMode();
        throw new ApiError('Trying to reconnect ...', 'NETWORK_ERROR');
    } finally {
        if (timeoutId) clearTimeout(timeoutId);
        if (externalSignal && onExternalAbort) {
            externalSignal.removeEventListener('abort', onExternalAbort);
        }
    }

    if ([502, 503, 504].includes(res.status)) {
        _startReconnectMode();
        throw new ApiError('Trying to reconnect ...', 'SERVER_UNAVAILABLE');
    } else if (res.ok) {
        if (_wbReconnectState?.active) {
            _stopReconnectMode();
        }
        if (_wbReconnectState) {
            _wbReconnectState.failCount = 0;
        }
    }

    // Auto-redirect on 401 Unauthorized
    if (res.status === 401) {
        clearSessionData();
        window.location.href = '/login';
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
                msg = payload.detail.map(e => e.msg || e.message || JSON.stringify(e)).join('; ');
            } else {
                msg = payload.detail;
            }
        } else if (payload?.message) {
            msg = payload.message;
        }
        throw new ApiError(msg, `HTTP_${res.status}`);
    }

    if (res.status === 204) return null;

    // Normalize API envelope: {status: "ok", data: ...}
    // Return data if present, otherwise return payload itself (for message-only responses)
    if (payload && payload.status === 'ok') {
        return payload.data !== undefined ? payload.data : payload;
    }
    return payload;
}
