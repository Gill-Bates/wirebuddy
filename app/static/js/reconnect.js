//
// app/static/js/reconnect.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

const _wbReconnectEl = document.getElementById('wbReconnectModal');
const _wbReconnectModal = _wbReconnectEl ? new bootstrap.Modal(_wbReconnectEl) : null;

const _wbReconnectState = {
    active: false,
    timer: null,
    inFlight: false,
    delayMs: 2000,
    pingUrl: '/api/wireguard/settings',
    failCount: 0,
    lastFailAt: 0,
    failThreshold: 3,
};

const _wbHeartbeatState = {
    timer: null,
    delayMs: 15000,
    timeoutMs: 4000,
    inFlight: false,
};

const _wbReconnectApi = Object.freeze({
    isActive: () => _wbReconnectState.active,
    destroy: destroyReconnect,
});

window.WBReconnect = _wbReconnectApi;

function _isReconnectActive() {
    return _wbReconnectState.active;
}

function _blurActiveElement() {
    document.activeElement?.blur();
}

function _redirectToLoginIfNeeded() {
    if (!window.location.pathname.startsWith('/login')) {
        window.location.href = '/login';
    }
}

function _safeHideModal(modal) {
    try {
        _blurActiveElement();
        modal?.hide();
    } catch (err) {
        _debugReconnectError('modal hide failed', err);
    }
}

function _getCsrfToken() {
    return typeof getCsrfToken === 'function' ? getCsrfToken() : '';
}

async function _fetchPing({ timeoutMs = 0 } = {}) {
    const controller = timeoutMs > 0 ? new AbortController() : null;
    const timeoutId = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;

    try {
        return await fetch(_wbReconnectState.pingUrl, {
            method: 'GET',
            headers: {
                'X-CSRF-Token': _getCsrfToken(),
                'Cache-Control': 'no-cache',
            },
            credentials: 'same-origin',
            cache: 'no-store',
            signal: controller ? controller.signal : undefined,
        });
    } finally {
        if (timeoutId) clearTimeout(timeoutId);
    }
}

function _handlePingResponse(res) {
    if (res.status === 401) {
        _redirectToLoginIfNeeded();
        return 'handled';
    }
    if (res.ok) {
        _stopReconnectMode();
        return 'handled';
    }
    return 'error';
}

function _debugReconnectError(context, err) {
    if (err instanceof DOMException && err.name === 'AbortError') return;
    console.debug(`[reconnect] ${context}:`, err);
}

function _clearReconnectTimer() {
    if (_wbReconnectState.timer) {
        clearTimeout(_wbReconnectState.timer);
        _wbReconnectState.timer = null;
    }
}

function _clearHeartbeatTimer() {
    if (_wbHeartbeatState.timer) {
        clearTimeout(_wbHeartbeatState.timer);
        _wbHeartbeatState.timer = null;
    }
}

function _scheduleHeartbeat(delay = _wbHeartbeatState.delayMs) {
    _clearHeartbeatTimer();
    if (_isReconnectActive() || document.visibilityState === 'hidden') return;
    _wbHeartbeatState.timer = setTimeout(_heartbeatReconnectCheck, delay);
}

function _stopReconnectMode() {
    _clearReconnectTimer();
    _wbReconnectState.active = false;
    _wbReconnectState.inFlight = false;
    _wbReconnectState.delayMs = 2000;
    _wbReconnectState.failCount = 0;
    document.body.classList.remove('wb-reconnecting');
    if (_wbReconnectModal) {
        _safeHideModal(_wbReconnectModal);
    }
    window.dispatchEvent(new CustomEvent('wb:reconnect:stop'));
    _scheduleHeartbeat();
}

async function _probeReconnect() {
    if (!_wbReconnectState.active) return;
    if (_wbReconnectState.inFlight) return;

    _clearReconnectTimer();
    _wbReconnectState.inFlight = true;

    try {
        const res = await _fetchPing();
        if (_handlePingResponse(res) === 'handled') {
            return;
        }
    } catch (err) {
        // Keep polling while server is down.
        _debugReconnectError('probe error', err);
    } finally {
        _wbReconnectState.inFlight = false;
    }

    if (_wbReconnectState.active) {
        const jitter = 0.8 + (Math.random() * 0.4);
        _wbReconnectState.delayMs = Math.min(Math.round(_wbReconnectState.delayMs * 1.5 * jitter), 30000);
        _wbReconnectState.timer = setTimeout(_probeReconnect, _wbReconnectState.delayMs);
    }
}

async function _heartbeatReconnectCheck() {
    if (_isReconnectActive() || document.visibilityState === 'hidden' || _wbHeartbeatState.inFlight) {
        _scheduleHeartbeat();
        return;
    }

    _wbHeartbeatState.inFlight = true;

    try {
        const res = await _fetchPing({ timeoutMs: _wbHeartbeatState.timeoutMs });
        if (_handlePingResponse(res) === 'handled') {
            if (res.ok) {
                _wbReconnectState.failCount = 0;
                _scheduleHeartbeat();
            }
            return;
        }
    } catch (err) {
        if (!_startReconnectMode()) {
            _scheduleHeartbeat();
        }
        _debugReconnectError('heartbeat error', err);
        return;
    } finally {
        _wbHeartbeatState.inFlight = false;
    }

    if (!_startReconnectMode()) {
        _scheduleHeartbeat();
    }
}

function _startReconnectMode(force = false) {
    if (_wbReconnectState.active) return true;

    const now = Date.now();
    const inSameBatch = (now - (_wbReconnectState.lastFailAt || 0)) <= 500;

    // Debounce: parallel failures within 500ms count as one batch
    if (!inSameBatch) {
        _wbReconnectState.failCount++;
    }
    _wbReconnectState.lastFailAt = now;

    if (!force && _wbReconnectState.failCount < _wbReconnectState.failThreshold) {
        return false;
    }

    _enterReconnectMode();
    _probeReconnect();
    return true;
}

function _enterReconnectMode() {
    _wbReconnectState.active = true;
    _wbReconnectState.inFlight = false;
    _clearHeartbeatTimer();
    document.body.classList.add('wb-reconnecting');
    if (window._wbModal) {
        _safeHideModal(window._wbModal);
    }

    const toastContainer = document.getElementById('wbToastContainer');
    if (toastContainer) {
        toastContainer.querySelectorAll('.toast').forEach(el => {
            bootstrap.Toast.getInstance(el)?.dispose();
        });
        toastContainer.replaceChildren();
    }

    if (_wbReconnectModal) _wbReconnectModal.show();
    window.dispatchEvent(new CustomEvent('wb:reconnect:start'));
}

function _onVisibilityChange() {
    if (_wbReconnectState.active) return;
    if (document.visibilityState === 'visible') {
        _scheduleHeartbeat(1000);
    } else {
        _clearHeartbeatTimer();
    }
}

function _onOnline() {
    if (_wbReconnectState.active) {
        _clearReconnectTimer();
        _probeReconnect();
        return;
    }
    _scheduleHeartbeat(500);
}

function _onOffline() {
    if (_wbReconnectState.active) return;
    _startReconnectMode(true);
}

function _onPageShow() {
    if (_wbReconnectState.active) return;
    _scheduleHeartbeat(1000);
}

function _onPageHide() {
    _clearHeartbeatTimer();
    _clearReconnectTimer();
    _wbHeartbeatState.inFlight = false;
}

function destroyReconnect() {
    _clearHeartbeatTimer();
    _clearReconnectTimer();
    document.removeEventListener('visibilitychange', _onVisibilityChange);
    window.removeEventListener('online', _onOnline);
    window.removeEventListener('offline', _onOffline);
    window.removeEventListener('pageshow', _onPageShow);
    window.removeEventListener('pagehide', _onPageHide);
}

document.addEventListener('visibilitychange', _onVisibilityChange);
window.addEventListener('online', _onOnline);
window.addEventListener('offline', _onOffline);
window.addEventListener('pageshow', _onPageShow);
window.addEventListener('pagehide', _onPageHide);

_scheduleHeartbeat();
