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

window._wbReconnectState = _wbReconnectState;

function _blurActiveElement() {
    document.activeElement?.blur();
}

function _getCsrfToken() {
    return typeof getCsrfToken === 'function' ? getCsrfToken() : '';
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
    if (_wbReconnectState.active || document.visibilityState === 'hidden') return;
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
        _blurActiveElement();
        _wbReconnectModal.hide();
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
        const res = await fetch(_wbReconnectState.pingUrl, {
            method: 'GET',
            headers: {
                'X-CSRF-Token': _getCsrfToken(),
                'Cache-Control': 'no-cache',
            },
            credentials: 'same-origin',
            cache: 'no-store',
        });
        if (res.status === 401) {
            window.location.href = '/login';
            return;
        }
        if (res.ok) {
            _stopReconnectMode();
            return;
        }
    } catch (err) {
        // Keep polling while server is down.
        _debugReconnectError('probe error', err);
    } finally {
        _wbReconnectState.inFlight = false;
    }

    if (_wbReconnectState.active) {
        _wbReconnectState.delayMs = Math.min(Math.round(_wbReconnectState.delayMs * 1.5), 30000);
        _wbReconnectState.timer = setTimeout(_probeReconnect, _wbReconnectState.delayMs);
    }
}

async function _heartbeatReconnectCheck() {
    if (_wbReconnectState.active || document.visibilityState === 'hidden' || _wbHeartbeatState.inFlight) {
        _scheduleHeartbeat();
        return;
    }

    _wbHeartbeatState.inFlight = true;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), _wbHeartbeatState.timeoutMs);

    try {
        const res = await fetch(_wbReconnectState.pingUrl, {
            method: 'GET',
            headers: {
                'X-CSRF-Token': _getCsrfToken(),
                'Cache-Control': 'no-cache',
            },
            credentials: 'same-origin',
            cache: 'no-store',
            signal: controller.signal,
        });

        if (res.status === 401) {
            window.location.href = '/login';
            return;
        }

        if (!res.ok) {
            if (!_startReconnectMode()) {
                _scheduleHeartbeat();
            }
            return;
        }

        _wbReconnectState.failCount = 0;
    } catch (err) {
        if (!_startReconnectMode()) {
            _scheduleHeartbeat();
        }
        _debugReconnectError('heartbeat error', err);
        return;
    } finally {
        clearTimeout(timeoutId);
        _wbHeartbeatState.inFlight = false;
    }

    _scheduleHeartbeat();
}

function _startReconnectMode() {
    if (_wbReconnectState.active) return;

    const now = Date.now();

    // Debounce: parallel failures within 500ms count as one batch
    if (now - (_wbReconnectState.lastFailAt || 0) > 500) {
        _wbReconnectState.failCount++;
    }
    _wbReconnectState.lastFailAt = now;

    if (_wbReconnectState.failCount < _wbReconnectState.failThreshold) {
        return false;
    }

    _wbReconnectState.active = true;
    _wbReconnectState.inFlight = false;
    _clearHeartbeatTimer();
    document.body.classList.add('wb-reconnecting');
    if (window._wbModal) {
        _blurActiveElement();
        window._wbModal.hide();
    }

    const toastContainer = document.getElementById('wbToastContainer');
    if (toastContainer) {
        toastContainer.querySelectorAll('.toast').forEach(el => {
            bootstrap.Toast.getInstance(el)?.dispose();
        });
        toastContainer.innerHTML = '';
    }

    if (_wbReconnectModal) _wbReconnectModal.show();
    window.dispatchEvent(new CustomEvent('wb:reconnect:start'));
    _probeReconnect();
    return true;
}

document.addEventListener('visibilitychange', () => {
    if (_wbReconnectState.active) return;
    if (document.visibilityState === 'visible') {
        _scheduleHeartbeat(1000);
    } else {
        _clearHeartbeatTimer();
    }
});

window.addEventListener('online', () => {
    if (_wbReconnectState.active) {
        _clearReconnectTimer();
        _probeReconnect();
        return;
    }
    _scheduleHeartbeat(500);
});

window.addEventListener('offline', () => {
    if (_wbReconnectState.active) return;
    _wbReconnectState.failCount = _wbReconnectState.failThreshold;
    _startReconnectMode();
});

window.addEventListener('pageshow', () => {
    if (_wbReconnectState.active) return;
    _scheduleHeartbeat(1000);
});

_scheduleHeartbeat();
