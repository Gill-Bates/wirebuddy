//
// app/static/js/reconnect.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

const _wbReconnectEl = document.getElementById('wbReconnectModal');
const _wbReconnectModal = _wbReconnectEl ? new bootstrap.Modal(_wbReconnectEl) : null;

const _wbReconnectState = {
    active: false,
    timer: null,
    delayMs: 2000,
    pingUrl: '/api/wireguard/settings',
    startupGraceMs: 8000,
    startedAt: Date.now(),
    failCount: 0,
    lastFailAt: 0,
    failThreshold: 3,
};

function _clearReconnectTimer() {
    if (_wbReconnectState.timer) {
        clearTimeout(_wbReconnectState.timer);
        _wbReconnectState.timer = null;
    }
}

function _stopReconnectMode() {
    _clearReconnectTimer();
    _wbReconnectState.active = false;
    _wbReconnectState.failCount = 0;
    document.body.classList.remove('wb-reconnecting');
    if (_wbReconnectModal) {
        document.activeElement?.blur();
        _wbReconnectModal.hide();
    }
    window.dispatchEvent(new CustomEvent('wb:reconnect:stop'));
}

async function _probeReconnect() {
    if (!_wbReconnectState.active) return;
    try {
        const res = await fetch(_wbReconnectState.pingUrl, {
            method: 'GET',
            headers: {
                'X-CSRF-Token': getCsrfToken(),
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
    } catch (_) {
        // Keep polling while server is down.
    }

    _wbReconnectState.timer = setTimeout(_probeReconnect, _wbReconnectState.delayMs);
}

function _startReconnectMode() {
    if (_wbReconnectState.active) return;

    const now = Date.now();

    // Debounce: parallel failures within 500ms count as one batch
    if (now - (_wbReconnectState.lastFailAt || 0) > 500) {
        _wbReconnectState.failCount++;
    }
    _wbReconnectState.lastFailAt = now;

    const timeSinceStart = now - _wbReconnectState.startedAt;
    if (timeSinceStart < _wbReconnectState.startupGraceMs &&
        _wbReconnectState.failCount < _wbReconnectState.failThreshold) {
        return;
    }

    _wbReconnectState.active = true;
    document.body.classList.add('wb-reconnecting');
    if (window._wbModal) {
        document.activeElement?.blur();
        window._wbModal.hide();
    }

    const toastContainer = document.getElementById('wbToastContainer');
    if (toastContainer) toastContainer.innerHTML = '';

    if (_wbReconnectModal) _wbReconnectModal.show();
    window.dispatchEvent(new CustomEvent('wb:reconnect:start'));
    _probeReconnect();
}
