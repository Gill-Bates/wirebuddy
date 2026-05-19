//
// app/static/js/reconnect.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

(() => {
    'use strict';

    const RECONNECT_PROBE_TIMEOUT_MS = 10000;
    const WB_DEBUG = window.WB_DEBUG === true;

    let _wbReconnectModal = null;
    let _wbActiveController = null;
    let _wbLoginRedirected = false;
    let _wbPageHidden = document.visibilityState === 'hidden';

    const _wbReconnectState = {
        active: false,
        timer: null,
        inFlight: false,
        delayMs: 2000,
        pingUrl: '/api/wireguard/settings',
        failCount: 0,
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

    // Consumers of wb:reconnect:start/stop must unregister their own listeners on teardown.
    window.WBReconnect = _wbReconnectApi;

    function _getReconnectModal() {
        if (_wbReconnectModal) return _wbReconnectModal;

        const reconnectEl = document.getElementById('wbReconnectModal');
        if (!reconnectEl) return null;

        _wbReconnectModal = new bootstrap.Modal(reconnectEl);
        return _wbReconnectModal;
    }

    function _isReconnectActive() {
        return _wbReconnectState.active;
    }

    function _blurActiveElement() {
        document.activeElement?.blur();
    }

    function _redirectToLoginIfNeeded() {
        if (_wbLoginRedirected) {
            return;
        }

        if (!window.location.pathname.startsWith('/login')) {
            _wbLoginRedirected = true;
            window.location.replace('/login');
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

    function _abortActiveProbe() {
        if (_wbActiveController) {
            _wbActiveController.abort();
            _wbActiveController = null;
        }
    }

    async function _fetchPing({ timeoutMs = 0 } = {}) {
        _abortActiveProbe();

        const controller = new AbortController();
        _wbActiveController = controller;
        const timeoutId = timeoutMs > 0 ? setTimeout(() => controller.abort(), timeoutMs) : null;

        try {
            return await fetch(_wbReconnectState.pingUrl, {
                method: 'GET',
                headers: {
                    'Cache-Control': 'no-cache',
                },
                credentials: 'same-origin',
                cache: 'no-store',
                signal: controller.signal,
            });
        } finally {
            if (timeoutId) {
                clearTimeout(timeoutId);
            }
            if (_wbActiveController === controller) {
                _wbActiveController = null;
            }
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
        if (WB_DEBUG) {
            console.debug(`[reconnect] ${context}:`, err);
        }
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
        if (_isReconnectActive() || _wbPageHidden || document.visibilityState === 'hidden') return;
        _wbHeartbeatState.timer = setTimeout(_heartbeatReconnectCheck, delay);
    }

    function _scheduleCompensatedHeartbeat(startedAt) {
        const elapsed = performance.now() - startedAt;
        _scheduleHeartbeat(Math.max(1000, _wbHeartbeatState.delayMs - elapsed));
    }

    function _stopReconnectMode() {
        _clearReconnectTimer();
        _wbReconnectState.active = false;
        _wbReconnectState.inFlight = false;
        _wbReconnectState.delayMs = 2000;
        _wbReconnectState.failCount = 0;
        document.body?.classList.remove('wb-reconnecting');
        if (_wbReconnectModal) {
            _safeHideModal(_wbReconnectModal);
        }
        window.dispatchEvent(new CustomEvent('wb:reconnect:stop'));
        _scheduleHeartbeat();
    }

    async function _probeReconnect() {
        if (!_wbReconnectState.active) return;
        if (_wbReconnectState.inFlight) return;
        if (navigator.onLine === false) {
            _clearReconnectTimer();
            _wbReconnectState.delayMs = Math.min(Math.round(_wbReconnectState.delayMs * 1.5), 30000);
            _wbReconnectState.timer = setTimeout(_probeReconnect, _wbReconnectState.delayMs);
            return;
        }

        _clearReconnectTimer();
        _wbReconnectState.inFlight = true;

        try {
            const res = await _fetchPing({ timeoutMs: RECONNECT_PROBE_TIMEOUT_MS });
            if (_handlePingResponse(res) === 'handled') {
                return;
            }
        } catch (err) {
            // Keep polling while server is down.
            _debugReconnectError('probe error', err);
        } finally {
            _wbReconnectState.inFlight = false;
        }

        if (_wbReconnectState.active && !_wbPageHidden) {
            const jitter = 0.8 + (Math.random() * 0.4);
            _wbReconnectState.delayMs = Math.min(Math.round(_wbReconnectState.delayMs * 1.5 * jitter), 30000);
            _wbReconnectState.timer = setTimeout(_probeReconnect, _wbReconnectState.delayMs);
        }
    }

    async function _heartbeatReconnectCheck() {
        const startedAt = performance.now();

        if (_isReconnectActive() || _wbPageHidden || document.visibilityState === 'hidden' || _wbHeartbeatState.inFlight) {
            _scheduleHeartbeat();
            return;
        }

        if (navigator.onLine === false) {
            _startReconnectMode(true);
            return;
        }

        _wbHeartbeatState.inFlight = true;

        try {
            const res = await _fetchPing({ timeoutMs: _wbHeartbeatState.timeoutMs });
            if (_handlePingResponse(res) === 'handled') {
                if (res.ok) {
                    _wbReconnectState.failCount = 0;
                    _scheduleCompensatedHeartbeat(startedAt);
                }
                return;
            }
        } catch (err) {
            if (!_startReconnectMode()) {
                _scheduleCompensatedHeartbeat(startedAt);
            }
            _debugReconnectError('heartbeat error', err);
            return;
        } finally {
            _wbHeartbeatState.inFlight = false;
        }

        if (!_startReconnectMode()) {
            _scheduleCompensatedHeartbeat(startedAt);
        }
    }

    function _startReconnectMode(force = false) {
        if (_wbReconnectState.active) return true;

        if (!force) {
            _wbReconnectState.failCount++;
        }

        if (!force && _wbReconnectState.failCount < _wbReconnectState.failThreshold) {
            return false;
        }

        _enterReconnectMode();
        void _probeReconnect();
        return true;
    }

    function _enterReconnectMode() {
        _wbReconnectState.active = true;
        _wbReconnectState.inFlight = false;
        _clearHeartbeatTimer();
        document.body?.classList.add('wb-reconnecting');
        if (window._wbModal) {
            _safeHideModal(window._wbModal);
        }

        const toastContainer = document.getElementById('wbToastContainer');
        if (toastContainer) {
            toastContainer.replaceChildren();
        }

        const reconnectModal = _getReconnectModal();
        if (reconnectModal) reconnectModal.show();
        window.dispatchEvent(new CustomEvent('wb:reconnect:start'));
    }

    function _onVisibilityChange() {
        _wbPageHidden = document.visibilityState === 'hidden';
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
            void _probeReconnect();
            return;
        }
        _scheduleHeartbeat(500);
    }

    function _onOffline() {
        if (_wbReconnectState.active) return;
        _startReconnectMode(true);
    }

    function _onPageShow(event) {
        _wbPageHidden = false;
        if (!event?.persisted) return;
        if (_wbReconnectState.active) {
            void _probeReconnect();
            return;
        }
        _scheduleHeartbeat(1000);
    }

    function _onPageHide() {
        _wbPageHidden = true;
        _abortActiveProbe();
        _clearHeartbeatTimer();
        _clearReconnectTimer();
        _wbHeartbeatState.inFlight = false;
        _wbReconnectState.inFlight = false;
    }

    function destroyReconnect() {
        _abortActiveProbe();
        _clearHeartbeatTimer();
        _clearReconnectTimer();
        _wbReconnectState.active = false;
        _wbReconnectState.inFlight = false;
        _wbReconnectState.delayMs = 2000;
        _wbReconnectState.failCount = 0;
        _wbHeartbeatState.inFlight = false;
        _wbPageHidden = false;
        document.body?.classList.remove('wb-reconnecting');
        if (_wbReconnectModal) {
            _safeHideModal(_wbReconnectModal);
            _wbReconnectModal.dispose();
            _wbReconnectModal = null;
        }
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

})();
