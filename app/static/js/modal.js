//
// app/static/js/modal.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

const _wbModalEl = document.getElementById('wbModal');
window._wbModal = _wbModalEl ? new bootstrap.Modal(_wbModalEl) : null;

const _wbIcons = {
    info: { icon: 'info', color: 'var(--wb-primary)' },
    success: { icon: 'check_circle', color: 'var(--wb-success)' },
    warning: { icon: 'warning', color: 'var(--wb-warning)' },
    danger: { icon: 'error', color: 'var(--wb-danger)' },
    confirm: { icon: 'help', color: 'var(--wb-primary)' },
    prompt: { icon: 'edit', color: 'var(--wb-primary)' },
};

const _wbAlertTypes = new Set(['info', 'success', 'warning', 'danger']);
// Whitelist safe input types for wbPrompt to avoid unsupported/surprising controls.
const _wbAllowedInputTypes = new Set(['text', 'password', 'email', 'number', 'url', 'tel', 'search']);
let _wbModalPendingFinish = null;
let _wbModalPendingAbort = null;

function _showModal({ title, message, type, showCancel, showInput, inputDefault, inputPlaceholder, inputType }) {
    const dismissValue = showInput ? null : (showCancel ? false : true);

    // Suppress modal UX interruptions while reconnect flow is active.
    if (window._wbReconnectState?.active) {
        return Promise.resolve(dismissValue);
    }

    if (!_wbModalEl || !window._wbModal) {
        console.error('Modal: #wbModal element or bootstrap instance missing');
        return Promise.resolve(dismissValue);
    }

    // Ensure previous modal promise settles before wiring a new modal lifecycle.
    if (typeof _wbModalPendingFinish === 'function') {
        _wbModalPendingFinish();
    }
    if (_wbModalPendingAbort) {
        _wbModalPendingAbort.abort();
        _wbModalPendingAbort = null;
    }

    return new Promise(resolve => {
        const controller = new AbortController();
        const signal = controller.signal;
        _wbModalPendingAbort = controller;

        let settled = false;
        let fallbackTimer = null;
        let closeValue = dismissValue;

        function safeResolve(val) {
            if (settled) return;
            settled = true;
            if (fallbackTimer) {
                clearTimeout(fallbackTimer);
                fallbackTimer = null;
            }
            if (_wbModalPendingFinish === finish) {
                _wbModalPendingFinish = null;
            }
            if (_wbModalPendingAbort === controller) {
                _wbModalPendingAbort = null;
            }
            controller.abort();
            resolve(val);
        }

        function finish(val = dismissValue) {
            if (settled) return;
            closeValue = val;
            if (!_wbModalEl.classList.contains('show')) {
                safeResolve(closeValue);
                return;
            }
            fallbackTimer = setTimeout(() => safeResolve(closeValue), 500);
            window._wbModal.hide();
        }

        // Close non-form modals to prevent stacking, but preserve form modals
        document.querySelectorAll('.modal.show').forEach(modal => {
            const bsModal = bootstrap.Modal.getInstance(modal);
            if (bsModal && modal.id !== 'wbModal' && !modal.querySelector('form')) {
                bsModal.hide();
            }
        });

        const cfg = _wbIcons[type] || _wbIcons.info;
        const titleEl = document.getElementById('wbModalTitle');
        const messageEl = document.getElementById('wbModalMessage');
        const iconEl = document.getElementById('wbModalIcon');
        const cancelBtn = document.getElementById('wbModalCancel');
        const inputWrap = document.getElementById('wbModalInputWrap');
        const inputEl = document.getElementById('wbModalInput');
        const okBtn = document.getElementById('wbModalOk');
        const closeBtn = document.getElementById('wbModalClose');

        if (!titleEl || !messageEl || !iconEl || !cancelBtn || !inputWrap || !inputEl || !okBtn) {
            console.error('Modal: required DOM elements missing');
            safeResolve(dismissValue);
            return;
        }

        // Register active modal finisher only after required DOM is confirmed.
        _wbModalPendingFinish = finish;

        titleEl.textContent = title;
        messageEl.textContent = message;
        iconEl.textContent = cfg.icon;
        iconEl.style.color = cfg.color;

        cancelBtn.classList.toggle('d-none', !showCancel);

        inputWrap.classList.toggle('d-none', !showInput);
        if (showInput) {
            inputEl.value = inputDefault || '';
            inputEl.placeholder = inputPlaceholder || '';
            const normalizedType = String(inputType || 'text').toLowerCase();
            inputEl.type = _wbAllowedInputTypes.has(normalizedType) ? normalizedType : 'text';
        }

        okBtn.className = 'btn ' + (type === 'danger' ? 'btn-danger' : 'btn-primary');
        okBtn.textContent = showCancel || showInput ? 'Confirm' : 'OK';

        okBtn.addEventListener('click', () => {
            if (showInput) finish(inputEl.value);
            else finish(true);
        }, { signal });

        cancelBtn.addEventListener('click', () => finish(dismissValue), { signal });
        if (closeBtn) closeBtn.addEventListener('click', () => finish(dismissValue), { signal });

        if (showInput) {
            inputEl.addEventListener('keydown', e => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    okBtn.click();
                }
            }, { signal });
            _wbModalEl.addEventListener('shown.bs.modal', () => {
                inputEl.focus();
                inputEl.select();
            }, { once: true, signal });
        }

        // Catches all hide completions: finish(), ESC, backdrop click, or external hide().
        _wbModalEl.addEventListener('hidden.bs.modal', () => {
            safeResolve(closeValue);
        }, { once: true, signal });

        window._wbModal.show();
    });
}

function wbAlert(message, type = 'info') {
    const safeType = _wbAlertTypes.has(type) ? type : 'info';
    const titles = { info: 'Info', success: 'Success', warning: 'Warning', danger: 'Error' };
    return _showModal({ title: titles[safeType], message, type: safeType, showCancel: false, showInput: false });
}

function wbConfirm(message, type = 'confirm') {
    return _showModal({ title: 'Confirm', message, type, showCancel: true, showInput: false });
}

function wbPrompt(message, { defaultValue = '', placeholder = '', inputType = 'text', title = 'Input' } = {}) {
    return _showModal({ title, message, type: 'prompt', showCancel: true, showInput: true, inputDefault: defaultValue, inputPlaceholder: placeholder, inputType });
}

function chartEmptyState(text = 'No Data Available') {
    const wrap = document.createElement('div');
    wrap.className = 'chart-empty-state';
    const icon = document.createElement('span');
    icon.className = 'material-icons';
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = 'database';

    const messageEl = document.createElement('span');
    messageEl.className = 'chart-empty-state-text';
    messageEl.textContent = text;

    wrap.append(icon, messageEl);
    return wrap;
}

window.addEventListener('pagehide', () => {
    if (typeof _wbModalPendingFinish === 'function') {
        _wbModalPendingFinish();
    }
    if (_wbModalPendingAbort) {
        _wbModalPendingAbort.abort();
        _wbModalPendingAbort = null;
    }
    _wbModalPendingFinish = null;
});
