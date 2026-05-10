//
// app/static/js/modal.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

window._wbModal = null;

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
let _activeModalController = null;

function _getModalEl() {
    return document.getElementById('wbModal');
}

function _getModalInstance() {
    const el = _getModalEl();
    if (!el || typeof bootstrap === 'undefined' || !bootstrap?.Modal) {
        window._wbModal = null;
        return null;
    }

    const current = window._wbModal;
    if (current?._element === el) {
        return current;
    }

    if (current?.dispose) {
        try {
            current.dispose();
        } catch (error) {
            console.warn('Modal: failed to dispose stale instance', error);
        }
    }

    window._wbModal = bootstrap.Modal.getOrCreateInstance
        ? bootstrap.Modal.getOrCreateInstance(el)
        : new bootstrap.Modal(el);
    return window._wbModal;
}

function _clearModalPageState() {
    const modalEl = _getModalEl();
    document.querySelectorAll('.modal-backdrop').forEach(el => el.remove());
    document.body.classList.remove('modal-open');
    if (modalEl) {
        modalEl.classList.remove('show');
        modalEl.setAttribute('aria-hidden', 'true');
        modalEl.style.display = 'none';
    }
}

function _showModal({ title, message, type, showCancel, showInput, inputDefault, inputPlaceholder, inputType }) {
    const dismissValue = showInput ? null : (showCancel ? false : true);

    // Suppress modal UX interruptions while reconnect flow is active.
    if (window.WBReconnect?.isActive?.()) {
        return Promise.resolve(dismissValue);
    }

    const modalEl = _getModalEl();
    const modalInstance = _getModalInstance();
    if (!modalEl || !modalInstance) {
        console.error('Modal: #wbModal element or bootstrap instance missing');
        return Promise.resolve(dismissValue);
    }

    // Ensure previous modal promise settles before wiring a new modal lifecycle.
    if (_activeModalController) {
        _activeModalController.finish();
        _activeModalController.abort();
        _activeModalController = null;
    }

    return new Promise(resolve => {
        const controller = new AbortController();
        const signal = controller.signal;
        const modalControl = {
            finish: () => { },
            abort: () => controller.abort(),
        };
        _wbModalPendingAbort = controller;
        _activeModalController = modalControl;

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
            if (_activeModalController === modalControl) {
                _activeModalController = null;
            }
            controller.abort();
            resolve(val);
        }

        function finish(val = dismissValue) {
            if (settled) return;
            closeValue = val;
            if (!modalEl.classList.contains('show')) {
                safeResolve(closeValue);
                return;
            }
            fallbackTimer = setTimeout(() => safeResolve(closeValue), 500);
            modalInstance.hide();
        }

        modalControl.finish = finish;

        // Close non-form modals to prevent stacking, but preserve form modals
        document.querySelectorAll('.modal.show').forEach(modal => {
            if (typeof bootstrap === 'undefined' || !bootstrap?.Modal) return;
            const bsModal = bootstrap.Modal.getInstance(modal);
            if (bsModal && modal.id !== 'wbModal' && !modal.querySelector('form')) {
                bsModal.hide();
            }
        });

        const cfg = _wbIcons[type] || _wbIcons.info;
        const titleEl = modalEl.querySelector('#wbModalTitle');
        const messageEl = modalEl.querySelector('#wbModalMessage');
        const iconEl = modalEl.querySelector('#wbModalIcon');
        const cancelBtn = modalEl.querySelector('#wbModalCancel');
        const inputWrap = modalEl.querySelector('#wbModalInputWrap');
        const inputEl = modalEl.querySelector('#wbModalInput');
        const okBtn = modalEl.querySelector('#wbModalOk');
        const closeBtn = modalEl.querySelector('#wbModalClose');

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
            if (showInput) finish(inputEl.value.trim());
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
            modalEl.addEventListener('shown.bs.modal', () => {
                inputEl.focus();
                inputEl.select();
            }, { once: true, signal });
        }

        // Catches all hide completions: finish(), ESC, backdrop click, or external hide().
        modalEl.addEventListener('hidden.bs.modal', () => {
            safeResolve(closeValue);
        }, { once: true, signal });

        modalInstance.show();
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
    wrap.setAttribute('role', 'status');
    wrap.setAttribute('aria-live', 'polite');
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
    _clearModalPageState();
    if (_wbModalPendingAbort) {
        _wbModalPendingAbort.abort();
        _wbModalPendingAbort = null;
    }
    _wbModalPendingFinish = null;
    _activeModalController = null;
});
