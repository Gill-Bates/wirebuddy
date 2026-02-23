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

function _showModal({ title, message, type, showCancel, showInput, inputDefault, inputPlaceholder, inputType }) {
    if (window._wbReconnectState && window._wbReconnectState.active) {
        if (showInput) return Promise.resolve(null);
        if (showCancel) return Promise.resolve(false);
        return Promise.resolve(true);
    }
    return new Promise(resolve => {
        // Close non-form modals to prevent stacking, but preserve form modals
        document.querySelectorAll('.modal.show').forEach(modal => {
            const bsModal = bootstrap.Modal.getInstance(modal);
            if (bsModal && modal.id !== 'wbModal' && !modal.querySelector('form')) {
                bsModal.hide();
            }
        });

        const cfg = _wbIcons[type] || _wbIcons.info;
        document.getElementById('wbModalTitle').textContent = title;
        document.getElementById('wbModalMessage').textContent = message;
        const iconEl = document.getElementById('wbModalIcon');
        iconEl.textContent = cfg.icon;
        iconEl.style.color = cfg.color;

        const cancelBtn = document.getElementById('wbModalCancel');
        cancelBtn.classList.toggle('d-none', !showCancel);

        const inputWrap = document.getElementById('wbModalInputWrap');
        const inputEl = document.getElementById('wbModalInput');
        inputWrap.classList.toggle('d-none', !showInput);
        if (showInput) {
            inputEl.value = inputDefault || '';
            inputEl.placeholder = inputPlaceholder || '';
            inputEl.type = inputType || 'text';
        }

        const okBtn = document.getElementById('wbModalOk');
        okBtn.className = 'btn ' + (type === 'danger' ? 'btn-danger' : 'btn-primary');
        okBtn.textContent = showCancel || showInput ? 'Confirm' : 'OK';

        let settled = false;
        function finish(val) {
            if (settled) return;
            settled = true;
            const modalEl = document.getElementById('wbModal');

            if (!modalEl.classList.contains('show')) {
                resolve(val);
                return;
            }

            const fallback = setTimeout(() => resolve(val), 500);
            modalEl.addEventListener('hidden.bs.modal', () => {
                clearTimeout(fallback);
                resolve(val);
            }, { once: true });
            window._wbModal.hide();
        }

        okBtn.onclick = () => {
            if (showInput) finish(inputEl.value);
            else finish(true);
        };

        cancelBtn.onclick = () => finish(showInput ? null : false);
        const closeBtn = document.getElementById('wbModalClose');
        if (closeBtn) closeBtn.onclick = () => finish(showInput ? null : !showCancel);

        if (showInput) {
            inputEl.onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); okBtn.click(); } };
        }

        window._wbModal.show();
        if (showInput) setTimeout(() => inputEl.focus(), 300);
    });
}

function wbAlert(message, type = 'info') {
    const titles = { info: 'Info', success: 'Success', warning: 'Warning', danger: 'Error' };
    return _showModal({ title: titles[type] || 'Info', message, type, showCancel: false, showInput: false });
}

function wbConfirm(message, type = 'confirm') {
    return _showModal({ title: 'Confirm', message, type, showCancel: true, showInput: false });
}

function wbPrompt(message, { defaultValue = '', placeholder = '', inputType = 'text' } = {}) {
    return _showModal({ title: 'Input', message, type: 'prompt', showCancel: true, showInput: true, inputDefault: defaultValue, inputPlaceholder: placeholder, inputType });
}

function chartEmptyState() {
    const wrap = document.createElement('div');
    wrap.className = 'chart-empty-state';
    wrap.innerHTML = '<span class="material-icons">database</span><span class="chart-empty-state-text">No Data Available</span>';
    return wrap;
}
