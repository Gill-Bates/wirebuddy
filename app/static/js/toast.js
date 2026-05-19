//
// app/static/js/toast.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

function wbToast(message, type = 'info', duration = 4000) {
    if (window.WBReconnect?.isActive?.()) return;
    if (!window.bootstrap?.Toast) {
        console.error('bootstrap.Toast not available - toast cannot be displayed:', message);
        return;
    }

    const toastType = type === 'error' ? 'danger' : type;
    const safeDuration = Number.isFinite(Number(duration))
        ? Math.max(1000, Number(duration))
        : 4000;
    const icons = { info: 'info', success: 'check_circle', warning: 'warning', danger: 'error' };
    const bgClasses = { info: 'text-bg-primary', success: 'text-bg-success', warning: 'text-bg-warning', danger: 'text-bg-danger' };
    const ariaLive = { info: 'polite', success: 'polite', warning: 'assertive', danger: 'assertive' };

    const container = document.getElementById('wbToastContainer');
    if (!container) {
        console.error('wbToastContainer not found - toast cannot be displayed:', message);
        return;
    }

    const existingToasts = container.querySelectorAll('.toast');
    const toastKey = `${toastType}:${message}`;

    for (const toastNode of existingToasts) {
        if (toastNode.dataset.wbToastKey === toastKey) {
            try {
                const bsToast = window.bootstrap.Toast.getInstance(toastNode);
                if (bsToast) {
                    // Use hide() instead of dispose() — dispose() nullifies
                    // _element immediately, which crashes if Bootstrap's
                    // queued transition callback fires after disposal.
                    // The 'hidden.bs.toast' listener already calls remove().
                    bsToast.hide();
                } else {
                    // No active Bootstrap instance — safe to remove directly
                    toastNode.remove();
                }
            } catch (e) {
                toastNode.remove();
            }
        }
    }

    const MAX_TOASTS = 5;
    const toTrim = Math.max(0, container.children.length - (MAX_TOASTS - 1));
    const oldestToasts = Array.from(container.children).slice(0, toTrim);
    for (const oldestToast of oldestToasts) {
        try {
            const oldestInstance = window.bootstrap.Toast.getInstance(oldestToast);
            if (oldestInstance) {
                oldestInstance.hide();
            } else {
                oldestToast.remove();
            }
        } catch (e) {
            oldestToast.remove();
        }
    }

    const toastEl = document.createElement('div');
    toastEl.className = `toast align-items-center border-0 ${bgClasses[toastType] || bgClasses.info}`;
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', ariaLive[toastType] || 'polite');
    toastEl.setAttribute('aria-atomic', 'true');
    toastEl.dataset.wbToastKey = toastKey;

    // Create elements safely to prevent XSS
    const toastBody = document.createElement('div');
    toastBody.className = 'toast-body d-flex align-items-center gap-2';

    const iconSpan = document.createElement('span');
    iconSpan.className = 'material-icons';
    iconSpan.textContent = icons[toastType] || icons.info;

    const messageSpan = document.createElement('span');
    messageSpan.textContent = message;  // textContent is XSS-safe

    toastBody.appendChild(iconSpan);
    toastBody.appendChild(messageSpan);

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'btn-close btn-close-white me-2 m-auto';
    closeBtn.setAttribute('data-bs-dismiss', 'toast');
    closeBtn.setAttribute('aria-label', 'Close');

    const flexDiv = document.createElement('div');
    flexDiv.className = 'd-flex';
    flexDiv.appendChild(toastBody);
    flexDiv.appendChild(closeBtn);

    toastEl.appendChild(flexDiv);

    container.appendChild(toastEl);
    const toast = new window.bootstrap.Toast(toastEl, { delay: safeDuration });
    toast.show();

    toastEl.addEventListener('hidden.bs.toast', () => {
        window.bootstrap.Toast.getInstance(toastEl)?.dispose();
        toastEl.remove();
    }, { once: true });
}
