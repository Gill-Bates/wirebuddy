(function () {
    'use strict';

    const errorAlert = document.getElementById('error-alert');
    const form = document.getElementById('change-password-form');
    const newPasswordInput = document.getElementById('new-password');
    const confirmPasswordInput = document.getElementById('confirm-password');
    const submitBtn = document.getElementById('submit-btn');
    const strengthBar = document.getElementById('new-password-strength');
    const reqContainer = document.getElementById('new-password-req');

    if (!errorAlert || !form || !newPasswordInput || !confirmPasswordInput || !submitBtn || !reqContainer) {
        return;
    }

    function showError(msg) {
        errorAlert.textContent = msg;
        errorAlert.classList.remove('is-hidden');
        errorAlert.focus();
    }

    function hideError() {
        errorAlert.textContent = '';
        errorAlert.classList.add('is-hidden');
    }

    function validatePassword(password) {
        const checks = {
            length: password.length >= 8,
            upper: /[A-Z]/.test(password),
            lower: /[a-z]/.test(password),
            digit: /[0-9]/.test(password),
            special: /[^A-Za-z0-9]/.test(password),
        };
        checks.strength = [checks.upper, checks.lower, checks.digit, checks.special].filter(Boolean).length >= 3;
        return checks;
    }

    function getErrorMessage(json) {
        if (typeof json.detail === 'string') return json.detail;
        if (Array.isArray(json.detail)) {
            return json.detail.map(item => item.msg || item.message || String(item)).join(' ');
        }
        return 'Request failed';
    }

    newPasswordInput.addEventListener('input', function () {
        const password = this.value;
        const checks = validatePassword(password);

        reqContainer.querySelectorAll('.req').forEach(el => {
            const req = el.dataset.req;
            const icon = el.querySelector('.material-icons');
            if (!icon || !(req in checks)) return;
            if (checks[req]) {
                el.classList.add('valid');
                el.classList.remove('invalid');
                icon.textContent = 'check_circle';
            } else if (password.length > 0) {
                el.classList.remove('valid');
                el.classList.add('invalid');
                icon.textContent = 'cancel';
            } else {
                el.classList.remove('valid', 'invalid');
                icon.textContent = 'radio_button_unchecked';
            }
        });

        if (strengthBar) {
            const validCount = Object.values(checks).filter(Boolean).length;
            strengthBar.style.width = `${Math.min(100, (validCount / 6) * 100)}%`;
            strengthBar.classList.remove('bg-danger', 'bg-warning', 'bg-success');
            if (validCount <= 2) strengthBar.classList.add('bg-danger');
            else if (validCount <= 4) strengthBar.classList.add('bg-warning');
            else strengthBar.classList.add('bg-success');
        }
    });

    form.addEventListener('submit', async function (e) {
        e.preventDefault();
        hideError();

        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
        if (!csrfToken) {
            showError('Security token missing. Please reload the page.');
            return;
        }

        const newPassword = newPasswordInput.value;
        const confirmPassword = confirmPasswordInput.value;

        const checks = validatePassword(newPassword);
        if (!checks.length || !checks.strength) {
            showError('Password does not meet the requirements.');
            return;
        }

        if (newPassword !== confirmPassword) {
            showError('Passwords do not match.');
            return;
        }

        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm align-middle me-1" aria-label="Processing"></span> Saving...';

        const controller = new AbortController();
        const timeoutId = window.setTimeout(() => controller.abort(), 15000);

        try {
            const resp = await fetch('/api/users/me/complete-required-change', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                },
                credentials: 'same-origin',
                signal: controller.signal,
                body: JSON.stringify({
                    new_password: newPassword,
                }),
            });

            let json = {};
            try { json = await resp.json(); } catch { /* non-JSON body */ }

            if (!resp.ok) {
                throw new Error(getErrorMessage(json));
            }

            submitBtn.innerHTML = '<span class="material-icons align-middle me-1">check_circle</span> Password changed – redirecting...';

            const overlay = document.createElement('div');
            overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;display:flex;align-items:center;justify-content:center;color:white;font-size:1.1rem;';
            overlay.innerHTML = '<div style="text-align:center;"><div class="spinner-border mb-3"></div><div>Password changed. Redirecting to login...</div></div>';
            document.body.appendChild(overlay);

            window.setTimeout(() => { window.location.replace('/login'); }, 1500);

        } catch (err) {
            const message = err.name === 'AbortError'
                ? 'Request timed out. Please try again.'
                : err.message || 'Failed to change password. Please try again.';
            showError(message);
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<span class="material-icons align-middle me-1">check_circle</span> Set New Password';
        } finally {
            window.clearTimeout(timeoutId);
        }
    });
})();
