//
// app/static/js/login.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

/**
 * Login Page - Main Logic and Utilities
 */

(function () {
    'use strict';

// Cached DOM elements
let errorAlert;
let loginForm;
let submitBtn;
let usernameField;
let passwordField;
let loginCard;
let throttleTimer = null;
let _loginInProgress = false;

function parseRetryAfter(headerValue) {
    if (!headerValue) return null;

    const seconds = parseInt(headerValue, 10);
    if (Number.isFinite(seconds) && seconds > 0) {
        return seconds;
    }

    const date = new Date(headerValue);
    if (Number.isNaN(date.getTime())) {
        return null;
    }
    const diffSeconds = Math.ceil((date.getTime() - Date.now()) / 1000);
    return Math.max(1, diffSeconds);
}

function restartAnimationClass(el, className) {
    if (!el) return;
    el.classList.remove(className);
    void el.offsetWidth;
    el.classList.add(className);
}

function setLoginFailureFeedback(active) {
    if (passwordField) {
        if (active) {
            restartAnimationClass(passwordField, 'is-invalid');
        } else {
            passwordField.classList.remove('is-invalid');
        }
    }

    if (loginCard) {
        if (active) {
            restartAnimationClass(loginCard, 'login-card-shake');
        } else {
            loginCard.classList.remove('login-card-shake');
        }
    }
}

// Button state management (preserves HTML content)
function setBusy(buttonEl, busyText) {
    if (!buttonEl) {
        return;
    }

    if (!buttonEl.dataset.originalText) {
        buttonEl.dataset.originalText = buttonEl.textContent?.trim() || '';
    }

    buttonEl.disabled = true;
    const spinner = document.createElement('span');
    spinner.className = 'spinner-border spinner-border-sm align-middle me-2';
    spinner.setAttribute('aria-hidden', 'true');
    buttonEl.replaceChildren(spinner, document.createTextNode(busyText));
    buttonEl.setAttribute('aria-busy', 'true');
}

function clearBusy(buttonEl, idleText) {
    if (!buttonEl) {
        return;
    }

    buttonEl.disabled = false;
    buttonEl.textContent = buttonEl.dataset.originalText || idleText;
    buttonEl.removeAttribute('aria-busy');
}

// Error display
function showError(message) {
    if (!errorAlert) {
        console.error('Login error:', message);
        return;
    }
    errorAlert.textContent = message;
    errorAlert.classList.remove('d-none');

    // Set aria-invalid on form inputs
    if (usernameField) usernameField.setAttribute('aria-invalid', 'true');
    if (passwordField) passwordField.setAttribute('aria-invalid', 'true');

    // Focus the error alert for screen readers
    errorAlert.setAttribute('tabindex', '-1');
    errorAlert.focus();
}

function hideError() {
    if (!errorAlert) return;
    const wasFocused = document.activeElement === errorAlert;
    errorAlert.classList.add('d-none');

    // Remove aria-invalid from form inputs
    if (usernameField) usernameField.removeAttribute('aria-invalid');
    if (passwordField) passwordField.removeAttribute('aria-invalid');

    // Remove tabindex
    errorAlert.removeAttribute('tabindex');
    setLoginFailureFeedback(false);
    if (wasFocused && usernameField) {
        usernameField.focus();
    }
}

// Throttle countdown (rate limiting)
function startThrottleCountdown(seconds) {
    if (!submitBtn) return;

    // Clear any existing throttle timer
    if (throttleTimer) {
        clearInterval(throttleTimer);
        throttleTimer = null;
    }

    let remainingSeconds = Math.max(1, parseInt(seconds, 10) || 60);

    // Disable button and show countdown
    submitBtn.disabled = true;
    submitBtn.setAttribute('aria-busy', 'true');

    const updateCountdown = () => {
        if (remainingSeconds <= 0) {
            clearInterval(throttleTimer);
            throttleTimer = null;
            submitBtn.disabled = false;
            submitBtn.textContent = 'Sign In';
            submitBtn.removeAttribute('aria-busy');
            hideError();
            return;
        }

        submitBtn.textContent = `Retry in ${remainingSeconds}s`;
        remainingSeconds--;
    };

    // Initial update
    updateCountdown();

    // Update every second
    throttleTimer = setInterval(updateCountdown, 1000);
}

// Main login form handler
async function handleLogin(e) {
    e.preventDefault();

    if (_loginInProgress || throttleTimer) {
        return;
    }

    if (!usernameField || !passwordField || !submitBtn) {
        console.error('Login page: required DOM elements missing during submit');
        showError('Login form is incomplete. Please reload the page.');
        return;
    }

    const username = usernameField.value.trim();
    const password = passwordField.value;

    hideError();

    if (!username || !password) {
        showError('Please enter both username and password.');
        return;
    }

    _loginInProgress = true;
    let shouldResetBusy = true;

    setBusy(submitBtn, 'Signing in...');

    try {
        const data = await api('POST', '/api/login', { username, password }, {
            timeoutMs: 15000,
            skipAuthRedirect: true,
        });

        if (data?.data?.mfa_required) {
            if (typeof showMfaForm !== 'function') {
                console.error('Login page: MFA required but MFA UI is unavailable');
                showError('Multi-factor authentication is required but unavailable. Please reload the page.');
                return;
            }
            clearBusy(submitBtn, 'Sign In');
            shouldResetBusy = false;
            showMfaForm(username, data.data.mfa_token);
            return;
        }

        const nextUrl = data?.data?.otp_setup_pending ? '/ui/otp-setup'
            : data?.data?.passkey_setup_pending ? '/ui/passkey-setup'
                : '/ui/dashboard';
        shouldResetBusy = false;
        window.location.assign(nextUrl);

    } catch (error) {
        if (error?.code === 'TIMEOUT' || error?.code === 'ABORTED' || error?.name === 'AbortError') {
            return;
        }

        if (error.status === 429) {
            // Rate limit exceeded - start countdown
            const retryAfter = parseRetryAfter(error.retryAfter) || 60;
            showError(error?.message || 'Too many attempts. Please wait.');
            startThrottleCountdown(retryAfter);
            shouldResetBusy = false;
            return;
        }

        if (error.status === 401 && passwordField) {
            passwordField.value = '';
            passwordField.focus();
        }
        if (error.status === 401 && error.message === 'Invalid username or password') {
            setLoginFailureFeedback(true);
        }
        showError(error?.message || 'Request failed');
    } finally {
        if (shouldResetBusy) {
            clearBusy(submitBtn, 'Sign In');
        }
        _loginInProgress = false;
    }
}

// Theme toggle (moved from inline handler)
function initThemeToggle() {
    const themeToggleBtn = document.getElementById('theme-toggle-btn');
    if (themeToggleBtn && typeof toggleTheme === 'function') {
        themeToggleBtn.addEventListener('click', toggleTheme);
    } else if (themeToggleBtn) {
        console.warn('Login page: theme toggle unavailable');
    }
}

// Initialize login page
function initLoginPage() {
    // Cache DOM elements
    errorAlert = document.getElementById('error-alert');
    loginForm = document.getElementById('login-form');
    submitBtn = document.getElementById('submit-btn');
    usernameField = document.getElementById('username');
    passwordField = document.getElementById('password');
    loginCard = document.querySelector('.login-card');

    if (!loginForm || !submitBtn || !usernameField || !passwordField) {
        console.error('Login page: required DOM elements missing');
        return;
    }

    // Setup event listeners
    loginForm.addEventListener('submit', handleLogin);

    passwordField.addEventListener('input', () => setLoginFailureFeedback(false));

    // Initialize theme toggle
    initThemeToggle();

    // Initialize MFA
    if (typeof initMfa === 'function') {
        initMfa();
    }

    // Initialize passkeys
    if (typeof initPasskeys === 'function') {
        initPasskeys();
    }
}

// Run on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initLoginPage);
} else {
    initLoginPage();
}

})();
