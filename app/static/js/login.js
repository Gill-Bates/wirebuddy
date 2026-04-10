//
// app/static/js/login.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

/**
 * Login Page - Main Logic and Utilities
 */

// Cached DOM elements
let errorAlert;
let loginForm;
let submitBtn;
let usernameField;
let passwordField;
let loginCard;
const busyState = new WeakMap();
let throttleTimer = null;
let loginAbortController = null;
let _loginInProgress = false;

// Get CSRF token
function getCsrfToken() {
    const metaToken = document.querySelector('meta[name="csrf-token"]')?.content;
    const bodyToken = document.body?.dataset?.csrfToken;
    const token = metaToken || bodyToken;
    if (!token) {
        console.error('Login page: CSRF token not found');
    }
    return token || '';
}

// API call helper to reduce duplication
async function apiCall(url, body, opts = {}) {
    const timeoutMs = Number.isFinite(Number(opts?.timeoutMs)) ? Number(opts.timeoutMs) : 15000;
    const externalSignal = opts?.signal || null;
    const controller = new AbortController();
    let timeoutAbort = false;
    let timeoutId = null;
    let onExternalAbort = null;

    if (externalSignal?.aborted) {
        const error = new Error('Request cancelled');
        error.status = 0;
        error.name = 'AbortError';
        throw error;
    }
    if (externalSignal) {
        onExternalAbort = () => controller.abort();
        externalSignal.addEventListener('abort', onExternalAbort, { once: true });
    }
    if (timeoutMs > 0) {
        timeoutId = setTimeout(() => {
            timeoutAbort = true;
            controller.abort();
        }, timeoutMs);
    }

    let response;
    try {
        response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCsrfToken(),
            },
            body: JSON.stringify(body),
            credentials: 'same-origin',
            signal: controller.signal,
        });
    } catch (networkError) {
        if (networkError?.name === 'AbortError') {
            if (externalSignal?.aborted && !timeoutAbort) {
                const error = new Error('Request cancelled');
                error.status = 0;
                error.name = 'AbortError';
                throw error;
            }
            if (timeoutAbort) {
                const error = new Error('Request timed out');
                error.status = 0;
                throw error;
            }
        }
        const error = new Error('Unable to reach the server');
        error.status = 0;
        throw error;
    } finally {
        if (timeoutId) clearTimeout(timeoutId);
        if (externalSignal && onExternalAbort) {
            externalSignal.removeEventListener('abort', onExternalAbort);
        }
    }

    let data = {};
    try {
        data = await response.json();
    } catch (jsonError) {
        const error = new Error('Invalid response from server');
        error.status = response.status;
        throw error;
    }

    if (!response.ok) {
        const error = new Error(data.detail || data.error || 'Request failed');
        error.status = response.status;
        error.retryAfter = response.headers.get('Retry-After');
        throw error;
    }

    return data;
}

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

function cloneChildNodes(node) {
    return Array.from(node.childNodes, (child) => child.cloneNode(true));
}

function restartAnimationClass(el, className) {
    if (!el) return;
    el.classList.remove(className);
    requestAnimationFrame(() => {
        requestAnimationFrame(() => {
            el.classList.add(className);
        });
    });
}

function triggerLoginFailureFeedback() {
    restartAnimationClass(passwordField, 'is-invalid');
    restartAnimationClass(loginCard, 'login-card-shake');
}

function clearLoginFailureFeedback() {
    if (passwordField) {
        passwordField.classList.remove('is-invalid');
    }

    if (loginCard) {
        loginCard.classList.remove('login-card-shake');
    }
}

// Button state management (preserves HTML content)
function setBusy(buttonEl, busyText) {
    if (!buttonEl) {
        return;
    }

    if (!busyState.has(buttonEl)) {
        busyState.set(buttonEl, {
            childNodes: cloneChildNodes(buttonEl),
            disabled: buttonEl.disabled,
        });
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

    const originalState = busyState.get(buttonEl);
    buttonEl.disabled = originalState?.disabled ?? false;
    if (originalState?.childNodes?.length) {
        // Clone again because replaceChildren moves nodes out of the stored snapshot.
        buttonEl.replaceChildren(...originalState.childNodes.map((child) => child.cloneNode(true)));
        busyState.delete(buttonEl);
    } else {
        buttonEl.textContent = idleText;
    }
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
    clearLoginFailureFeedback();
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
    if (loginAbortController && !loginAbortController.signal.aborted) {
        loginAbortController.abort();
    }
    loginAbortController = new AbortController();
    let keepBusyReason = null;

    setBusy(submitBtn, 'Signing in...');

    try {
        const data = await apiCall('/api/login', { username, password }, {
            signal: loginAbortController.signal,
            timeoutMs: 15000,
        });

        if (data?.data?.mfa_required) {
            if (typeof showMfaForm !== 'function') {
                console.error('Login page: MFA required but MFA UI is unavailable');
                showError('Multi-factor authentication is required but unavailable. Please reload the page.');
                return;
            }
            clearBusy(submitBtn, 'Sign In');
            showMfaForm(username, data.data.mfa_token);
            return;
        }

        // OTP setup data is fetched server-side on the next page.
        if (data?.data?.otp_setup_pending) {
            keepBusyReason = 'redirect';
            window.location.href = '/ui/otp-setup';
            return;
        }

        // Check if passkey setup is pending (admin enabled but user hasn't registered)
        if (data?.data?.passkey_setup_pending) {
            keepBusyReason = 'redirect';
            window.location.href = '/ui/passkey-setup';
            return;
        }

        // Auth cookie is set by the server (HttpOnly, Secure, SameSite=Strict).
        // No client-side token storage needed.
        keepBusyReason = 'redirect';
        window.location.href = '/ui/dashboard';

    } catch (error) {
        if (error?.name === 'AbortError') {
            return;
        }

        if (error.status === 429) {
            // Rate limit exceeded - start countdown
            const retryAfter = parseRetryAfter(error.retryAfter) || 60;
            showError(error?.message || 'Too many attempts. Please wait.');
            startThrottleCountdown(retryAfter);
            keepBusyReason = 'throttle';
            return;
        }

        if (error.status === 401 && passwordField) {
            passwordField.value = '';
            passwordField.focus();
        }
        if (error.status === 401 && error.message === 'Invalid username or password') {
            triggerLoginFailureFeedback();
        }
        showError(error?.message || 'Request failed');
    } finally {
        loginAbortController = null;
        if (keepBusyReason === 'throttle') {
            _loginInProgress = false;
            return;
        }
        if (keepBusyReason === 'redirect') {
            setTimeout(() => {
                if (_loginInProgress && !throttleTimer) {
                    _loginInProgress = false;
                    clearBusy(submitBtn, 'Sign In');
                }
            }, 3000);
            return;
        }
        clearBusy(submitBtn, 'Sign In');
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

    passwordField.addEventListener('input', clearLoginFailureFeedback);

    // Cleanup throttle timer on page unload
    window.addEventListener('beforeunload', () => {
        if (loginAbortController && !loginAbortController.signal.aborted) {
            loginAbortController.abort();
        }
        if (throttleTimer) {
            clearInterval(throttleTimer);
            throttleTimer = null;
        }
    });

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
