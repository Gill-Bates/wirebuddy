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

// Get CSRF token
function getCsrfToken() {
    const token = document.body?.dataset?.csrfToken;
    if (!token) {
        console.error('Login page: CSRF token not found on document body');
    }
    return token || '';
}

// API call helper to reduce duplication
async function apiCall(url, body) {
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
        });
    } catch (networkError) {
        const error = new Error('Unable to reach the server');
        error.status = 0;
        throw error;
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

function cloneChildNodes(node) {
    return Array.from(node.childNodes, (child) => child.cloneNode(true));
}

function triggerLoginFailureFeedback() {
    if (passwordField) {
        passwordField.classList.remove('is-invalid');
        void passwordField.offsetWidth;
        passwordField.classList.add('is-invalid');
    }

    if (loginCard) {
        loginCard.classList.remove('login-card-shake');
        void loginCard.offsetWidth;
        loginCard.classList.add('login-card-shake');
    }
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
    errorAlert.classList.add('d-none');

    // Remove aria-invalid from form inputs
    if (usernameField) usernameField.removeAttribute('aria-invalid');
    if (passwordField) passwordField.removeAttribute('aria-invalid');

    // Remove tabindex
    errorAlert.removeAttribute('tabindex');
    clearLoginFailureFeedback();
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

    setBusy(submitBtn, 'Signing in...');

    try {
        const data = await apiCall('/api/login', { username, password });

        if (data?.data?.mfa_required) {
            if (typeof showMfaForm !== 'function') {
                throw new Error('MFA UI is unavailable');
            }
            showMfaForm(username, data.data.mfa_token);
            return;
        }

        // OTP setup data is fetched server-side on the next page.
        if (data?.data?.otp_setup_pending) {
            window.location.href = '/ui/otp-setup';
            return;
        }

        // Check if passkey setup is pending (admin enabled but user hasn't registered)
        if (data?.data?.passkey_setup_pending) {
            window.location.href = '/ui/passkey-setup';
            return;
        }

        // Auth cookie is set by the server (HttpOnly, Secure, SameSite=Strict).
        // No client-side token storage needed.
        window.location.href = '/ui/dashboard';

    } catch (error) {
        if (error.status === 429) {
            // Rate limit exceeded - start countdown
            const retryAfter = error.retryAfter || 60;
            showError(error?.message || 'Too many attempts. Please wait.');
            startThrottleCountdown(retryAfter);
            return; // Don't clear busy state - button stays disabled
        }

        if (error.status === 401 && error.message === 'Invalid username or password') {
            triggerLoginFailureFeedback();
        }
        showError(error?.message || 'Request failed');
    } finally {
        clearBusy(submitBtn, 'Sign In');
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
