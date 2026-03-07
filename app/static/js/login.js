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

// Get CSRF token
function getCsrfToken() {
    return document.body.dataset.csrfToken;
}

// API call helper to reduce duplication
async function apiCall(url, body) {
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCsrfToken(),
        },
        body: JSON.stringify(body),
        credentials: 'same-origin',
    });

    let data = {};
    try {
        data = await response.json();
    } catch (jsonError) {
        throw new Error('Invalid response from server');
    }

    if (!response.ok) {
        throw new Error(data.detail || 'Request failed');
    }

    return data;
}

// Button state management (preserves HTML content)
function setBusy(buttonEl, busyText) {
    if (!buttonEl.dataset.originalHtml) {
        buttonEl.dataset.originalHtml = buttonEl.innerHTML;
    }
    buttonEl.disabled = true;
    buttonEl.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>${busyText}`;
    buttonEl.setAttribute('aria-busy', 'true');
}

function clearBusy(buttonEl, idleText) {
    buttonEl.disabled = false;
    if (buttonEl.dataset.originalHtml) {
        buttonEl.innerHTML = buttonEl.dataset.originalHtml;
        delete buttonEl.dataset.originalHtml;
    } else {
        buttonEl.textContent = idleText;
    }
    buttonEl.removeAttribute('aria-busy');
}

// Error display
function showError(message) {
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
    errorAlert.classList.add('d-none');

    // Remove aria-invalid from form inputs
    if (usernameField) usernameField.removeAttribute('aria-invalid');
    if (passwordField) passwordField.removeAttribute('aria-invalid');

    // Remove tabindex
    errorAlert.removeAttribute('tabindex');
}

// Main login form handler
async function handleLogin(e) {
    e.preventDefault();

    const username = usernameField.value;
    const password = passwordField.value;

    hideError();
    setBusy(submitBtn, 'Signing in...');

    try {
        const data = await apiCall('/api/login', { username, password });

        if (data?.data?.mfa_required) {
            showMfaForm(username, data.data.mfa_token);
            return;
        }

        // Check if OTP setup is pending (secret set but not confirmed)
        if (data?.data?.otp_setup_pending) {
            sessionStorage.setItem('otp_setup_pending', 'true');
            sessionStorage.setItem('otp_setup_secret', data.data.otp_secret || '');
            sessionStorage.setItem('otp_setup_uri', data.data.provisioning_uri || '');
            sessionStorage.setItem('otp_setup_qr', data.data.qr_code_data_url || '');
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
        showError(error.message);
    } finally {
        clearBusy(submitBtn, 'Sign In');
    }
}

// Theme toggle (moved from inline handler)
function initThemeToggle() {
    const themeToggleBtn = document.getElementById('theme-toggle-btn');
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', toggleTheme);
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

    // Setup event listeners
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    // Initialize theme toggle
    initThemeToggle();

    // Initialize MFA
    initMfa();

    // Initialize passkeys
    initPasskeys();
}

// Run on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initLoginPage);
} else {
    initLoginPage();
}
