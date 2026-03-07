//
// app/static/js/mfa.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

/**
 * MFA / OTP Handling
 */

let mfaUsername = '';
let mfaToken = '';

// Cached DOM elements
let mfaSubmitBtn;
let otpDigits;
let recoveryForm;
let mfaHeader;
let otpDigitsContainer;
let recoveryCodeInput;

// Initialize MFA form
function initMfa() {
    // Cache DOM elements
    mfaSubmitBtn = document.getElementById('mfa-submit-btn');
    otpDigitsContainer = document.getElementById('otp-digits');
    recoveryForm = document.getElementById('recovery-form');
    mfaHeader = document.getElementById('mfa-header');
    recoveryCodeInput = document.getElementById('recovery-code');

    // Setup recovery code flow
    const useRecoveryBtn = document.getElementById('use-recovery-btn');
    if (useRecoveryBtn) {
        useRecoveryBtn.addEventListener('click', showRecoveryForm);
    }

    const recoverySubmitBtn = document.getElementById('recovery-submit-btn');
    if (recoverySubmitBtn) {
        recoverySubmitBtn.addEventListener('click', submitRecoveryCode);
    }

    if (recoveryCodeInput) {
        recoveryCodeInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                submitRecoveryCode();
            }
        });
    }

    if (mfaSubmitBtn) {
        mfaSubmitBtn.addEventListener('click', () => {
            submitMfa(getOtpCode());
        });
    }
}

// Show MFA form
function showMfaForm(username, token) {
    mfaUsername = username;
    mfaToken = String(token || '').trim();

    if (!mfaToken) {
        throw new Error('MFA challenge could not be initialized');
    }

    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('mfa-form').classList.remove('hidden');
    initOtpDigits();
}

// OTP digit boxes with auto-advance and auto-submit
function initOtpDigits() {
    otpDigits = document.querySelectorAll('.otp-digit');

    otpDigits.forEach((input, idx) => {
        // Add accessibility labels
        input.setAttribute('aria-label', `Digit ${idx + 1} of 6`);
        // Add autocomplete hint for iOS
        input.setAttribute('autocomplete', 'one-time-code');

        input.value = '';

        input.addEventListener('input', (e) => {
            const val = e.target.value.replace(/\D/g, '');
            e.target.value = val.slice(0, 1);

            if (val && idx < otpDigits.length - 1) {
                otpDigits[idx + 1].focus();
            }
            updateSubmitState();
            autoSubmitIfComplete();
        });

        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && !e.target.value && idx > 0) {
                otpDigits[idx - 1].focus();
            }
        });

        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const paste = (e.clipboardData || window.clipboardData).getData('text').replace(/\D/g, '');
            for (let i = 0; i < Math.min(paste.length, otpDigits.length); i++) {
                otpDigits[i].value = paste[i];
            }
            const focusIdx = Math.min(paste.length, otpDigits.length - 1);
            otpDigits[focusIdx].focus();
            updateSubmitState();
            autoSubmitIfComplete();
        });

        input.addEventListener('focus', () => input.select());
    });

    otpDigits[0].focus();

    function updateSubmitState() {
        const code = getOtpCode();
        mfaSubmitBtn.disabled = code.length !== 6;
    }

    function autoSubmitIfComplete() {
        const code = getOtpCode();
        if (code.length === 6) {
            submitMfa(code);
        }
    }
}

function getOtpCode() {
    return Array.from(otpDigits).map(d => d.value).join('');
}

function clearOtpDigits() {
    otpDigits.forEach(d => d.value = '');
    otpDigits[0]?.focus();
    mfaSubmitBtn.disabled = true;
}

async function submitMfa(code) {
    hideError();
    setBusy(mfaSubmitBtn, 'Verifying...');

    try {
        const result = await apiCall('/api/mfa/verify', {
            username: mfaUsername,
            mfa_token: mfaToken,
            code
        });

        // Check if passkey setup is pending after MFA
        if (result?.data?.passkey_setup_pending) {
            window.location.href = '/ui/passkey-setup';
            return;
        }

        window.location.href = '/ui/dashboard';
    } catch (error) {
        // Shake + red flash, then clear for re-entry
        otpDigits.forEach(d => {
            d.classList.add('otp-error');
            d.setAttribute('aria-invalid', 'true');
        });

        // Show error message
        showError(error.message || 'Invalid code. Please try again.');

        setTimeout(() => {
            otpDigits.forEach(d => {
                d.classList.remove('otp-error');
                d.removeAttribute('aria-invalid');
                d.value = '';
            });
            otpDigits[0]?.focus();
            mfaSubmitBtn.disabled = true;
        }, 600);
    } finally {
        clearBusy(mfaSubmitBtn, 'Verify');
    }
}

function showRecoveryForm() {
    mfaHeader.classList.add('hidden');
    otpDigitsContainer.classList.add('d-none');
    mfaSubmitBtn.classList.add('hidden');
    document.getElementById('use-recovery-btn').classList.add('hidden');
    recoveryForm.classList.remove('hidden');
    recoveryCodeInput.focus();
}

async function submitRecoveryCode() {
    const code = recoveryCodeInput.value.trim();
    if (!code) {
        showError('Please enter a recovery code');
        return;
    }
    await submitMfa(code);
}
