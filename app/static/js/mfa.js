//
// app/static/js/mfa.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

/**
 * MFA / OTP Handling
 */

let mfaUsername = '';
let mfaToken = '';
let mfaInitialized = false;
let mfaSubmitting = false;
let errorClearTimeoutId = null;

// Cached DOM elements
let mfaSubmitBtn;
let otpDigits;
let recoveryForm;
let mfaHeader;
let otpDigitsContainer;
let recoveryCodeInput;

function clearPendingOtpReset() {
    if (errorClearTimeoutId !== null) {
        clearTimeout(errorClearTimeoutId);
        errorClearTimeoutId = null;
    }
}

function clearOtpErrorState() {
    if (!otpDigits?.length) return;
    otpDigits.forEach((digit) => {
        digit.classList.remove('otp-error');
        digit.removeAttribute('aria-invalid');
    });
}

function updateSubmitState() {
    if (!mfaSubmitBtn) return;
    mfaSubmitBtn.disabled = mfaSubmitting || getOtpCode().length !== 6;
}

// Initialize MFA form
function initMfa() {
    if (mfaInitialized) {
        return;
    }
    mfaInitialized = true;

    // Cache DOM elements
    mfaSubmitBtn = document.getElementById('mfa-submit-btn');
    otpDigitsContainer = document.getElementById('otp-digits');
    recoveryForm = document.getElementById('recovery-form');
    mfaHeader = document.getElementById('mfa-header');
    recoveryCodeInput = document.getElementById('recovery-code');

    // Setup recovery code flow
    const useRecoveryBtn = document.getElementById('use-recovery-btn');
    if (useRecoveryBtn) {
        useRecoveryBtn.addEventListener('click', (e) => {
            e.preventDefault();
            showRecoveryForm();
        });
    }

    const recoverySubmitBtn = document.getElementById('recovery-submit-btn');
    if (recoverySubmitBtn) {
        recoverySubmitBtn.addEventListener('click', (e) => {
            e.preventDefault();
            void submitRecoveryCode();
        });
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
        mfaSubmitBtn.addEventListener('click', (e) => {
            e.preventDefault();
            void submitMfa(getOtpCode());
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

    mfaSubmitting = false;
    clearPendingOtpReset();
    hideError();

    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('mfa-form').classList.remove('hidden');
    mfaHeader?.classList.remove('hidden');
    otpDigitsContainer?.classList.remove('d-none');
    mfaSubmitBtn?.classList.remove('hidden');
    document.getElementById('use-recovery-btn')?.classList.remove('hidden');
    recoveryForm?.classList.add('hidden');
    if (recoveryCodeInput) {
        recoveryCodeInput.value = '';
        recoveryCodeInput.removeAttribute('aria-invalid');
    }
    initOtpDigits();
    clearOtpDigits();
}

// OTP digit boxes with auto-advance and auto-submit
function initOtpDigits() {
    otpDigits = document.querySelectorAll('.otp-digit');

    if (!otpDigits.length) {
        return;
    }

    otpDigits.forEach((input, idx) => {
        // Add accessibility labels
        input.setAttribute('aria-label', `Digit ${idx + 1} of 6`);
        input.setAttribute('inputmode', 'numeric');
        input.setAttribute('pattern', '[0-9]*');
        input.setAttribute('autocomplete', 'one-time-code');

        input.value = '';

        if (input.dataset.mfaBound === '1') {
            return;
        }
        input.dataset.mfaBound = '1';

        input.addEventListener('input', (e) => {
            clearPendingOtpReset();
            clearOtpErrorState();
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
            clearPendingOtpReset();
            clearOtpErrorState();
            const paste = e.clipboardData.getData('text').replace(/\D/g, '');
            for (let i = 0; i < Math.min(paste.length, otpDigits.length); i++) {
                otpDigits[i].value = paste[i];
            }
            const focusIdx = Math.min(paste.length, otpDigits.length - 1);
            otpDigits[focusIdx].focus();
            updateSubmitState();
            autoSubmitIfComplete();
        });

        input.addEventListener('focus', () => {
            clearPendingOtpReset();
            input.select();
        });
    });

    otpDigits[0].focus();

    function autoSubmitIfComplete() {
        const code = getOtpCode();
        if (code.length === 6 && !mfaSubmitting) {
            void submitMfa(code);
        }
    }

    updateSubmitState();
}

function getOtpCode() {
    return Array.from(otpDigits || []).map(d => d.value).join('');
}

function clearOtpDigits() {
    if (!otpDigits?.length) {
        return;
    }
    clearPendingOtpReset();
    clearOtpErrorState();
    otpDigits.forEach(d => d.value = '');
    otpDigits[0]?.focus();
    updateSubmitState();
}

async function submitMfa(code) {
    if (mfaSubmitting) {
        return;
    }

    clearPendingOtpReset();
    mfaSubmitting = true;
    hideError();
    updateSubmitState();
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
        if (otpDigits?.length) {
            otpDigits.forEach(d => {
                d.classList.add('otp-error');
                d.setAttribute('aria-invalid', 'true');
            });
        }

        // Show error message
        showError(error.message || 'Invalid code. Please try again.');

        errorClearTimeoutId = setTimeout(() => {
            clearOtpErrorState();
            if (otpDigits?.length) {
                otpDigits.forEach(d => {
                    d.value = '';
                });
                otpDigits[0]?.focus();
            }
            updateSubmitState();
            errorClearTimeoutId = null;
        }, 600);
    } finally {
        mfaSubmitting = false;
        clearBusy(mfaSubmitBtn, 'Verify');
        updateSubmitState();
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
