//
// app/static/js/passkeys.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

/**
 * WebAuthn / Passkey Authentication
 */

// Check if WebAuthn is supported (more robust check)
const isWebAuthnSupported = typeof window.PublicKeyCredential === 'function';

// AbortController for canceling pending conditional mediation requests
let conditionalAbortController = null;

// Base64URL encoding/decoding helpers
function base64UrlToArrayBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - base64.length % 4) % 4);
    let binary;
    try {
        binary = atob(base64 + padding);
    } catch (e) {
        throw new Error('Invalid data received from server. Please try again.');
    }
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function arrayBufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    const CHUNK_SIZE = 32768; // 32KB chunks to avoid call stack limits
    const parts = [];

    for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
        // Use subarray + apply to avoid stack overflow on large buffers
        parts.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK_SIZE)));
    }

    return btoa(parts.join(''))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

// Convert server options to WebAuthn format
function prepareAuthOptions(serverOptions) {
    if (!serverOptions?.challenge) {
        throw new Error('Invalid response from server');
    }
    if (!serverOptions?.rp_id) {
        throw new Error('Server did not provide RP ID');
    }

    const options = {
        challenge: base64UrlToArrayBuffer(serverOptions.challenge),
        rpId: serverOptions.rp_id,
        timeout: serverOptions.timeout || 60000,
        userVerification: serverOptions.user_verification || 'preferred',
    };

    if (serverOptions.allow_credentials && serverOptions.allow_credentials.length > 0) {
        options.allowCredentials = serverOptions.allow_credentials.map(cred => ({
            type: 'public-key',
            id: base64UrlToArrayBuffer(cred.id),
            transports: cred.transports || undefined,
        }));
    }

    return options;
}

// Convert credential response to JSON for server
function credentialToJSON(credential) {
    const response = credential.response;

    const serializedResponse = {
        clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
    };

    // Assertion response (login)
    if (response.authenticatorData && response.signature) {
        serializedResponse.authenticatorData = arrayBufferToBase64Url(response.authenticatorData);
        serializedResponse.signature = arrayBufferToBase64Url(response.signature);
        serializedResponse.userHandle = response.userHandle
            ? arrayBufferToBase64Url(response.userHandle)
            : null;
    }

    // Attestation response (registration) - included for compatibility
    if (response.attestationObject) {
        serializedResponse.attestationObject = arrayBufferToBase64Url(response.attestationObject);
        if (response.getTransports) {
            serializedResponse.transports = response.getTransports();
        }
    }

    return {
        id: credential.id,
        rawId: arrayBufferToBase64Url(credential.rawId),
        type: credential.type,
        response: serializedResponse,
    };
}

function getLoginStartPayload() {
    const username = document.getElementById('username')?.value?.trim();
    return username ? { username } : {};
}

async function executePasskeyLogin(options = {}) {
    const startData = await apiCall('/api/passkeys/login/start', getLoginStartPayload());
    const serverOptions = startData?.data;
    const publicKeyOptions = prepareAuthOptions(serverOptions);

    const credentialOptions = { publicKey: publicKeyOptions };
    if (options.mediation) credentialOptions.mediation = options.mediation;
    if (options.signal) credentialOptions.signal = options.signal;

    const credential = await navigator.credentials.get(credentialOptions);
    if (!credential) {
        throw new Error('Passkey authentication cancelled');
    }

    await apiCall('/api/passkeys/login/finish', { credential: credentialToJSON(credential) });
    window.location.href = '/ui/dashboard';
}

// Passkey login flow
async function startPasskeyLogin() {
    const passkeyBtn = document.getElementById('passkey-login-btn');
    if (!passkeyBtn) return;

    // Abort any pending conditional mediation request
    if (conditionalAbortController) {
        conditionalAbortController.abort();
        conditionalAbortController = null;
    }

    hideError();
    const originalHtml = passkeyBtn.innerHTML;
    passkeyBtn.disabled = true;
    passkeyBtn.innerHTML = '<span class="spinner-border spinner-border-sm align-middle me-2"></span>Authenticating...';

    try {
        await executePasskeyLogin();
    } catch (error) {
        // Handle user cancellation gracefully
        if (error.name === 'NotAllowedError') {
            return;
        }
        showError(error.message || 'Passkey authentication failed');
    } finally {
        passkeyBtn.disabled = false;
        passkeyBtn.innerHTML = originalHtml;
    }
}

// Conditional UI (autofill) passkey login
async function startConditionalPasskeyLogin() {
    const supported = typeof window.PublicKeyCredential?.isConditionalMediationAvailable === 'function';
    if (!supported) return;

    let available = false;
    try {
        available = await window.PublicKeyCredential.isConditionalMediationAvailable();
    } catch {
        return;
    }
    if (!available) return;

    try {
        conditionalAbortController = new AbortController();
        await executePasskeyLogin({
            mediation: 'conditional',
            signal: conditionalAbortController.signal,
        });

    } catch (error) {
        // Silent failure for conditional UI (including intentional abort)
        if (error.name !== 'AbortError' && error.name !== 'NotAllowedError') {
            console.debug('Conditional passkey login not available:', error.message);
        }
    } finally {
        conditionalAbortController = null;
    }
}

// Initialize passkey support
async function initPasskeys() {
    if (!isWebAuthnSupported) return;

    // Check if any passkeys are configured in the system
    let passkeyAvailable = false;
    try {
        const response = await fetch('/api/passkeys/available', {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
            },
        });
        if (response.ok) {
            const json = await response.json();
            passkeyAvailable = json?.data?.available === true;
        }
        if (!passkeyAvailable) {
            console.debug('No passkeys configured in system');
            return;
        }
    } catch (error) {
        console.debug('Error checking passkey availability:', error.message);
        return;
    }

    const passkeySection = document.getElementById('passkey-section');
    if (passkeySection) {
        passkeySection.classList.remove('hidden');
    }

    const passkeyBtn = document.getElementById('passkey-login-btn');
    if (passkeyBtn) {
        passkeyBtn.addEventListener('click', startPasskeyLogin);
    } else {
        console.error('Passkey login button not found in DOM');
    }

    // Try Conditional UI (autofill) for browsers that support it
    if (typeof window.PublicKeyCredential?.isConditionalMediationAvailable === 'function') {
        try {
            const available = await window.PublicKeyCredential.isConditionalMediationAvailable();
            if (available) {
                // Enable conditional UI by adding webauthn to autocomplete
                const usernameField = document.getElementById('username');
                if (usernameField) {
                    usernameField.setAttribute('autocomplete', 'username webauthn');
                }
                // Automatically start conditional passkey flow
                await startConditionalPasskeyLogin();
            }
        } catch (error) {
            console.debug('Conditional mediation check failed:', error.message);
        }
    }
}
