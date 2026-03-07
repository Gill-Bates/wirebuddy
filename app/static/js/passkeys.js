//
// app/static/js/passkeys.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

/**
 * WebAuthn / Passkey Authentication
 */

// Check if WebAuthn is supported (more robust check)
const isWebAuthnSupported =
    window.PublicKeyCredential &&
    typeof window.PublicKeyCredential === 'function';

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
    const CHUNK = 0x8000; // 32KB chunks (safe for all JS engines)
    const parts = [];

    for (let i = 0; i < bytes.length; i += CHUNK) {
        // Use subarray + apply to avoid stack overflow on large buffers
        parts.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK)));
    }

    return btoa(parts.join(''))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

// Convert server options to WebAuthn format
function prepareAuthOptions(serverOptions) {
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
    return {
        id: credential.id,
        rawId: arrayBufferToBase64Url(credential.rawId),
        type: credential.type,
        response: {
            clientDataJSON: arrayBufferToBase64Url(credential.response.clientDataJSON),
            authenticatorData: arrayBufferToBase64Url(credential.response.authenticatorData),
            signature: arrayBufferToBase64Url(credential.response.signature),
            userHandle: credential.response.userHandle
                ? arrayBufferToBase64Url(credential.response.userHandle)
                : null,
        },
    };
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
    passkeyBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Authenticating...';

    try {
        // 1. Get authentication options from server
        const startData = await apiCall('/api/passkeys/login/start', {});
        const serverOptions = startData?.data;
        if (!serverOptions || !serverOptions.challenge) {
            throw new Error('Invalid response from server');
        }
        const publicKeyOptions = prepareAuthOptions(serverOptions);

        // 2. Get credentials from browser
        const credential = await navigator.credentials.get({
            publicKey: publicKeyOptions,
        });

        if (!credential) {
            throw new Error('Passkey authentication cancelled');
        }

        // 3. Send credential to server
        const credentialJSON = credentialToJSON(credential);
        await apiCall('/api/passkeys/login/finish', { credential: credentialJSON });

        // Success - redirect to dashboard
        window.location.href = '/ui/dashboard';

    } catch (error) {
        // Handle user cancellation gracefully
        if (error.name === 'NotAllowedError') {
            // User cancelled - just reset button
            passkeyBtn.disabled = false;
            passkeyBtn.innerHTML = originalHtml;
            return;
        }
        showError(error.message || 'Passkey authentication failed');
        passkeyBtn.disabled = false;
        passkeyBtn.innerHTML = originalHtml;
    }
}

// Conditional UI (autofill) passkey login
async function startConditionalPasskeyLogin() {
    try {
        const startData = await apiCall('/api/passkeys/login/start', {});
        const serverOptions = startData?.data;
        if (!serverOptions || !serverOptions.challenge) {
            console.debug('Invalid passkey options received');
            return;
        }
        const publicKeyOptions = prepareAuthOptions(serverOptions);

        // Create AbortController for this conditional request
        conditionalAbortController = new AbortController();

        // Use conditional mediation with abort signal
        const credential = await navigator.credentials.get({
            publicKey: publicKeyOptions,
            mediation: 'conditional',
            signal: conditionalAbortController.signal,
        });

        conditionalAbortController = null;

        if (!credential) return;

        // Send credential to server
        const credentialJSON = credentialToJSON(credential);
        await apiCall('/api/passkeys/login/finish', { credential: credentialJSON });

        // Success - redirect
        window.location.href = '/ui/dashboard';

    } catch (error) {
        conditionalAbortController = null;
        // Silent failure for conditional UI (including intentional abort)
        if (error.name !== 'AbortError') {
            console.debug('Conditional passkey login not available:', error.message);
        }
    }
}

// Initialize passkey support
async function initPasskeys() {
    if (!isWebAuthnSupported) return;

    // Check if any passkeys are configured in the system
    let passkeyAvailable = false;
    try {
        const response = await fetch('/api/passkeys/available');
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
    if (window.PublicKeyCredential.isConditionalMediationAvailable) {
        PublicKeyCredential.isConditionalMediationAvailable().then(available => {
            if (available) {
                // Enable conditional UI by adding webauthn to autocomplete
                const usernameField = document.getElementById('username');
                if (usernameField) {
                    usernameField.setAttribute('autocomplete', 'username webauthn');
                }
                // Automatically start conditional passkey flow
                startConditionalPasskeyLogin();
            }
        });
    }
}
