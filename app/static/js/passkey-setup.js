//
// app/static/js/passkey-setup.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

(async () => {
    'use strict';

    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
    let registering = false;

    // Friendly error messages (prevent server internals from leaking)
    const FRIENDLY_ERRORS = {
        NotAllowedError: 'Registration was cancelled or timed out. Please try again.',
        InvalidStateError: 'A passkey already exists on this device for this account.',
        SecurityError: 'Security check failed. Ensure you are using HTTPS.',
        NotSupportedError: 'Your device does not support this type of passkey.',
        AbortError: 'Registration timed out. Please try again.',
    };

    // ============================================================================
    // API Helper
    // ============================================================================

    async function api(method, url, body = null) {
        const opts = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken,
            },
            credentials: 'same-origin',
        };
        if (body) opts.body = JSON.stringify(body);
        const resp = await fetch(url, opts);
        let json;
        try {
            json = await resp.json();
        } catch {
            throw new Error('Server error. Please try again.');
        }
        if (!resp.ok) {
            const detail = json?.detail || 'Request failed';
            // Only pass through safe error messages
            const safeDetail = typeof detail === 'string' && detail.length < 200
                ? detail
                : 'Request failed. Please try again.';
            throw new Error(safeDetail);
        }
        return json.data;
    }

    // ============================================================================
    // UI Helpers
    // ============================================================================

    function showError(msg) {
        const el = document.getElementById('error-alert');
        el.textContent = msg;
        el.style.display = 'block';
    }

    function hideError() {
        const el = document.getElementById('error-alert');
        if (el) el.style.display = 'none';
    }

    // ============================================================================
    // Base64URL Encoding/Decoding (Fixed for Large Buffers)
    // ============================================================================

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

    // ============================================================================
    // Snake-case to Camel-case Converter
    // ============================================================================

    function snakeToCamel(obj) {
        if (Array.isArray(obj)) {
            return obj.map(snakeToCamel);
        }
        if (obj !== null && typeof obj === 'object') {
            return Object.fromEntries(
                Object.entries(obj).map(([k, v]) => [
                    k.replace(/_([a-z0-9])/gi, (_, c) => c.toUpperCase()),
                    snakeToCamel(v),
                ])
            );
        }
        return obj;
    }

    // ============================================================================
    // WebAuthn Options Preparation
    // ============================================================================

    function buildAuthenticatorSelection(sel) {
        if (!sel) {
            return {
                residentKey: 'preferred',
                userVerification: 'preferred'
            };
        }

        return {
            residentKey: sel.residentKey || 'preferred',
            userVerification: sel.userVerification || 'preferred',
            ...(sel.authenticatorAttachment && { authenticatorAttachment: sel.authenticatorAttachment }),
        };
    }

    function prepareRegistrationOptions(serverOptions) {
        // Convert snake_case to camelCase for all server data
        const s = snakeToCamel(serverOptions);

        const options = {
            challenge: base64UrlToArrayBuffer(s.challenge),
            rp: {
                name: s.rp.name,
                id: s.rp.id,
            },
            user: {
                id: base64UrlToArrayBuffer(s.user.id),
                name: s.user.name,
                displayName: s.user.displayName || s.user.name,
            },
            pubKeyCredParams: (s.pubKeyCredParams || []).map(p => ({
                type: p.type,
                alg: p.alg,
            })),
            timeout: s.timeout || 60000,
            authenticatorSelection: buildAuthenticatorSelection(s.authenticatorSelection),
        };

        // Handle excludeCredentials if present
        if (s.excludeCredentials && s.excludeCredentials.length > 0) {
            options.excludeCredentials = s.excludeCredentials.map(cred => ({
                type: 'public-key',
                id: base64UrlToArrayBuffer(cred.id),
                transports: cred.transports || undefined,
            }));
        }

        return options;
    }

    function credentialToJSON(credential) {
        const response = {
            id: credential.id,
            rawId: arrayBufferToBase64Url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: arrayBufferToBase64Url(credential.response.clientDataJSON),
                attestationObject: arrayBufferToBase64Url(credential.response.attestationObject),
            },
        };

        // Include transports if available
        if (credential.response.getTransports) {
            response.response.transports = credential.response.getTransports();
        }

        return response;
    }

    // ============================================================================
    // Input Sanitization
    // ============================================================================

    function sanitizeDeviceName(name) {
        if (!name) return null;

        // Remove control characters, zero-width characters, excessive whitespace
        const cleaned = name
            .replace(/[\x00-\x1F\x7F-\x9F\u200B-\u200D\uFEFF]/g, '')
            .replace(/\s+/g, ' ')
            .trim()
            .substring(0, 100);

        return cleaned || null;
    }

    // ============================================================================
    // WebAuthn Capability Detection
    // ============================================================================

    function checkWebAuthnSupport() {
        return Boolean(
            window.PublicKeyCredential &&
            typeof window.PublicKeyCredential === 'function'
        );
    }

    // ============================================================================
    // Passkey Registration
    // ============================================================================

    async function registerPasskey() {
        if (registering) return;
        registering = true;
        hideError();

        const btn = document.getElementById('register-btn');
        const btnText = document.getElementById('register-btn-text');
        const originalText = btnText.textContent;

        btn.disabled = true;
        btn.setAttribute('aria-busy', 'true');
        btnText.innerHTML =
            '<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span>' +
            '<span>Registering…</span>';

        // AbortController for timeout
        const abortController = new AbortController();
        const timeoutId = setTimeout(() => {
            abortController.abort();
        }, 120000); // 2 minute timeout

        try {
            // 1. Get registration options from server
            const serverOptions = await api('POST', '/api/passkeys/register/start');
            const challenge = serverOptions.challenge;  // Save for finish request
            const publicKeyOptions = prepareRegistrationOptions(serverOptions);

            // 2. Create credential with browser (with timeout)
            const credential = await navigator.credentials.create({
                publicKey: publicKeyOptions,
                signal: abortController.signal,
            });

            if (!credential) {
                throw new Error('Passkey registration was cancelled');
            }

            // 3. Send credential to server
            const deviceName = sanitizeDeviceName(
                document.getElementById('device-name')?.value
            );
            const credentialJSON = credentialToJSON(credential);

            await api('POST', '/api/passkeys/register/finish', {
                credential: credentialJSON,
                device_name: deviceName,
                challenge: challenge,
            });

            // 4. Success - show success state
            document.getElementById('step-setup').style.display = 'none';
            document.getElementById('step-success').style.display = 'block';

        } catch (error) {
            // Use friendly error messages
            const friendlyMsg = FRIENDLY_ERRORS[error.name] ||
                (error.message && error.message.length < 200
                    ? error.message
                    : 'Failed to register passkey. Please try again.');
            showError(friendlyMsg);
        } finally {
            clearTimeout(timeoutId);
            registering = false;
            btn.disabled = false;
            btn.removeAttribute('aria-busy');
            btnText.textContent = originalText;
        }
    }

    // ============================================================================
    // Initialization
    // ============================================================================

    async function init() {
        const isSupported = checkWebAuthnSupport();

        if (!isSupported) {
            document.getElementById('step-setup').style.display = 'none';
            document.getElementById('step-unsupported').style.display = 'block';
            return;
        }

        const registerBtn = document.getElementById('register-btn');
        if (registerBtn) {
            registerBtn.addEventListener('click', registerPasskey);
        }

        // Get redirect URL from page data or use default
        const redirectUrl = document.body.dataset?.redirect || '/';

        const continueBtn = document.getElementById('continue-btn');
        if (continueBtn) {
            continueBtn.addEventListener('click', () => {
                window.location.href = redirectUrl;
            });
        }

        const skipBtn = document.getElementById('skip-btn');
        if (skipBtn) {
            skipBtn.addEventListener('click', () => {
                window.location.href = redirectUrl;
            });
        }

        // Focus device name input
        const deviceNameInput = document.getElementById('device-name');
        if (deviceNameInput) {
            deviceNameInput.focus();
        }
    }

    // Run init when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            init().catch(error => {
                console.error('Passkey setup initialization failed:', error);
                const el = document.getElementById('error-alert');
                if (el) {
                    el.textContent = 'Failed to initialize passkey setup. Please reload the page.';
                    el.style.display = 'block';
                }
            });
        });
    } else {
        await init();
    }
})().catch(error => {
    console.error('Passkey setup fatal error:', error);
    const el = document.getElementById('error-alert');
    if (el) {
        el.textContent = 'Failed to initialize passkey setup. Please reload the page.';
        el.style.display = 'block';
    }
});
