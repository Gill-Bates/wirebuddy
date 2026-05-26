//
// app/static/js/users.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

(function () {
    'use strict';

    // Helper to toggle d-none class
    function setHidden(el, hidden) {
        if (!el) return;
        el.classList.toggle('d-none', hidden);
    }

    const pageConfigEl = document.getElementById('wb-page-config');
    const pageConfig = pageConfigEl ? pageConfigEl.dataset : {};
    const CURRENT_USER_ID = Number.parseInt(pageConfig.currentUserId || '', 10);
    const IS_ADMIN = pageConfig.isAdmin === 'true';

    // Password strength validation
    function validatePassword(password) {
        const checks = {
            length: password.length >= 8,
            upper: /[A-Z]/.test(password),
            lower: /[a-z]/.test(password),
            digit: /[0-9]/.test(password),
            special: /[^A-Za-z0-9]/.test(password),
        };
        const categoryCount = [checks.upper, checks.lower, checks.digit, checks.special].filter(Boolean).length;
        checks.strength = categoryCount >= 3;
        return checks;
    }

    function updatePasswordIndicator(inputId, reqContainerId, strengthBarId) {
        const input = document.getElementById(inputId);
        const reqContainer = document.getElementById(reqContainerId);
        const strengthBar = document.getElementById(strengthBarId);
        if (!input || !reqContainer) return;

        input.addEventListener('input', function () {
            const password = this.value;
            const checks = validatePassword(password);

            // Update requirement indicators
            reqContainer.querySelectorAll('.req').forEach(el => {
                const req = el.dataset.req;
                const icon = el.querySelector('.material-icons');
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

            // Update strength bar
            if (strengthBar) {
                const validCount = Object.values(checks).filter(Boolean).length;
                const pct = Math.min(100, (validCount / 6) * 100);
                strengthBar.style.width = pct + '%';
                if (validCount <= 2) {
                    strengthBar.style.backgroundColor = 'var(--bs-danger)';
                } else if (validCount <= 4) {
                    strengthBar.style.backgroundColor = 'var(--bs-warning)';
                } else {
                    strengthBar.style.backgroundColor = 'var(--bs-success)';
                }
            }
        });
    }

    function initUserActionDropdowns(root = document) {
        if (typeof bootstrap === 'undefined' || !bootstrap.Dropdown) {
            return;
        }

        const scope = root && typeof root.querySelectorAll === 'function' ? root : document;
        for (const trigger of scope.querySelectorAll('.users-mobile-actions-toggle')) {
            if (trigger.dataset.dropdownInitialized === 'true') {
                continue;
            }

            trigger.dataset.dropdownInitialized = 'true';
            bootstrap.Dropdown.getOrCreateInstance(trigger, {
                popperConfig: {
                    strategy: 'fixed',
                    modifiers: [
                        { name: 'preventOverflow', options: { boundary: 'viewport' } },
                    ],
                },
            });
        }
    }

    function closeUserActionDropdowns(clickedInside = null) {
        if (typeof bootstrap === 'undefined' || !bootstrap.Dropdown) {
            return;
        }

        for (const trigger of document.querySelectorAll('.users-mobile-actions-toggle[aria-expanded="true"]')) {
            if (clickedInside && clickedInside.contains(trigger)) {
                continue;
            }

            const dropdown = bootstrap.Dropdown.getInstance(trigger);
            dropdown?.hide();
        }
    }

    // Initialize password validators
    updatePasswordIndicator('new-password', 'new-password-req', 'new-password-strength');
    updatePasswordIndicator('new-password-change', 'change-password-req', 'change-password-strength');
    initUserActionDropdowns();

    function resetPasswordIndicator(reqContainerId, strengthBarId) {
        const reqContainer = document.getElementById(reqContainerId);
        const strengthBar = document.getElementById(strengthBarId);
        if (reqContainer) {
            reqContainer.querySelectorAll('.req').forEach(el => {
                el.classList.remove('valid', 'invalid');
                el.querySelector('.material-icons').textContent = 'radio_button_unchecked';
            });
        }
        if (strengthBar) {
            strengthBar.style.width = '0%';
        }
    }

    // Reset add user modal when opened
    document.getElementById('addUserModal').addEventListener('show.bs.modal', function () {
        document.getElementById('add-user-form').reset();
        resetPasswordIndicator('new-password-req', 'new-password-strength');
    });

    // Add user form submission
    document.getElementById('add-user-form').addEventListener('submit', async function (e) {
        e.preventDefault();

        const submitBtn = this.querySelector('[type="submit"]');
        if (submitBtn.disabled) return;

        const password = document.getElementById('new-password').value;
        const checks = validatePassword(password);
        if (!checks.length || !checks.strength) {
            wbAlert('Password does not meet requirements', 'warning');
            return;
        }

        const data = {
            username: document.getElementById('new-username').value,
            password: password,
            is_admin: document.getElementById('new-is-admin').checked,
        };

        submitBtn.disabled = true;
        try {
            await api('POST', '/api/users', data);
            // Use generic success message instead of echoing user input
            window.location.href = window.location.pathname + '?action=created';
        } catch (error) {
            wbAlert('Failed to create user: ' + error.message, 'danger');
        } finally {
            submitBtn.disabled = false;
        }
    });

    // Edit user (change password)
    function editUser(userId, username) {
        const isSelf = userId === CURRENT_USER_ID;

        // Reset form first
        const form = document.getElementById('change-password-form');
        form.reset();
        resetPasswordIndicator('change-password-req', 'change-password-strength');

        // Set modal data attributes for state
        const modalEl = document.getElementById('changePasswordModal');
        modalEl.dataset.userId = userId;
        modalEl.dataset.isSelf = isSelf;

        // Set hidden username for accessibility
        const usernameField = document.getElementById('change-password-username');
        if (usernameField) usernameField.value = username || '';

        // Show/hide current password field
        const currentPwField = document.getElementById('current-password-field');
        const currentPwInput = document.getElementById('current-password');
        setHidden(currentPwField, !isSelf);
        currentPwInput.required = isSelf;

        // Show modal (reuse existing instance)
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();
    }

    // Change password form submission
    document.getElementById('change-password-form').addEventListener('submit', async function (e) {
        e.preventDefault();

        const submitBtn = this.querySelector('[type="submit"]');
        if (submitBtn.disabled) return;

        const modalEl = document.getElementById('changePasswordModal');
        const userId = parseInt(modalEl.dataset.userId, 10);
        const isSelf = modalEl.dataset.isSelf === 'true';

        const newPassword = document.getElementById('new-password-change').value;
        const verifyPassword = document.getElementById('verify-password').value;
        const currentPassword = document.getElementById('current-password').value;

        // Validate password strength
        const checks = validatePassword(newPassword);
        if (!checks.length || !checks.strength) {
            wbAlert('Password does not meet requirements', 'warning');
            return;
        }

        // Validate passwords match
        if (newPassword !== verifyPassword) {
            wbAlert('Passwords do not match', 'warning');
            return;
        }

        // Validate current password if changing own password
        if (isSelf && !currentPassword) {
            wbAlert('Current password is required', 'warning');
            return;
        }

        submitBtn.disabled = true;
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm align-middle me-1" aria-label="Processing"></span> Changing...';
        try {
            const data = { new_password: newPassword };
            if (isSelf) {
                data.current_password = currentPassword;
            }

            await api('POST', `/api/users/${userId}/change-password`, data);

            // Close modal
            const modal = bootstrap.Modal.getInstance(modalEl);
            if (modal) modal.hide();

            if (isSelf) {
                // Session invalidated - show overlay and redirect immediately
                const overlay = document.createElement('div');
                overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.8);z-index:9999;display:flex;align-items:center;justify-content:center;color:white;font-size:1.2rem;';
                overlay.innerHTML = '<div style="text-align:center;"><div class="spinner-border mb-3"></div><div>Password changed. Redirecting to login...</div></div>';
                document.body.appendChild(overlay);
                setTimeout(() => {
                    window.location.href = '/login';
                }, 1500);
            } else {
                wbToast('Password changed successfully', 'success');
            }
        } catch (error) {
            wbAlert('Failed to change password: ' + error.message, 'danger');
        } finally {
            if (!isSelf) {
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            }
        }
    });

    // Delete user
    async function deleteUser(userId, username) {
        if (!await wbConfirm(`Are you sure you want to delete user "${username}"?`, 'danger')) return;

        try {
            await api('DELETE', `/api/users/${userId}`);
            // Use generic success message instead of echoing user input
            window.location.href = window.location.pathname + '?action=deleted';
        } catch (error) {
            wbAlert('Failed to delete user: ' + error.message, 'danger');
        }
    }

    // Check for success messages from URL parameters (safe - no reflected content)
    (function () {
        const urlParams = new URLSearchParams(window.location.search);
        const action = urlParams.get('action');

        if (action === 'deleted') {
            wbToast('User deleted successfully', 'success');
            window.history.replaceState({}, '', window.location.pathname);
        } else if (action === 'created') {
            wbToast('User created successfully', 'success');
            window.history.replaceState({}, '', window.location.pathname);
        }
    })();

    // OTP Settings

    function setUserOtpState(userId, isEnabled, hasSecret) {
        const otpBtn = document.getElementById(`otp-settings-btn-${userId}`);
        if (otpBtn) {
            otpBtn.dataset.otpEnabled = isEnabled ? 'true' : 'false';
            otpBtn.dataset.otpSecret = hasSecret ? 'true' : 'false';
        }

        const indicator = document.getElementById(`otp-indicator-${userId}`);
        if (!indicator) return;

        indicator.classList.remove('text-success', 'text-warning', 'd-none');
        indicator.textContent = '';
        indicator.removeAttribute('title');

        if (isEnabled) {
            indicator.classList.add('text-success');
            indicator.title = 'OTP enabled';
            indicator.textContent = 'verified_user';
            return;
        }

        if (hasSecret) {
            indicator.classList.add('text-warning');
            indicator.title = 'OTP setup pending';
            indicator.textContent = 'schedule';
            return;
        }

        indicator.classList.add('d-none');
    }

    function openOtpSettings(userId, username, isEnabled, hasSecret) {
        isEnabled = !!isEnabled;
        hasSecret = !!hasSecret;

        // Store state in modal data attributes
        const modalEl = document.getElementById('otpSettingsModal');
        modalEl.dataset.userId = userId;
        modalEl.dataset.username = username;

        document.getElementById('otp-modal-username').textContent = username;
        const toggleBtn = document.getElementById('otp-toggle-btn');
        const toggleIcon = document.getElementById('otp-toggle-icon');
        const toggleLabel = document.getElementById('otp-toggle-label');
        const actionHelp = document.getElementById('otp-action-help');

        if (isEnabled) {
            document.getElementById('otp-status-text').textContent = 'Two-factor authentication is active';
            document.getElementById('otp-status-badge').innerHTML = '<span class="badge bg-success">Enabled</span>';
            actionHelp.textContent = 'Disable two-factor authentication for this user.';
            toggleBtn.className = 'btn btn-outline-danger w-100';
            toggleBtn.setAttribute('aria-pressed', 'true');
            toggleIcon.textContent = 'remove_moderator';
            toggleLabel.textContent = 'Disable OTP';
        } else if (hasSecret) {
            document.getElementById('otp-status-text').textContent = '';
            document.getElementById('otp-status-badge').innerHTML = '<span class="badge bg-warning text-dark">Pending</span>';
            actionHelp.textContent = 'OTP is pending. User onboarding starts at next login. You can disable OTP here.';
            toggleBtn.className = 'btn btn-outline-danger w-100';
            toggleBtn.setAttribute('aria-pressed', 'false');
            toggleIcon.textContent = 'remove_moderator';
            toggleLabel.textContent = 'Disable OTP';
        } else {
            document.getElementById('otp-status-text').textContent = 'Two-factor authentication is not enabled';
            document.getElementById('otp-status-badge').innerHTML = '<span class="badge bg-secondary">Disabled</span>';
            actionHelp.textContent = 'Enable two-factor authentication. User onboarding starts at next login.';
            toggleBtn.className = 'btn btn-primary w-100';
            toggleBtn.setAttribute('aria-pressed', 'false');
            toggleIcon.textContent = 'add_moderator';
            toggleLabel.textContent = 'Enable OTP';
        }

        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();
    }

    document.getElementById('otp-toggle-btn').addEventListener('click', async function () {
        if (this.disabled) return;

        const modalEl = document.getElementById('otpSettingsModal');
        const userId = parseInt(modalEl.dataset.userId, 10);
        const username = modalEl.dataset.username;

        const otpBtn = document.getElementById(`otp-settings-btn-${userId}`);
        const isEnabled = otpBtn?.dataset.otpEnabled === 'true';
        const hasSecret = otpBtn?.dataset.otpSecret === 'true';
        const shouldDisable = isEnabled || hasSecret;

        if (shouldDisable) {
            if (!await wbConfirm(`Disable two-factor authentication for "${username}"?`, 'warning')) return;

            this.disabled = true;
            try {
                await api('POST', `/api/users/${userId}/otp/disable`);
                setUserOtpState(userId, false, false);
                // Close modal and return to user overview
                const modal = bootstrap.Modal.getInstance(modalEl);
                if (modal) modal.hide();
                wbToast('OTP disabled', 'success');
            } catch (error) {
                wbAlert('Failed to disable OTP: ' + error.message, 'danger');
            } finally {
                this.disabled = false;
            }
            return;
        }

        this.disabled = true;
        try {
            await api('POST', `/api/users/${userId}/otp/enable`);
            setUserOtpState(userId, false, true);
            openOtpSettings(userId, username, false, true);
            wbToast('OTP enabled. User onboarding starts at next login.', 'success');
        } catch (error) {
            wbAlert('Failed to enable OTP: ' + error.message, 'danger');
        } finally {
            this.disabled = false;
        }
    });

    // Initialize tooltips on desktop only (touch devices don't benefit)
    if (window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
        document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
            if (el.dataset.tooltipInitialized) return;
            if (!el.isConnected || !el.getAttribute) return;
            const existingInstance = bootstrap.Tooltip.getInstance(el);
            if (existingInstance) {
                existingInstance.dispose();
            }
            try {
                new bootstrap.Tooltip(el, {
                    container: document.body,
                    trigger: 'hover focus',
                });
                el.dataset.tooltipInitialized = 'true';
            } catch (err) {
                console.error('Failed to initialize tooltip:', err, el);
            }
        });
    }

    // Event delegation for user action buttons
    const usersTable = document.querySelector('.users-table');
    if (usersTable) {
        usersTable.addEventListener('click', (e) => {
            const editBtn = e.target.closest('.btn-edit-user');
            if (editBtn) {
                e.preventDefault();
                editUser(
                    parseInt(editBtn.dataset.userId, 10),
                    editBtn.dataset.username
                );
                return;
            }

            const otpBtn = e.target.closest('.btn-otp-settings');
            if (otpBtn) {
                e.preventDefault();
                openOtpSettings(
                    parseInt(otpBtn.dataset.userId, 10),
                    otpBtn.dataset.username,
                    otpBtn.dataset.otpEnabled === 'true',
                    otpBtn.dataset.otpSecret === 'true'
                );
                return;
            }

            const deleteBtn = e.target.closest('.btn-delete-user');
            if (deleteBtn) {
                e.preventDefault();
                deleteUser(
                    parseInt(deleteBtn.dataset.userId, 10),
                    deleteBtn.dataset.username
                );
                return;
            }

            const passkeyBtn = e.target.closest('.btn-passkey-settings');
            if (passkeyBtn) {
                e.preventDefault();
                openPasskeySettings(
                    parseInt(passkeyBtn.dataset.userId, 10),
                    passkeyBtn.dataset.username
                );
                return;
            }
        });
    }

    document.addEventListener('click', (event) => {
        // Bootstrap handles toggling via data-bs-toggle="dropdown".
        // Keep explicit outside-close fallback for robustness.
        const clickedInsideDropdown = event.target.closest('.users-mobile-actions');
        if (!clickedInsideDropdown) {
            closeUserActionDropdowns();
        }
    });

    // ─── PASSKEY MANAGEMENT ───────────────────────────────────────────

    const isWebAuthnSupported = window.PublicKeyCredential !== undefined;

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

    function readDualCaseField(source, snakeKey, camelKey, defaultValue) {
        if (source[snakeKey] !== undefined) return source[snakeKey];
        if (source[camelKey] !== undefined) return source[camelKey];
        return defaultValue;
    }

    // Build authenticatorSelection with dual-case field support.
    function buildAuthenticatorSelection(serverAuthSel) {
        if (!serverAuthSel) {
            return {
                residentKey: 'preferred',
                userVerification: 'preferred'
            };
        }

        const result = {
            residentKey: readDualCaseField(serverAuthSel, 'resident_key', 'residentKey', 'preferred'),
            userVerification: readDualCaseField(serverAuthSel, 'user_verification', 'userVerification', 'preferred'),
        };

        const authenticatorAttachment = readDualCaseField(serverAuthSel, 'authenticator_attachment', 'authenticatorAttachment', undefined);
        if (authenticatorAttachment !== undefined) {
            result.authenticatorAttachment = authenticatorAttachment;
        }

        const requireResidentKey = readDualCaseField(serverAuthSel, 'require_resident_key', 'requireResidentKey', undefined);
        if (requireResidentKey !== undefined) {
            result.requireResidentKey = requireResidentKey;
        }

        return result;
    }

    // Sanitize device name input
    function sanitizeDeviceName(name) {
        if (!name || typeof name !== 'string') return '';

        // Remove control characters, zero-width spaces, direction marks
        const cleaned = name
            .replace(/[\x00-\x1F\x7F-\x9F]/g, '') // Control characters
            .replace(/[\u200B-\u200D\uFEFF]/g, '') // Zero-width spaces
            .replace(/[\u202A-\u202E]/g, '') // Direction marks
            .trim();

        return cleaned.slice(0, 100); // Enforce max length
    }

    // Friendly error messages for common WebAuthn errors
    const FRIENDLY_ERRORS = {
        'NotAllowedError': 'Passkey registration was cancelled',
        'InvalidStateError': 'This passkey may already be registered',
        'NotSupportedError': 'Your browser does not support passkeys',
        'SecurityError': 'Security error - please ensure you are using HTTPS',
        'AbortError': 'Registration timed out (120 seconds)',
        'UnknownError': 'An unknown error occurred',
    };

    // Convert server options to WebAuthn format for registration
    function prepareRegistrationOptions(serverOptions) {
        const options = {
            challenge: base64UrlToArrayBuffer(serverOptions.challenge),
            rp: {
                name: serverOptions.rp.name,
                id: serverOptions.rp.id,
            },
            user: {
                id: base64UrlToArrayBuffer(serverOptions.user.id),
                name: serverOptions.user.name,
                displayName: serverOptions.user.display_name || serverOptions.user.name,
            },
            pubKeyCredParams: serverOptions.pub_key_cred_params.map(p => ({
                type: p.type,
                alg: p.alg,
            })),
            timeout: serverOptions.timeout || 60000,
            authenticatorSelection: buildAuthenticatorSelection(serverOptions.authenticator_selection),
        };

        if (serverOptions.exclude_credentials && serverOptions.exclude_credentials.length > 0) {
            options.excludeCredentials = serverOptions.exclude_credentials.map(cred => ({
                type: 'public-key',
                id: base64UrlToArrayBuffer(cred.id),
                transports: cred.transports || undefined,
            }));
        }

        return options;
    }

    // Convert registration credential to JSON for server
    function registrationCredentialToJSON(credential) {
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

    let currentPasskeyUserId = null;
    let currentPasskeyUsername = null;

    function _updatePasskeyModalSections(isCurrentUser, isAdmin) {
        const registerSection = document.getElementById('passkey-register-section');
        const adminSection = document.getElementById('passkey-admin-section');
        const warningEl = document.getElementById('passkey-webauthn-warning');

        const showRegister = isCurrentUser && isWebAuthnSupported;
        const showWarning = isCurrentUser && !isWebAuthnSupported;
        const showAdmin = !isCurrentUser && isAdmin;

        setHidden(registerSection, !showRegister);
        setHidden(adminSection, !showAdmin);
        setHidden(warningEl, !showWarning);
    }

    function _resetPasskeyListState() {
        setHidden(document.getElementById('passkey-list-loading'), false);
        setHidden(document.getElementById('passkey-list-empty'), true);
        setHidden(document.getElementById('passkey-list-error'), true);
        setHidden(document.getElementById('passkey-list'), true);
    }

    async function refreshPasskeyList() {
        if (currentPasskeyUserId === null) return;
        const isCurrentUser = currentPasskeyUserId === CURRENT_USER_ID;
        await loadPasskeys(currentPasskeyUserId, isCurrentUser, IS_ADMIN);
    }

    async function openPasskeySettings(userId, username) {
        currentPasskeyUserId = userId;
        currentPasskeyUsername = username;

        const isCurrentUser = userId === CURRENT_USER_ID;
        const isAdmin = IS_ADMIN;

        const modalEl = document.getElementById('passkeySettingsModal');
        modalEl.dataset.userId = userId;
        modalEl.dataset.username = username;

        document.getElementById('passkey-modal-username').textContent = username;
        document.getElementById('passkey-status-text').textContent = 'Loading...';
        document.getElementById('passkey-count-badge').innerHTML = '';

        // Reset list display states
        _resetPasskeyListState();

        // Update section visibility
        _updatePasskeyModalSections(isCurrentUser, isAdmin);

        // Show modal
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();

        // Load passkeys
        await loadPasskeys(userId, isCurrentUser, isAdmin);
    }

    async function loadPasskeys(userId, isCurrentUser, isAdmin) {
        try {
            let endpoint = isCurrentUser ? '/api/passkeys' : `/api/passkeys/user/${userId}`;
            const passkeys = await api('GET', endpoint) || [];

            setHidden(document.getElementById('passkey-list-loading'), true);

            const statusText = document.getElementById('passkey-status-text');
            const countBadge = document.getElementById('passkey-count-badge');

            // Update passkey indicator in user row
            updatePasskeyIndicator(userId, passkeys.length > 0);

            if (passkeys.length === 0) {
                statusText.textContent = '';
                countBadge.innerHTML = '<span class="badge bg-secondary">0 Passkeys</span>';
                setHidden(document.getElementById('passkey-list-empty'), false);
                setHidden(document.getElementById('passkey-list'), true);
            } else {
                statusText.textContent = `${passkeys.length} passkey${passkeys.length !== 1 ? 's' : ''} registered`;
                countBadge.innerHTML = `<span class="badge bg-success">${passkeys.length} Passkey${passkeys.length !== 1 ? 's' : ''}</span>`;
                setHidden(document.getElementById('passkey-list-empty'), true);

                const listEl = document.getElementById('passkey-list');
                listEl.innerHTML = '';

                for (const pk of passkeys) {
                    const item = document.createElement('div');
                    item.className = 'list-group-item d-flex justify-content-between align-items-center';

                    const createdAt = new Date(pk.created_at || Date.now()).toLocaleDateString();
                    const deviceName = pk.device_name || 'Unnamed Passkey';
                    const transports = pk.transports ? pk.transports.join(', ') : '';

                    const contentWrap = document.createElement('div');
                    const nameEl = document.createElement('strong');
                    nameEl.textContent = deviceName;

                    const metaEl = document.createElement('div');
                    metaEl.className = 'small text-muted';
                    metaEl.textContent = transports ? `Created: ${createdAt} • ${transports}` : `Created: ${createdAt}`;

                    contentWrap.append(nameEl, metaEl);
                    item.appendChild(contentWrap);

                    if (isCurrentUser) {
                        const deleteBtn = document.createElement('button');
                        deleteBtn.type = 'button';
                        deleteBtn.className = 'btn btn-sm btn-outline-danger btn-delete-passkey users-action-btn';
                        deleteBtn.dataset.passkeyId = String(pk.id);
                        deleteBtn.title = 'Delete passkey';

                        const icon = document.createElement('span');
                        icon.className = 'material-icons icon-md';
                        icon.setAttribute('aria-hidden', 'true');
                        icon.textContent = 'delete';
                        deleteBtn.appendChild(icon);
                        item.appendChild(deleteBtn);
                    }

                    listEl.appendChild(item);
                }

                setHidden(document.getElementById('passkey-list'), false);
            }

            // Ensure error box is hidden on success
            setHidden(document.getElementById('passkey-list-error'), true);

        } catch (error) {
            setHidden(document.getElementById('passkey-list-loading'), true);
            setHidden(document.getElementById('passkey-list-empty'), true);
            setHidden(document.getElementById('passkey-list-error'), false);
        }
    }

    function updatePasskeyIndicator(userId, hasPasskeys) {
        const indicator = document.getElementById(`passkey-indicator-${userId}`);
        setHidden(indicator, !hasPasskeys);
    }

    // Register new passkey
    document.getElementById('passkey-register-btn')?.addEventListener('click', async function () {
        if (this.disabled || !isWebAuthnSupported) return;

        const deviceNameInput = document.getElementById('passkey-device-name');
        const deviceName = sanitizeDeviceName(deviceNameInput.value);
        const btn = this;
        const originalHtml = btn.innerHTML;

        btn.disabled = true;
        btn.setAttribute('aria-busy', 'true');
        btn.innerHTML = '<span class="spinner-border spinner-border-sm align-middle me-1"></span> Registering...';

        // Create AbortController for timeout
        const abortController = new AbortController();
        const timeoutId = setTimeout(() => abortController.abort(), 120000); // 120 seconds

        try {
            // 1. Get registration options
            const startResp = await api('POST', '/api/passkeys/register/start');
            const publicKeyOptions = prepareRegistrationOptions(startResp);

            // 2. Create credential with browser (with timeout)
            const credential = await navigator.credentials.create({
                publicKey: publicKeyOptions,
                signal: abortController.signal,
            });

            if (!credential) {
                throw new Error('Passkey registration cancelled');
            }

            // 3. Send credential to server
            const credentialJSON = registrationCredentialToJSON(credential);

            await api('POST', '/api/passkeys/register/finish', {
                credential: credentialJSON,
                device_name: deviceName || null,
            });

            // 4. Success - refresh list
            wbToast('Passkey registered successfully', 'success');
            deviceNameInput.value = '';
            await refreshPasskeyList();

        } catch (error) {
            // Show friendly error message
            if (error.name !== 'NotAllowedError' && error.name !== 'AbortError') {
                const friendlyMsg = FRIENDLY_ERRORS[error.name] || 'Failed to register passkey';
                const serverMsg = error.message ? String(error.message).slice(0, 200) : '';
                const displayMsg = FRIENDLY_ERRORS[error.name] ? friendlyMsg : `${friendlyMsg}: ${serverMsg}`;

                wbAlert(displayMsg, 'danger');
            }
        } finally {
            clearTimeout(timeoutId);
            btn.disabled = false;
            btn.removeAttribute('aria-busy');
            btn.innerHTML = originalHtml;
        }
    });

    // Delete passkey (event delegation)
    document.getElementById('passkey-list')?.addEventListener('click', async (e) => {
        const deleteBtn = e.target.closest('.btn-delete-passkey');
        if (!deleteBtn) return;

        const passkeyId = parseInt(deleteBtn.dataset.passkeyId, 10);

        if (!await wbConfirm('Delete this passkey?', 'danger')) return;

        deleteBtn.disabled = true;

        try {
            await api('DELETE', `/api/passkeys/${passkeyId}`);
            wbToast('Passkey deleted', 'success');
            await refreshPasskeyList();
        } catch (error) {
            wbAlert('Failed to delete passkey: ' + error.message, 'danger');
            deleteBtn.disabled = false;
        }
    });

    // Admin reset all passkeys
    document.getElementById('passkey-reset-btn')?.addEventListener('click', async function () {
        if (this.disabled) return;

        if (!await wbConfirm(`Reset ALL passkeys for "${currentPasskeyUsername}"? This cannot be undone.`, 'danger')) return;

        this.disabled = true;

        try {
            const resp = await api('POST', `/api/passkeys/reset/${currentPasskeyUserId}`);
            const deletedCount = resp?.deleted_count || 0;
            wbToast(`Reset ${deletedCount} passkey(s)`, 'success');

            // Close modal
            const modalEl = document.getElementById('passkeySettingsModal');
            const modal = bootstrap.Modal.getInstance(modalEl);
            if (modal) modal.hide();
        } catch (error) {
            wbAlert('Failed to reset passkeys: ' + error.message, 'danger');
        } finally {
            this.disabled = false;
        }
    });

    // ─── END PASSKEY MANAGEMENT ───────────────────────────────────────
})();
