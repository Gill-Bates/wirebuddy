(async function () {
    // Shared scope: all includes below run in this IIFE and share identifiers.
    // Keep include-local names unique and preserve load order (_js_init first).
    const cfg = document.getElementById('wb-page-config')?.dataset ?? {};
    const isAdmin = cfg.isAdmin === 'true';
    const USER_ID = Number.parseInt(cfg.userId || '', 10);
    if (!Number.isInteger(USER_ID)) {
        console.error('Invalid page config: USER_ID is missing or not an integer.');
        return;
    }

    // XSS protection helper
    function esc(str) {
        const d = document.createElement('div');
        d.textContent = str ?? '';
        return d.innerHTML;
    }

    // Simple string hash for generating stable DOM IDs
    // Returns a short alphanumeric string based on input
    function simpleHash(str) {
        if (!str) return 'empty';
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash |= 0; // Convert to 32bit integer
        }
        // Convert to positive base-36 string (0-9, a-z)
        return Math.abs(hash).toString(36);
    }

    // FQDN/Domain detection helper (DRY)
    function detectHostname() {
        const hostname = window.location.hostname;
        if (!hostname) return null;
        // Strip brackets from IPv6 [::1] → ::1
        return hostname.replace(/^\[|\]$/g, '');
    }

    // Tab state tracking for lazy loading
    const tabLoaded = {
        general: false,
        wireguard: false,
        letsencrypt: false,
        dns: false,
        logs: false
    };

    // Initialize tabs with URL hash support
    async function initTabs() {
        const hash = window.location.hash.replace('#', '');
        const validTabs = ['general', 'wireguard', 'letsencrypt', 'dns', 'logs', 'backup'];

        if (hash && validTabs.includes(hash)) {
            const tabBtn = document.getElementById(`${hash}-tab`);
            if (tabBtn) {
                const tab = new bootstrap.Tab(tabBtn);
                tab.show();
            }
        }

        // Listen for tab changes (use replaceState to avoid history pollution)
        document.querySelectorAll('#settingsTabs button[data-bs-toggle="tab"]').forEach(tabBtn => {
            tabBtn.addEventListener('shown.bs.tab', async function (e) {
                const tabId = e.target.id.replace('-tab', '');
                history.replaceState(null, '', `#${tabId}`);
                await loadTabData(tabId);
            });
        });

        // Load initial tab data and wait for it to complete
        const activeTab = document.querySelector('#settingsTabs .nav-link.active');
        if (activeTab) {
            await loadTabData(activeTab.id.replace('-tab', ''));
        }
    }

    // Lazy load tab data
    async function loadTabData(tabId) {
        if (tabLoaded[tabId]) return;

        switch (tabId) {
            case 'general':
                await loadWgSettings();  // Status Page toggle is on General tab
                await loadSpeedtestSettings();
                tabLoaded.general = true;
                break;
            case 'wireguard':
                await loadWgSettings();  // Must await to ensure wgSettingsLoaded is true before user interaction
                refreshInterfaces();
                loadTrafficStatus();
                tabLoaded.wireguard = true;
                break;
            case 'letsencrypt':
                if (document.getElementById('certificates-list')) {
                    refreshCertificates();
                }
                tabLoaded.letsencrypt = true;
                break;
            case 'dns':
                if (document.getElementById('blocklist-sources')) {
                    loadBlocklistSources();
                }
                bindDnsConfigListeners();
                if (document.getElementById('dns-upstream-servers')) {
                    loadDnsConfig();
                }
                loadCustomRules();
                loadDnsServiceStatus();
                tabLoaded.dns = true;
                break;
            case 'logs':
                loadTsdbStats();
                loadDnsMetricsStats();
                loadPeerMetricsStats();
                loadSpeedtestStats();
                tabLoaded.logs = true;
                break;
        }
    }

    // WireGuard global settings
    // Type-safe boolean conversion for settings values (handles '1', 1, true, 'true', etc.)

    function toBool(v) {
        return v === true || v === 1 || v === '1' || String(v).toLowerCase() === 'true';
    }

    let _wgSettings = {};

    async function loadWgSettings() {
        try {
            const settings = await api('GET', '/api/wireguard/settings');
            _wgSettings = settings || {};
            
            const fqdnInput = document.getElementById('wg-fqdn');
            if (fqdnInput && settings.wg_fqdn) {
                fqdnInput.value = settings.wg_fqdn;
            }
            
            const guiPortInput = document.getElementById('gui-port');
            if (guiPortInput && settings.gui_port) {
                guiPortInput.value = settings.gui_port;
            }

            const guiExternalPortInput = document.getElementById('gui-external-port');
            if (guiExternalPortInput && settings.gui_external_port) {
                guiExternalPortInput.value = settings.gui_external_port;
            }
            
            const mtuInput = document.getElementById('wg-mtu');
            if (mtuInput && settings.wg_mtu !== null && settings.wg_mtu !== undefined && settings.wg_mtu !== '') {
                mtuInput.value = settings.wg_mtu;
            }
            
            const keepaliveInput = document.getElementById('wg-keepalive');
            if (keepaliveInput && settings.wg_persistent_keepalive !== null && settings.wg_persistent_keepalive !== undefined && settings.wg_persistent_keepalive !== '') {
                keepaliveInput.value = settings.wg_persistent_keepalive;
            }

            // Localhost toggle
            const localhostToggle = document.getElementById('gui-localhost-only');
            if (localhostToggle) {
                localhostToggle.checked = toBool(settings.gui_localhost_only);
            }

            // PSK toggle
            const pskToggle = document.getElementById('wg-use-psk');
            if (pskToggle) {
                pskToggle.checked = toBool(settings.wg_use_psk);
                togglePskDetails(pskToggle.checked);
                if (pskToggle.checked) await loadPsk();
            }

            const statusToggle = document.getElementById('enable-status-page');
            if (statusToggle) {
                // Disable transition during initial load to prevent animation
                statusToggle.style.transition = 'none';
                statusToggle.checked = toBool(settings.enable_status_page);
                // Force reflow, then restore transition
                statusToggle.offsetHeight;
                statusToggle.style.transition = '';
            }

            const swaggerToggle = document.getElementById('enable-swagger');
            if (swaggerToggle) {
                swaggerToggle.style.transition = 'none';
                swaggerToggle.checked = toBool(settings.enable_swagger);
                swaggerToggle.offsetHeight;
                swaggerToggle.style.transition = '';
            }

            updateStatusPageUrlPreview();
            updateSwaggerUrlPreview();
        } catch (error) {
            console.error('Failed to load WG settings:', error.message);
            wbToast('Failed to load WireGuard settings. Please refresh the page.', 'danger');
        } finally {
            // Always allow saves after load attempt to prevent permanent blocking
            // If load failed, user can still manually enter values
            wgSettingsLoaded = true;
        }
    }

    function updateStatusPageUrlPreview() {
        const target = document.getElementById('status-page-url');
        if (!target) return;

        const fqdnInput = document.getElementById('wg-fqdn');
        const rawHost = (fqdnInput?.value || '').trim().replace(/^\[|\]$/g, '');
        const host = rawHost || window.location.hostname;
        const urlHost = host.includes(':') ? `[${host}]` : host;

        target.textContent = `https://${urlHost}/status`;
    }

    async function copyStatusPageUrl() {
        const target = document.getElementById('status-page-url');
        const value = (target?.textContent || '').trim();
        if (!value) {
            wbToast('Status URL is empty', 'warning');
            return;
        }

        try {
            if (navigator.clipboard?.writeText) {
                await navigator.clipboard.writeText(value);
            } else {
                const el = document.createElement('textarea');
                el.value = value;
                el.setAttribute('readonly', '');
                el.style.position = 'absolute';
                el.style.left = '-9999px';
                document.body.appendChild(el);
                el.select();
                document.execCommand('copy');
                document.body.removeChild(el);
            }
            wbToast('Status URL copied', 'success');
        } catch (error) {
            wbToast('Failed to copy status URL', 'danger');
        }
    }

    function updateSwaggerUrlPreview() {
        const target = document.getElementById('swagger-url');
        if (!target) return;

        const fqdnInput = document.getElementById('wg-fqdn');
        const rawHost = (fqdnInput?.value || '').trim().replace(/^\[|\]$/g, '');
        const host = rawHost || window.location.hostname;
        const urlHost = host.includes(':') ? `[${host}]` : host;

        target.textContent = `https://${urlHost}/swagger`;
    }

    async function copySwaggerUrl() {
        const target = document.getElementById('swagger-url');
        const value = (target?.textContent || '').trim();
        if (!value) {
            wbToast('Swagger URL is empty', 'warning');
            return;
        }

        try {
            if (navigator.clipboard?.writeText) {
                await navigator.clipboard.writeText(value);
            } else {
                const el = document.createElement('textarea');
                el.value = value;
                el.setAttribute('readonly', '');
                el.style.position = 'absolute';
                el.style.left = '-9999px';
                document.body.appendChild(el);
                el.select();
                document.execCommand('copy');
                document.body.removeChild(el);
            }
            wbToast('Swagger URL copied', 'success');
        } catch (error) {
            wbToast('Failed to copy Swagger URL', 'danger');
        }
    }

    function togglePskDetails(show) {
        const el = document.getElementById('psk-details');
        if (el) el.classList.toggle('d-none', !show);
    }

    function isValidWgPsk(value) {
        const trimmed = (value || '').trim();
        if (!/^[A-Za-z0-9+/]{43}=$/.test(trimmed)) return false;
        try {
            return atob(trimmed).length === 32;
        } catch (_) {
            return false;
        }
    }

    function isMaskedPskValue(value) {
        const trimmed = (value || '').trim();
        return trimmed.includes('*');
    }

    function setPskValidationState(invalid, message = 'Invalid PSK format (must be 44-char WireGuard key)') {
        const input = document.getElementById('wg-psk-display');
        const feedback = document.getElementById('wg-psk-feedback');
        if (!input || !feedback) return;

        input.classList.toggle('is-invalid', invalid);
        feedback.classList.toggle('d-none', !invalid);
        feedback.textContent = message;
    }

    let lastSavedCustomPsk = null;
    let cachedMaskedPsk = '';
    let cachedRevealedPsk = '';

    async function saveCustomPsk(rawValue, options = {}) {
        const { silentSuccess = false, silentInvalid = false } = options;
        const psk = (rawValue || '').trim();
        if (!isValidWgPsk(psk)) {
            setPskValidationState(true);
            if (!silentInvalid) {
                wbToast('Invalid PSK format (must be 44-char WireGuard key)', 'warning');
            }
            return false;
        }
        if (lastSavedCustomPsk && psk === lastSavedCustomPsk) {
            setPskValidationState(false);
            return true;
        }
        try {
            const res = await api('PUT', '/api/wireguard/settings/psk', { psk });
            const display = document.getElementById('wg-psk-display');
            const maskedValue = res.masked || res.data?.masked || '';
            if (display) {
                display.value = maskedValue;
                display.type = 'password';
            }
            lastSavedCustomPsk = psk;
            cachedMaskedPsk = maskedValue;
            cachedRevealedPsk = psk;
            setPskValidationState(false);
            if (!silentSuccess) {
                wbToast('PresharedKey saved', 'success');
            }
            return true;
        } catch (error) {
            wbToast('Failed to save PSK: ' + error.message, 'danger');
            return false;
        }
    }

    async function loadPsk() {
        if (!isAdmin) return;  // PSK endpoint requires admin
        
        try {
            const res = await api('GET', '/api/wireguard/settings/psk');
            const maskedValue = res.masked || res.data?.masked || '';
            const display = document.getElementById('wg-psk-display');
            if (display) {
                display.value = maskedValue;
                display.type = 'password';
            }
            cachedMaskedPsk = maskedValue;
            setPskValidationState(false);
        } catch (error) {
            console.warn('Failed to load PSK:', error.message);
        }
    }

    // WG settings auto-save with debouncing
    let wgSettingsSaveTimeout = null;
    let wgSettingsLoaded = false;  // Prevent saves before initial load completes

    // Strict IPv4 CIDR validator: checks octet range (0-255) and prefix (0-32)
    function isValidIPv4Cidr(value) {
        const match = value.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/);
        if (!match) return false;
        const [, a, b, c, d, mask] = match.map(Number);
        if ([a, b, c, d].some(n => n < 0 || n > 255)) return false;
        if (mask < 0 || mask > 32) return false;
        return true;
    }

    // IPv6 CIDR validator: validates prefix (0-128) and uses RFC-compliant regex
    function isValidIPv6Cidr(value) {
        const match = value.match(/^([0-9a-fA-F:]+)\/(\d{1,3})$/);
        if (!match) return false;
        const addr = match[1];
        const mask = Number(match[2]);
        if (!Number.isFinite(mask) || mask < 0 || mask > 128) return false;
        
        // Comprehensive IPv6 regex (handles all valid formats including ::1, 2001:db8::, etc.)
        const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;
        return ipv6Regex.test(addr);
    }

    function parseOptionalInt(rawValue, min, max, label) {
        if (rawValue === '' || rawValue === null || rawValue === undefined) {
            return { value: null, valid: true };
        }
        const parsed = Number.parseInt(rawValue, 10);
        if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
            return {
                value: null,
                valid: false,
                message: `${label} must be a number between ${min} and ${max}`,
            };
        }
        return { value: parsed, valid: true };
    }

    async function saveWgSettings(options = {}) {
        if (!isAdmin) return;
        // Prevent saving before settings are loaded (race condition protection)
        if (!wgSettingsLoaded) {
            console.warn('[WG Settings] Save blocked - settings not yet loaded');
            return false;
        }
        const { silentSuccess = false, fields = null } = options;
        const payload = {};
        const includeField = (field) => !Array.isArray(fields) || fields.includes(field);
        
        const fqdnInput = document.getElementById('wg-fqdn');
        const guiPortInput = document.getElementById('gui-port');
        const guiExternalPortInput = document.getElementById('gui-external-port');
        const mtuInput = document.getElementById('wg-mtu');
        const keepaliveInput = document.getElementById('wg-keepalive');
        
        if (fqdnInput && includeField('wg_fqdn')) {
            const fqdn = fqdnInput.value.trim();
            payload.wg_fqdn = fqdn || null;
        }

        if (guiPortInput && includeField('gui_port')) {
            const guiPortResult = parseOptionalInt(guiPortInput.value, 1, 65535, 'HTTP Port (GUI)');
            if (!guiPortResult.valid) {
                wbToast(guiPortResult.message, 'warning');
                return false;
            }
            payload.gui_port = guiPortResult.value;
        }

        if (guiExternalPortInput && includeField('gui_external_port')) {
            const guiExternalPortResult = parseOptionalInt(guiExternalPortInput.value, 1, 65535, 'External Port (Reverse Proxy)');
            if (!guiExternalPortResult.valid) {
                wbToast(guiExternalPortResult.message, 'warning');
                return false;
            }
            payload.gui_external_port = guiExternalPortResult.value;
        }

        if (mtuInput && includeField('wg_mtu')) {
            const mtuResult = parseOptionalInt(mtuInput.value, 1280, 9000, 'MTU');
            if (!mtuResult.valid) {
                wbToast(mtuResult.message, 'warning');
                return false;
            }
            payload.wg_mtu = mtuResult.value;
        }

        if (keepaliveInput && includeField('wg_persistent_keepalive')) {
            const keepaliveResult = parseOptionalInt(keepaliveInput.value, 0, 600, 'Persistent Keepalive');
            if (!keepaliveResult.valid) {
                wbToast(keepaliveResult.message, 'warning');
                return false;
            }
            payload.wg_persistent_keepalive = keepaliveResult.value;
        }

        // Include localhost toggle state
        const localhostToggle = document.getElementById('gui-localhost-only');
        if (localhostToggle && includeField('gui_localhost_only')) payload.gui_localhost_only = localhostToggle.checked ? '1' : '0';

        // Include PSK toggle state
        const pskToggle = document.getElementById('wg-use-psk');
        if (pskToggle && includeField('wg_use_psk')) payload.wg_use_psk = pskToggle.checked ? '1' : '0';

        const statusToggle = document.getElementById('enable-status-page');
        if (statusToggle && includeField('enable_status_page')) payload.enable_status_page = statusToggle.checked ? '1' : '0';

        const swaggerToggle = document.getElementById('enable-swagger');
        if (swaggerToggle && includeField('enable_swagger')) payload.enable_swagger = swaggerToggle.checked ? '1' : '0';

        // Guard against empty payload
        if (Object.keys(payload).length === 0) {
            return true;
        }

        try {
            const response = await api('PATCH', '/api/wireguard/settings', payload);
            _wgSettings = response?.settings || response?.data?.settings || _wgSettings;
            if (!silentSuccess) {
                wbToast('Settings saved', 'success');
            }
            return true;
        } catch (error) {
            wbToast('Failed to save settings: ' + error.message, 'danger');
            return false;
        }
    }

    // FQDN Auto-Detect
    const fqdnDetectBtn = document.getElementById('btn-fqdn-detect');
    if (fqdnDetectBtn && fqdnDetectBtn.dataset.bound !== '1') {
        fqdnDetectBtn.dataset.bound = '1';
        fqdnDetectBtn.addEventListener('click', async () => {
            const detected = detectHostname();
            if (!detected) {
                wbToast('Could not detect hostname', 'warning');
                return;
            }
            const input = document.getElementById('wg-fqdn');
            if (!input) return;
            input.value = detected;
            updateStatusPageUrlPreview();
            await saveWgSettings({ silentSuccess: true });
            wbToast(`Detected: ${detected}`, 'success');
        });
    }

    // Certificate Domain Auto-Detect
    document.getElementById('btn-cert-domain-detect')?.addEventListener('click', () => {
        const detected = detectHostname();
        if (!detected) {
            wbToast('Could not detect hostname', 'warning');
            return;
        }
        document.getElementById('cert-domain').value = detected;
        wbToast(`Detected: ${detected}`, 'success');
    });

    function saveWgSettingsDebounced() {
        clearTimeout(wgSettingsSaveTimeout);
        wgSettingsSaveTimeout = setTimeout(saveWgSettings, 800);
    }

    // Cancel pending debounced saves on page unload to prevent stale writes
    window.addEventListener('pagehide', () => clearTimeout(wgSettingsSaveTimeout));

    // PSK toggle handler (with race condition protection)

    const pskToggle = document.getElementById('wg-use-psk');
    if (pskToggle) {
        pskToggle.addEventListener('change', async function () {
            this.disabled = true;
            try {
                togglePskDetails(this.checked);
                if (this.checked) {
                    const display = document.getElementById('wg-psk-display');
                    try {
                        let existingMasked = '';
                        try {
                            const current = await api('GET', '/api/wireguard/settings/psk');
                            existingMasked = current.masked || current.data?.masked || '';
                        } catch (loadErr) {
                            console.warn('Failed to load existing PSK, attempting to generate a new one:', loadErr.message);
                        }

                        if (existingMasked) {
                            display.value = existingMasked;
                            display.type = 'password';
                            cachedMaskedPsk = existingMasked;
                        } else {
                            const res = await api('POST', '/api/wireguard/settings/generate-psk');
                            const maskedValue = res.masked || res.data?.masked || '';
                            display.value = maskedValue;
                            display.type = 'password';
                            cachedMaskedPsk = maskedValue;
                            cachedRevealedPsk = '';
                            wbToast('PresharedKey generated', 'success');
                        }
                    } catch (err) {
                        wbToast('Failed to initialize PSK: ' + err.message, 'danger');
                        this.checked = false;
                        togglePskDetails(false);
                        return;
                    }
                }
                await saveWgSettings({ silentSuccess: true });
            } finally {
                this.disabled = false;
            }
        });
    }

    // PSK visibility toggle (loads actual key on reveal)
    const pskVisBtn = document.getElementById('psk-toggle-visibility');
    if (pskVisBtn) {
        pskVisBtn.addEventListener('click', async function () {
            const display = document.getElementById('wg-psk-display');
            const icon = this.querySelector('.material-icons');
            if (display.type === 'password') {
                try {
                    if (!cachedRevealedPsk) {
                        const res = await api('GET', '/api/wireguard/settings/psk?reveal=true');
                        cachedRevealedPsk = res.key || res.data?.key || '';
                    }
                    display.value = cachedRevealedPsk || display.value;
                    display.type = 'text';
                    setPskValidationState(false);
                    icon.textContent = 'visibility_off';
                } catch (e) {
                    wbToast('Cannot reveal key', 'warning');
                }
            } else {
                if (!cachedMaskedPsk) {
                    const res = await api('GET', '/api/wireguard/settings/psk');
                    cachedMaskedPsk = res.masked || res.data?.masked || '';
                }
                display.value = cachedMaskedPsk;
                display.type = 'password';
                setPskValidationState(false);
                icon.textContent = 'visibility';
            }
        });
    }

    // PSK copy to clipboard
    const pskCopyBtn = document.getElementById('psk-copy-btn');
    if (pskCopyBtn) {
        pskCopyBtn.addEventListener('click', async function () {
            const display = document.getElementById('wg-psk-display');
            let keyToCopy = display.value;

            // If password is masked, fetch the actual key first
            if (display.type === 'password') {
                try {
                    const res = await api('GET', '/api/wireguard/settings/psk?reveal=true');
                    keyToCopy = res.key || res.data?.key || '';
                } catch (e) {
                    wbToast('Cannot retrieve key', 'danger');
                    return;
                }
            }

            if (!keyToCopy || keyToCopy === 'No key generated yet') {
                wbToast('No key to copy', 'warning');
                return;
            }

            try {
                await navigator.clipboard.writeText(keyToCopy);
                wbToast('PresharedKey copied to clipboard', 'success');
            } catch (e) {
                wbToast('Failed to copy to clipboard', 'danger');
            }
        });
    }

    // PSK generate button
    const pskGenBtn = document.getElementById('psk-generate-btn');
    if (pskGenBtn) {
        pskGenBtn.addEventListener('click', async function () {
            if (!await wbConfirm(
                'Generate a new PresharedKey? Existing client configurations will need to be re-downloaded.',
                'warning'
            )) return;

            try {
                const res = await api('POST', '/api/wireguard/settings/generate-psk');
                const display = document.getElementById('wg-psk-display');
                // API returns {status: "ok", data: {masked: "..."}, masked: "..."}
                // After processing by api(), we get {masked: "...", status: "ok"}
                const maskedValue = res.masked || res.data?.masked || '';
                display.value = maskedValue;
                display.type = 'password';
                cachedMaskedPsk = maskedValue;
                cachedRevealedPsk = '';
                setPskValidationState(false);
                wbToast('New PresharedKey generated', 'success');
            } catch (err) {
                wbToast('Failed to generate PSK: ' + err.message, 'danger');
            }
        });
    }

    // PSK autosave for custom input (validated)
    let pskSaveTimeout = null;
    const pskDisplayInput = document.getElementById('wg-psk-display');
    if (pskDisplayInput) {
        pskDisplayInput.addEventListener('input', function () {
            const pskToggleInput = document.getElementById('wg-use-psk');
            if (!pskToggleInput?.checked) return;

            const candidate = this.value.trim();
            if (!candidate || isMaskedPskValue(candidate)) {
                setPskValidationState(false);
                return;
            }

            setPskValidationState(!isValidWgPsk(candidate));

            clearTimeout(pskSaveTimeout);
            pskSaveTimeout = setTimeout(async () => {
                await saveCustomPsk(candidate, { silentSuccess: false, silentInvalid: true });
            }, 800);
        });

        pskDisplayInput.addEventListener('blur', async function () {
            const pskToggleInput = document.getElementById('wg-use-psk');
            if (!pskToggleInput?.checked) return;

            const candidate = this.value.trim();
            if (!candidate || isMaskedPskValue(candidate)) {
                setPskValidationState(false);
                return;
            }

            clearTimeout(pskSaveTimeout);
            await saveCustomPsk(candidate, { silentSuccess: false, silentInvalid: true });
        });
    }

    // Add auto-save listeners to WG settings inputs
    const wgFqdn = document.getElementById('wg-fqdn');
    const guiPort = document.getElementById('gui-port');
    const guiExternalPort = document.getElementById('gui-external-port');
    const guiLocalhostOnly = document.getElementById('gui-localhost-only');
    const wgMtu = document.getElementById('wg-mtu');
    const wgKeepalive = document.getElementById('wg-keepalive');
    const enableStatusPage = document.getElementById('enable-status-page');

    if (wgFqdn) {
        wgFqdn.addEventListener('input', () => {
            updateStatusPageUrlPreview();
            updateSwaggerUrlPreview();
            saveWgSettingsDebounced();
        });
    }
    if (guiPort) {
        guiPort.addEventListener('change', () => {
            updateStatusPageUrlPreview();
            updateSwaggerUrlPreview();
            saveWgSettingsDebounced();
        });
    }
    if (guiExternalPort) {
        guiExternalPort.addEventListener('change', () => {
            saveWgSettingsDebounced();
        });
    }
    if (guiLocalhostOnly) {
        guiLocalhostOnly.addEventListener('change', () => saveWgSettings({ fields: ['gui_localhost_only'] }));
    }
    if (wgMtu) wgMtu.addEventListener('change', saveWgSettingsDebounced);
    if (wgKeepalive) wgKeepalive.addEventListener('change', saveWgSettingsDebounced);
    if (enableStatusPage) {
        enableStatusPage.addEventListener('change', () => saveWgSettings({ fields: ['enable_status_page'] }));
    }

    const enableSwagger = document.getElementById('enable-swagger');
    if (enableSwagger) {
        enableSwagger.addEventListener('change', () => saveWgSettings({ fields: ['enable_swagger'] }));
    }

    const copyStatusPageUrlBtn = document.getElementById('btn-copy-status-page-url');
    if (copyStatusPageUrlBtn) {
        copyStatusPageUrlBtn.addEventListener('click', () => {
            void copyStatusPageUrl();
        });
    }

    const copySwaggerUrlBtn = document.getElementById('btn-copy-swagger-url');
    if (copySwaggerUrlBtn) {
        copySwaggerUrlBtn.addEventListener('click', () => {
            void copySwaggerUrl();
        });
    }

    const purgeTrafficBtn = document.getElementById('btn-purge-traffic-logs');
    if (purgeTrafficBtn) {
        purgeTrafficBtn.addEventListener('click', () => {
            void purgeTrafficLogs();
        });
    }

    const purgePeerBtn = document.getElementById('btn-purge-peer-logs');
    if (purgePeerBtn) {
        purgePeerBtn.addEventListener('click', () => {
            void purgePeerLogs();
        });
    }

    const openCreateInterfaceModalBtn = document.getElementById('btn-open-create-interface-modal');
    if (openCreateInterfaceModalBtn) {
        openCreateInterfaceModalBtn.addEventListener('click', () => {
            void prepareCreateInterfaceModal();
        });
    }

    const updateBlocklistBtn = document.getElementById('btn-update-blocklist');
    if (updateBlocklistBtn) {
        updateBlocklistBtn.addEventListener('click', () => {
            void updateBlocklist();
        });
    }

    const saveCustomRulesBtn = document.getElementById('save-custom-rules-btn');
    if (saveCustomRulesBtn) {
        saveCustomRulesBtn.addEventListener('click', () => {
            void saveCustomRules();
        });
    }

    const validateDnsBtn = document.getElementById('validate-dns-btn');
    if (validateDnsBtn) {
        validateDnsBtn.addEventListener('click', () => {
            void validateDnsServers();
        });
    }

    const purgeDnsLogsBtn = document.getElementById('btn-purge-dns-logs');
    if (purgeDnsLogsBtn) {
        purgeDnsLogsBtn.addEventListener('click', () => {
            void purgeDnsLogs();
        });
    }

    const purgeSpeedtestLogsBtn = document.getElementById('btn-purge-speedtest-logs');
    if (purgeSpeedtestLogsBtn) {
        purgeSpeedtestLogsBtn.addEventListener('click', () => {
            void purgeSpeedtestLogs();
        });
    }


    async function loadTrafficStatus() {
        const toggle = document.getElementById('traffic-analysis-toggle');
        const badge = document.getElementById('traffic-requirements-badge');
        const badgeText = badge?.querySelector('.badge-text');
        const badgeIcon = badge?.querySelector('.material-icons');

        try {
            const status = await api('GET', '/api/wireguard/settings/traffic');
            const enabled = status.enabled === true;
            const requirementsMet = status.requirements_met === true;

            if (toggle) {
                toggle.checked = enabled;
                toggle.disabled = !isAdmin || !requirementsMet;
            }

            if (badge && badgeText && badgeIcon) {
                badge.style.display = '';
                if (requirementsMet) {
                    badge.className = 'badge bg-success';
                    badgeText.textContent = 'Available';
                    badgeIcon.textContent = 'check_circle';
                } else {
                    badge.className = 'badge bg-warning text-dark';
                    badgeText.textContent = 'conntrack not available';
                    badgeIcon.textContent = 'warning';
                }
            }
        } catch (e) {
            if (badge && badgeText) {
                badge.style.display = '';
                badge.className = 'badge bg-secondary';
                badgeText.textContent = 'Unknown';
            }
            if (toggle) toggle.disabled = true;
        }
    }

    async function toggleTrafficAnalysis() {
        const toggle = document.getElementById('traffic-analysis-toggle');
        if (!toggle) return;

        try {
            await api('PATCH', '/api/wireguard/settings', {
                traffic_analysis_enabled: toggle.checked
            });
            wbToast(`Traffic analysis ${toggle.checked ? 'enabled' : 'disabled'}`, 'success');
        } catch (e) {
            toggle.checked = !toggle.checked;
            wbToast('Failed to update traffic analysis setting: ' + (e.message || e), 'danger');
        }
    }

    // Attach traffic analysis toggle event listener
    document.getElementById('traffic-analysis-toggle')?.addEventListener('change', toggleTrafficAnalysis);

    // DNS Service Control
    async function loadDnsServiceStatus() {
        const startBtn = document.getElementById('btn-dns-start');
        const stopBtn = document.getElementById('btn-dns-stop');
        const restartBtn = document.getElementById('btn-dns-restart');

        try {
            // Check if any WireGuard interfaces exist (DNS needs interface IPs to bind)
            let hasInterfaces = false;
            try {
                const ifaceRes = await api('GET', '/api/wireguard/interfaces');
                hasInterfaces = ifaceRes?.interfaces?.length > 0;
            } catch (e) {
                console.warn('Could not check WireGuard interfaces:', e);
            }

            const status = await api('GET', '/api/dns/status');
            const isRunning = status.is_running === true;
            const dnsUnavailable = status.unavailable === true;
            // DNS unavailable (Unbound not installed) - disable all DNS controls
            if (dnsUnavailable) {
                if (startBtn) {
                    startBtn.disabled = true;
                    startBtn.title = 'Unbound not installed';
                }
                if (stopBtn) {
                    stopBtn.disabled = true;
                    stopBtn.title = 'Unbound not installed';
                }
                if (restartBtn) {
                    restartBtn.disabled = true;
                    restartBtn.title = 'Unbound not installed';
                }
                return;
            }
            // Start only available if not running and interfaces exist.
            if (startBtn) {
                startBtn.disabled = !isAdmin || isRunning || !hasInterfaces;
            }
            if (stopBtn) stopBtn.disabled = !isAdmin || !isRunning;
            if (restartBtn) restartBtn.disabled = !isAdmin || !isRunning;
        } catch (e) {
            if (startBtn) {
                startBtn.disabled = true;
                startBtn.title = 'DNS status unavailable';
            }
            if (stopBtn) stopBtn.disabled = true;
            if (restartBtn) restartBtn.disabled = true;
        }
    }

    async function dnsServiceAction(action) {
        const validActions = ['start', 'stop', 'restart'];
        if (!validActions.includes(action)) {
            wbToast('Invalid DNS action', 'danger');
            return;
        }

        if (action === 'stop') {
            if (!await wbConfirm('Stop the DNS resolver? VPN clients may lose DNS resolution.')) return;
        }

        try {
            await api('POST', `/api/dns/${encodeURIComponent(action)}`);
            await loadDnsServiceStatus();
            wbToast(`DNS ${action} successful`, 'success');
        } catch (e) {
            wbToast('DNS action failed: ' + (e.message || e), 'danger');
        }
    }

    const dnsStartBtn = document.getElementById('btn-dns-start');
    if (dnsStartBtn) {
        dnsStartBtn.addEventListener('click', () => dnsServiceAction('start'));
    }
    const dnsStopBtn = document.getElementById('btn-dns-stop');
    if (dnsStopBtn) {
        dnsStopBtn.addEventListener('click', () => dnsServiceAction('stop'));
    }
    const dnsRestartBtn = document.getElementById('btn-dns-restart');
    if (dnsRestartBtn) {
        dnsRestartBtn.addEventListener('click', () => dnsServiceAction('restart'));
    }

    const requestCertificateBtn = document.getElementById('btn-request-certificate');
    if (requestCertificateBtn) {
        requestCertificateBtn.addEventListener('click', () => {
            void requestCertificate();
        });
    }

    const ifaceSubmitBtn = document.getElementById('btn-iface-submit');
    if (ifaceSubmitBtn) {
        ifaceSubmitBtn.addEventListener('click', () => {
            void submitInterfaceForm();
        });
    }

    // WireGuard interface management
    let editingInterfaceName = null;
    const interfaceDefaults = {
        name: 'wg0',
        address: '10.13.13.1/24',
        address6: 'fd13:13:13::1/64',
        listen_port: 51820,
        dns: '',
    };

    function setInterfaceSubmitBusy(isBusy) {
        const spinner = document.getElementById('iface-spinner');
        const submitBtn = document.getElementById('btn-iface-submit');
        if (spinner) spinner.classList.toggle('d-none', !isBusy);
        if (submitBtn) submitBtn.disabled = isBusy;
    }

    async function prepareCreateInterfaceModal() {
        editingInterfaceName = null;

        const title = document.getElementById('ifaceModalTitle');
        const submitLabel = document.getElementById('btn-iface-submit-label');
        const nameInput = document.getElementById('iface-name');
        const addressInput = document.getElementById('iface-address');
        const address6Input = document.getElementById('iface-address6');
        const portInput = document.getElementById('iface-port');
        const dnsInput = document.getElementById('iface-dns');
        const wbDnsToggle = document.getElementById('iface-use-wb-dns');
        const showOnDashboardToggle = document.getElementById('iface-show-on-dashboard');
        const form = document.getElementById('iface-form');

        if (title) title.textContent = 'Create WireGuard Interface';
        if (submitLabel) submitLabel.textContent = 'Create Interface';
        if (form) form.reset();

        // Fetch next available subnet from API
        let nextSubnet = {
            address: interfaceDefaults.address,
            address6: interfaceDefaults.address6,
            listen_port: interfaceDefaults.listen_port
        };
        try {
            const res = await api('GET', '/api/wireguard/interfaces/_next-subnet');
            if (res.address) nextSubnet.address = res.address;
            if (res.address6) nextSubnet.address6 = res.address6;
            if (res.listen_port) nextSubnet.listen_port = res.listen_port;
        } catch (err) {
            console.warn('Could not fetch next subnet, using defaults:', err);
        }

        if (nameInput) {
            nameInput.value = interfaceDefaults.name;
            nameInput.readOnly = false;
        }
        if (addressInput) addressInput.value = nextSubnet.address;
        if (address6Input) address6Input.value = nextSubnet.address6;
        if (portInput) portInput.value = String(nextSubnet.listen_port);
        if (dnsInput) {
            dnsInput.value = interfaceDefaults.dns;
            dnsInput.readOnly = false;
        }
        if (wbDnsToggle) wbDnsToggle.checked = false;
        if (showOnDashboardToggle) showOnDashboardToggle.checked = true;  // Default to showing on dashboard
    }

    async function refreshInterfaces() {
        try {
            const res = await api('GET', '/api/wireguard/interfaces');
            let html = '';
            for (const iface of res.interfaces) {
                const safeName = esc(iface.name);
                const dataName = esc(iface.name).replace(/"/g, '&quot;');
                const statusBadge = iface.is_active
                    ? '<span class="badge bg-success">Active</span>'
                    : '<span class="badge bg-secondary">Inactive</span>';

                // Button states
                const isActive = !!iface.is_active;
                const isConfigured = !!(iface.is_configured ?? (iface.in_database || iface.has_config_file));
                
                // Action buttons - disabled for non-admins or based on state
                const startDisabled = !isAdmin || isActive;
                const stopDisabled = !isAdmin || !isActive;
                const restartDisabled = !isAdmin || !isActive;
                const deleteDisabled = !isAdmin || isActive;
                
                // Start: only enabled if admin and not active
                const startBtn = `<button class="btn btn-sm btn-outline-success text-nowrap iface-action-btn" data-iface="${dataName}" data-action="up" title="${!isAdmin ? 'Admin privileges required' : 'Start'}" aria-label="Start"${startDisabled ? ' disabled' : ''}${!isAdmin ? ' style="pointer-events: none;"' : ''}><span class="material-icons align-middle icon-md">play_arrow</span></button>`;
                // Stop: only enabled if admin and active
                const stopBtn = `<button class="btn btn-sm btn-outline-danger text-nowrap iface-action-btn" data-iface="${dataName}" data-action="down" title="${!isAdmin ? 'Admin privileges required' : 'Stop'}" aria-label="Stop"${stopDisabled ? ' disabled' : ''}${!isAdmin ? ' style="pointer-events: none;"' : ''}><span class="material-icons align-middle icon-md">stop</span></button>`;
                // Restart: only enabled if admin and active
                const restartBtn = `<button class="btn btn-sm btn-outline-warning text-nowrap iface-action-btn" data-iface="${dataName}" data-action="restart" title="${!isAdmin ? 'Admin privileges required' : 'Restart'}" aria-label="Restart"${restartDisabled ? ' disabled' : ''}${!isAdmin ? ' style="pointer-events: none;"' : ''}><span class="material-icons align-middle icon-md">restart_alt</span></button>`;
                // Delete: only enabled if admin and not active
                const deleteBtn = (isAdmin)
                    ? `<button class="btn btn-sm btn-outline-danger text-nowrap iface-delete-btn" data-iface="${dataName}" title="Delete" aria-label="Delete"${deleteDisabled ? ' disabled' : ''}><span class="material-icons align-middle icon-md">delete</span></button>`
                    : '';
                const editBtn = (isAdmin && isConfigured)
                    ? `<button class="btn btn-sm btn-outline-secondary text-nowrap iface-edit-btn" data-iface="${dataName}" title="Edit" aria-label="Edit"><span class="material-icons align-middle icon-md">edit</span></button>`
                    : '';

                html += `
                    <div class="settings-interface-row">
                        <div>
                            <strong>${safeName}</strong>
                            <span class="ms-2">${statusBadge}</span>
                        </div>
                        <div class="settings-interface-actions">${startBtn}${stopBtn}${restartBtn}${editBtn}${deleteBtn}</div>
                    </div>`;
            }
            if (!html) {
                html = isAdmin
                    ? '<p class="text-muted mb-0">No WireGuard interfaces. Click <strong>+</strong> to create one.</p>'
                    : '<p class="text-muted mb-0">No WireGuard interfaces configured.</p>';
            }
            const listEl = document.getElementById('interfaces-list');
            listEl.innerHTML = html;

            // Event delegation for interface buttons
            listEl.removeEventListener('click', handleInterfaceClick);
            listEl.addEventListener('click', handleInterfaceClick);
        } catch (error) {
            document.getElementById('interfaces-list').innerHTML = `<p class="text-danger mb-0">Failed to load interfaces: ${esc(error.message)}</p>`;
        }
    }

    async function handleInterfaceClick(e) {
        const actionBtn = e.target.closest('.iface-action-btn');
        const editBtn = e.target.closest('.iface-edit-btn');
        const deleteBtn = e.target.closest('.iface-delete-btn');

        if (actionBtn) {
            if (!isAdmin) return;  // Safety check
            const name = actionBtn.dataset.iface;
            const action = actionBtn.dataset.action;
            await toggleInterface(name, action);
        } else if (editBtn) {
            if (!isAdmin) return;  // Safety check
            const name = editBtn.dataset.iface;
            await editInterface(name);
        } else if (deleteBtn) {
            if (!isAdmin) return;  // Safety check
            const name = deleteBtn.dataset.iface;
            await deleteInterface(name);
        }
    }

    async function toggleInterface(name, action) {
        const listEl = document.getElementById('interfaces-list');
        const btn = listEl?.querySelector(`.iface-action-btn[data-iface="${CSS.escape(name)}"][data-action="${CSS.escape(action)}"]`);

        // Immediately disable all action buttons for this interface to prevent double-clicks
        const siblingBtns = listEl?.querySelectorAll(`.iface-action-btn[data-iface="${CSS.escape(name)}"]`);
        siblingBtns?.forEach(b => { b.disabled = true; });

        // Optimistic feedback — show immediately, before API responds
        const actionText = action === 'up' ? 'started' : (action === 'down' ? 'stopped' : 'restarted');
        wbToast(`Interface '${name}' ${actionText === 'restarted' ? 'restarting…' : actionText === 'started' ? 'starting…' : 'stopping…'}`, 'info');

        try {
            await api('POST', `/api/wireguard/interfaces/${encodeURIComponent(name)}/${action}`);
            await refreshInterfaces();
            wbToast(`Interface '${name}' successfully ${actionText}`, 'success');
        } catch (e) {
            // Re-enable buttons on failure so the user can retry
            siblingBtns?.forEach(b => { b.disabled = false; });
            wbToast(`Failed to ${action} interface: ` + e.message, 'danger');
        }
    }

    async function createInterface() {
        const name = document.getElementById('iface-name').value.trim();
        const address = document.getElementById('iface-address').value.trim();
        const address6 = document.getElementById('iface-address6').value.trim() || null;
        const port = document.getElementById('iface-port').value || 51820;
        const dns = document.getElementById('iface-dns').value.trim() || null;

        if (!name || !address) {
            wbToast('Please fill in name and address', 'warning');
            return;
        }

        // Validate interface name (1-15 alphanumeric chars, _, -)
        if (!/^[a-zA-Z0-9_-]{1,15}$/.test(name)) {
            wbToast('Interface name must be 1–15 alphanumeric characters (a-z, 0-9, _, -)', 'warning');
            return;
        }

        // Validate CIDR notation (octet range 0-255, mask 0-32)
        if (!isValidIPv4Cidr(address)) {
            wbToast('IPv4 address must be in CIDR format with valid octets and prefix (e.g. 10.13.13.1/24)', 'warning');
            return;
        }

        if (address6 && !isValidIPv6Cidr(address6)) {
            wbToast('IPv6 address must be valid CIDR notation (e.g. fd13:13:13::1/64)', 'warning');
            return;
        }

        setInterfaceSubmitBusy(true);
        try {
            await api('POST', '/api/wireguard/interfaces', {
                name: name,
                address: address,
                address6: address6,
                listen_port: parseInt(port),
                dns: dns
            });

            document.activeElement?.blur();
            bootstrap.Modal.getInstance(document.getElementById('ifaceModal')).hide();
            void prepareCreateInterfaceModal();

            wbToast(`Interface '${name}' created successfully!`, 'success');
            await refreshInterfaces();
            // Refresh DNS status (Unbound may have auto-started)
            await loadDnsServiceStatus();
        } catch (error) {
            wbToast('Failed to create interface: ' + error.message, 'danger');
        } finally {
            setInterfaceSubmitBusy(false);
        }
    }

    async function editInterface(name) {
        try {
            const res = await api('GET', `/api/wireguard/interfaces/${encodeURIComponent(name)}/config`);
            const iface = res?.data || res;
            editingInterfaceName = iface.name || name;

            document.getElementById('ifaceModalTitle').textContent = `Edit Interface ${editingInterfaceName}`;
            document.getElementById('btn-iface-submit-label').textContent = 'Save Changes';

            const nameInput = document.getElementById('iface-name');
            nameInput.value = editingInterfaceName;
            nameInput.readOnly = true;

            document.getElementById('iface-address').value = iface.address || '';
            document.getElementById('iface-address6').value = iface.address6 || '';
            document.getElementById('iface-port').value = String(iface.listen_port || 51820);
            document.getElementById('iface-dns').value = iface.dns || '';

            // Show on Dashboard toggle
            const showOnDashboardToggle = document.getElementById('iface-show-on-dashboard');
            if (showOnDashboardToggle) {
                showOnDashboardToggle.checked = iface.show_on_dashboard !== false;
            }

            // Optional WireBuddy DNS toggle (may not exist in all versions)
            const serverIp = (iface.address || '').split('/')[0];
            const wbDnsToggle = document.getElementById('iface-use-wb-dns');
            const dnsInput = document.getElementById('iface-dns');
            const isWireBuddyDns = Boolean(iface.dns) && iface.dns === serverIp;
            if (wbDnsToggle) wbDnsToggle.checked = isWireBuddyDns;
            if (dnsInput) dnsInput.readOnly = isWireBuddyDns;

            const modalEl = document.getElementById('ifaceModal');
            const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
            modal.show();
        } catch (error) {
            wbToast('Failed to load interface config: ' + error.message, 'danger');
        }
    }

    async function updateInterface() {
        if (!editingInterfaceName) return;

        const address = document.getElementById('iface-address').value.trim();
        const address6 = document.getElementById('iface-address6').value.trim() || null;
        const port = document.getElementById('iface-port').value || 51820;
        const dns = document.getElementById('iface-dns').value.trim() || null;
        const showOnDashboardToggle = document.getElementById('iface-show-on-dashboard');
        const showOnDashboard = showOnDashboardToggle ? showOnDashboardToggle.checked : true;

        if (!address) {
            wbToast('Please fill in an IPv4 address', 'warning');
            return;
        }

        // Validate CIDR notation (octet range 0-255, mask 0-32)
        if (!isValidIPv4Cidr(address)) {
            wbToast('IPv4 address must be in CIDR format with valid octets and prefix (e.g. 10.13.13.1/24)', 'warning');
            return;
        }

        if (address6 && !isValidIPv6Cidr(address6)) {
            wbToast('IPv6 address must be valid CIDR notation (e.g. fd13:13:13::1/64)', 'warning');
            return;
        }

        setInterfaceSubmitBusy(true);
        try {
            const res = await api('PATCH', `/api/wireguard/interfaces/${encodeURIComponent(editingInterfaceName)}`, {
                address: address,
                address6: address6,
                listen_port: parseInt(port),
                dns: dns,
                show_on_dashboard: showOnDashboard
            });
            const payload = res?.data || res;

            const updatedName = editingInterfaceName;
            const needsRestart = payload?.restart_required;

            document.activeElement?.blur();
            bootstrap.Modal.getInstance(document.getElementById('ifaceModal')).hide();
            void prepareCreateInterfaceModal();

            if (needsRestart) {
                // Auto-restart in background if interface is active
                try {
                    await api('POST', `/api/wireguard/interfaces/${encodeURIComponent(updatedName)}/restart`);
                    wbToast(`Interface '${updatedName}' updated and restarted`, 'success');
                } catch (err) {
                    wbToast(`Interface '${updatedName}' updated`, 'success');
                    wbToast(`Failed to restart interface: ${err.message}`, 'danger');
                }
            } else {
                wbToast(`Interface '${updatedName}' updated`, 'success');
            }
            await refreshInterfaces();
        } catch (error) {
            wbToast('Failed to update interface: ' + error.message, 'danger');
        } finally {
            setInterfaceSubmitBusy(false);
        }
    }

    async function submitInterfaceForm() {
        if (editingInterfaceName) {
            await updateInterface();
            return;
        }
        await createInterface();
    }

    async function deleteInterface(name) {
        if (!await wbConfirm(`Delete interface '${name}'? This will remove the configuration file. Connected peers will lose connectivity.`, 'danger')) return;

        try {
            await api('DELETE', `/api/wireguard/interfaces/${encodeURIComponent(name)}`);
            wbToast(`Interface '${name}' deleted`, 'success');
            await refreshInterfaces();
            // Refresh DNS status (Unbound may have auto-stopped)
            await loadDnsServiceStatus();
        } catch (error) {
            wbToast('Failed to delete interface: ' + (error?.message || String(error)), 'danger');
        }
    }

    document.getElementById('ifaceModal')?.addEventListener('hidden.bs.modal', function () {
        setInterfaceSubmitBusy(false);
        void prepareCreateInterfaceModal();
    });

    document.getElementById('iface-use-frontend-port')?.addEventListener('change', function () {
        toggleFrontendPortField(this.checked);
    });

    // Interfaces are loaded by tab system (initTabs)

    // SSL/TLS Certificate management

    async function refreshCertificates() {
        try {
            const certs = await api('GET', '/api/acme/certificates');
            const guidanceEl = document.getElementById('letsencrypt-guidance');
            let html = '';

            for (const cert of certs) {
                const safeDomain = esc(cert.domain);
                const dataDomain = esc(cert.domain).replace(/"/g, '&quot;');
                const staging = !!cert.is_staging;
                const stagingBadge = staging ? '<span class="badge bg-warning text-dark ms-1">Staging</span>' : '';
                const isExpired = cert.days_until_expiry !== null && cert.days_until_expiry < 0;
                const needsRenewal = cert.needs_renewal && !isExpired;

                let statusBadge = '<span class="badge bg-success">Valid</span>';
                if (isExpired) {
                    statusBadge = '<span class="badge bg-danger">Expired</span>';
                } else if (needsRenewal) {
                    statusBadge = '<span class="badge bg-warning text-dark">Renew</span>';
                }

                const expiresDate = cert.expires_at ? new Date(cert.expires_at) : null;
                const expiresStr = expiresDate ? expiresDate.toLocaleDateString() : 'Unknown';
                const daysStr = cert.days_until_expiry !== null ? ` (${cert.days_until_expiry}d)` : '';

                html += `
                    <div class="d-flex justify-content-between align-items-center py-2 border-bottom">
                        <div>
                            <strong>${safeDomain}</strong>
                            ${statusBadge}${stagingBadge}
                            <br><small class="text-muted">Expires: ${expiresStr}${daysStr} • Issuer: ${esc(cert.issuer || 'Unknown')}</small>
                        </div>
                        <div class="d-flex gap-1">
                            ${needsRenewal ? `<button class="btn btn-sm btn-outline-warning cert-renew-btn" data-domain="${dataDomain}" data-staging="${staging}" title="Renew"><span class="material-icons" style="font-size: 18px;">refresh</span></button>` : ''}
                            <button class="btn btn-sm btn-outline-danger cert-delete-btn" data-domain="${dataDomain}" data-staging="${staging}" title="Delete">
                                <span class="material-icons" style="font-size: 18px;">delete</span>
                            </button>
                        </div>
                    </div>`;
            }

            if (!html) {
                html = '<p class="text-muted mb-0">No certificates found. Click + to request one.</p>';
            }

            if (guidanceEl) {
                guidanceEl.classList.toggle('d-none', certs.length > 0);
            }

            const listEl = document.getElementById('certificates-list');
            listEl.innerHTML = html;

            // Event delegation for certificate buttons
            listEl.removeEventListener('click', handleCertificateClick);
            listEl.addEventListener('click', handleCertificateClick);
        } catch (error) {
            const guidanceEl = document.getElementById('letsencrypt-guidance');
            if (guidanceEl) {
                guidanceEl.classList.remove('d-none');
            }
            document.getElementById('certificates-list').innerHTML = `<p class="text-danger mb-0">Failed to load certificates: ${esc(error.message)}</p>`;
        }
    }

    async function handleCertificateClick(e) {
        const renewBtn = e.target.closest('.cert-renew-btn');
        const deleteBtn = e.target.closest('.cert-delete-btn');

        if (renewBtn) {
            const domain = renewBtn.dataset.domain;
            const staging = renewBtn.dataset.staging === 'true';
            await renewCertificate(domain, staging);
        } else if (deleteBtn) {
            const domain = deleteBtn.dataset.domain;
            const staging = deleteBtn.dataset.staging === 'true';
            await deleteCertificate(domain, staging);
        }
    }

    async function requestCertificate() {
        const domain = document.getElementById('cert-domain').value.trim();
        const email = document.getElementById('cert-email').value.trim();
        const staging = document.getElementById('cert-staging').checked;

        if (!domain || !email) {
            wbToast('Please fill in all fields', 'warning');
            return;
        }

        const spinner = document.getElementById('cert-spinner');
        spinner.classList.remove('d-none');

        try {
            await api('POST', '/api/acme/certificates/request', {
                domain: domain,
                email: email,
                staging: staging
            });

            document.activeElement?.blur();
            bootstrap.Modal.getInstance(document.getElementById('certModal')).hide();
            document.getElementById('cert-form').reset();
            wbToast('Certificate issued successfully!', 'success');
            await refreshCertificates();
        } catch (error) {
            wbToast('Failed to request certificate: ' + error.message, 'danger');
        } finally {
            spinner.classList.add('d-none');
        }
    }

    async function deleteCertificate(domain, isStaging) {
        if (!await wbConfirm(`Delete certificate for ${domain}?`, 'danger')) return;

        try {
            await api('DELETE', `/api/acme/certificates/${encodeURIComponent(domain)}?staging=${isStaging}`);
            wbToast('Certificate deleted', 'success');
            await refreshCertificates();
        } catch (error) {
            wbToast('Failed to delete certificate: ' + error.message, 'danger');
        }
    }

    async function renewCertificate(domain, isStaging) {
        const email = await wbPrompt(`Enter email for renewal of ${domain}:`, 'admin@example.com');
        if (!email) return;

        try {
            wbToast('Requesting certificate renewal...', 'info');
            await api('POST', '/api/acme/certificates/request', {
                domain: domain,
                email: email,
                staging: isStaging
            });
            wbToast('Certificate renewed successfully!', 'success');
            await refreshCertificates();
        } catch (error) {
            wbToast('Failed to renew certificate: ' + error.message, 'danger');
        }
    }

    // DNS Blocklist management
    let blocklistSaveTimeout = null;
    let dnsConfigLoaded = false;
    let dnsConfigLastUpstream = [];
    let dnsConfigHydrating = false;
    let dnsConfigSaveTimeout = null;
    let dnsConfigSaving = false;
    let dnsConfigSavePending = false;
    let dnsConfigListenersBound = false;

    const DNS_RETENTION_VALUES = [0, 7, 30, 90, 180, 365];

    // Cache frequently accessed DOM elements for better performance
    const domCache = {
        dnsUpstream: null,
        dnssecToggle: null,
        dnssecStatus: null,
        init() {
            this.dnsUpstream = document.getElementById('dns-upstream-servers');
            this.dnssecToggle = document.getElementById('dnssec-enabled');
            this.dnssecStatus = document.getElementById('dnssec-status');
        }
    };

    async function loadBlocklistSources() {
        try {
            const [res, status] = await Promise.all([
                api('GET', '/api/dns/blocklist/sources'),
                api('GET', '/api/dns/status'),
            ]);
            // DNS unavailable (Unbound not installed) - disable all blocklist controls
            const dnsUnavailable = status?.unavailable || false;
            const rebuildInProgress = res.rebuild_in_progress || false;
            // Level priority: Moderate → Balanced → Extreme! → 18+
            const levelPriority = { 'Moderat': 1, 'Ausgewogen': 2, 'Extrem': 3, '18+': 4 };
            const sortedSources = [...(res.sources || [])].sort((a, b) => {
                const aEnabled = !!a?.enabled;
                const bEnabled = !!b?.enabled;
                if (aEnabled !== bEnabled) return aEnabled ? -1 : 1;

                // Sort by level priority (intensity)
                const aLevel = levelPriority[a?.level] ?? 99;
                const bLevel = levelPriority[b?.level] ?? 99;
                if (aLevel !== bLevel) return aLevel - bLevel;

                const aName = String(a?.name || '').trim();
                const bName = String(b?.name || '').trim();
                return aName.localeCompare(bName, undefined, { sensitivity: 'base' });
            });
            let html = '';
            for (let i = 0; i < sortedSources.length; i++) {
                const source = sortedSources[i];
                const checked = source.enabled ? 'checked' : '';
                const domainsValue = source.domains;
                // Show "Pending" for enabled blocklists with 0 domains during rebuild
                const isPending = source.enabled && rebuildInProgress && Number(domainsValue) === 0;
                const domains = isPending
                    ? 'Pending'
                    : (Number.isFinite(Number(domainsValue))
                        ? Number(domainsValue).toLocaleString()
                        : (String(domainsValue ?? '').trim() || '—'));
                const updated = source.last_updated || '—';
                const level = source.level || '';
                const levelBadgeLabel = {
                    'Moderat': 'Moderate',
                    'Ausgewogen': 'Balanced',
                    'Extrem': '🔥Extreme',
                    '18+': '❤️ 18+',
                }[level] || (level ? esc(level) : '');
                const levelBadgeIcon = '';
                const levelBadge = levelBadgeLabel
                    ? `<span class="badge text-bg-secondary blocklist-level-badge">${levelBadgeIcon}${levelBadgeLabel}</span>`
                    : '';
                // Use hash + index to prevent ID collisions
                const sourceId = `blocklist-${simpleHash(source.url)}-${i}`;
                const dataUrl = esc(source.url).replace(/"/g, '&quot;');
                html += `
                    <article class="blocklist-item${source.enabled ? ' enabled' : ''}">
                        <div class="blocklist-row">
                            <div class="flex-grow-1">
                                <label class="blocklist-title" for="${sourceId}">
                                    <span>${esc(source.name)}</span>
                                    ${levelBadge}
                                </label>
                                <div class="blocklist-desc">${esc(source.description)}</div>
                                <div class="blocklist-meta">
                                    <span class="blocklist-meta-mono">${domains} domains</span>
                                    <span class="blocklist-meta-separator" aria-hidden="true">·</span>
                                    <span class="blocklist-meta-mono">Updated ${updated}</span>
                                </div>
                            </div>
                            <div class="form-check form-switch m-0">
                                <input class="form-check-input" type="checkbox" id="${sourceId}"
                                    data-url="${dataUrl}" data-name="${esc(source.name)}" ${checked}${(isAdmin && !dnsUnavailable) ? '' : ' disabled'}>
                            </div>
                        </div>
                    </article>`;
            }
            const container = document.getElementById('blocklist-sources');
            // Disable transitions during initial render to prevent toggle animation
            container.classList.add('no-transitions');
            container.innerHTML =
                html || '<div class="text-muted text-center py-3">No blocklist sources available</div>';
            bindBlocklistSourceListeners();
            // Re-enable transitions after render completes
            requestAnimationFrame(() => {
                container.classList.remove('no-transitions');
            });
            
            // DNS unavailable - disable all DNS filtering controls
            const updateBlocklistBtn = document.getElementById('btn-update-blocklist');
            const saveCustomRulesBtn = document.getElementById('save-custom-rules-btn');
            const customRulesInput = document.getElementById('custom-rules-input');
            if (dnsUnavailable) {
                if (updateBlocklistBtn) {
                    updateBlocklistBtn.disabled = true;
                    updateBlocklistBtn.title = 'Unbound not installed';
                }
                if (saveCustomRulesBtn) {
                    saveCustomRulesBtn.disabled = true;
                    saveCustomRulesBtn.title = 'Unbound not installed';
                }
                if (customRulesInput) {
                    customRulesInput.disabled = true;
                    customRulesInput.title = 'Unbound not installed';
                }
            } else {
                // Re-enable controls (respecting admin check)
                if (updateBlocklistBtn) updateBlocklistBtn.disabled = !isAdmin;
                if (saveCustomRulesBtn) saveCustomRulesBtn.disabled = !isAdmin;
                if (customRulesInput && isAdmin) customRulesInput.disabled = false;
            }
            
            const updEl = document.getElementById('blocklist-last-update');
            const updValueEl = updEl?.querySelector('.blocklist-last-value');
            if (updEl) {
                if (status?.blocklist_updated_at) {
                    const d = new Date(status.blocklist_updated_at);
                    const value = d.toLocaleString();
                    if (updValueEl) {
                        updValueEl.textContent = value;
                    } else {
                        updEl.textContent = value;
                    }
                } else if (updValueEl) {
                    updValueEl.textContent = '–';
                } else {
                    updEl.textContent = '–';
                }
            }

            // Auto-poll while rebuild is in progress so "Pending" badges update
            if (rebuildInProgress) {
                scheduleRebuildPoll();
            } else {
                cancelRebuildPoll();
            }
        } catch (error) {
            document.getElementById('blocklist-sources').innerHTML =
                `<div class="text-danger py-2">Failed to load blocklists: ${error.message}</div>`;
            const updEl = document.getElementById('blocklist-last-update');
            const updValueEl = updEl?.querySelector('.blocklist-last-value');
            if (updValueEl) {
                updValueEl.textContent = '–';
            } else if (updEl) {
                updEl.textContent = '–';
            }
        }
    }

    // Rebuild polling: re-check blocklist sources while rebuild is in progress
    let _rebuildPollTimer = null;
    let _rebuildPollCount = 0;
    const _REBUILD_POLL_INTERVAL = 5000;   // 5 seconds
    const _REBUILD_POLL_MAX = 24;          // max 2 minutes

    function scheduleRebuildPoll() {
        if (_rebuildPollTimer) return; // already polling
        _rebuildPollCount = 0;
        _rebuildPollTimer = setInterval(async () => {
            _rebuildPollCount++;
            if (_rebuildPollCount >= _REBUILD_POLL_MAX) {
                cancelRebuildPoll();
                return;
            }
            await loadBlocklistSources();
        }, _REBUILD_POLL_INTERVAL);
    }

    function cancelRebuildPoll() {
        if (_rebuildPollTimer) {
            clearInterval(_rebuildPollTimer);
            _rebuildPollTimer = null;
        }
        _rebuildPollCount = 0;
    }

    // Track last toggled blocklist for better toast messages
    let lastToggledBlocklist = null;
    let _blocklistSaving = false;
    let _blocklistSavePending = false;

    function bindBlocklistSourceListeners() {
        document.querySelectorAll('#blocklist-sources input[type="checkbox"][data-url]').forEach(cb => {
            cb.addEventListener('change', () => {
                lastToggledBlocklist = {
                    name: cb.dataset.name || 'Blocklist',
                    enabled: cb.checked,
                };
                toggleBlocklistCardState(cb);
                saveBlocklistsDebounced();
            });
        });
    }

    function toggleBlocklistCardState(checkboxEl) {
        const card = checkboxEl?.closest('.blocklist-item');
        if (!card) return;
        card.classList.toggle('enabled', !!checkboxEl.checked);
    }

    function saveBlocklistsDebounced() {
        // Debounce to avoid spamming when clicking multiple checkboxes quickly
        clearTimeout(blocklistSaveTimeout);
        blocklistSaveTimeout = setTimeout(saveBlocklists, 500);
    }

    async function saveBlocklists() {
        // Re-entrancy guard: if a save is already in-flight, queue another
        if (_blocklistSaving) {
            _blocklistSavePending = true;
            return;
        }
        _blocklistSaving = true;

        const checkboxes = document.querySelectorAll('#blocklist-sources input[type="checkbox"]');
        const enabledUrls = Array.from(checkboxes)
            .filter(cb => cb.checked)
            .map(cb => cb.dataset.url);

        // Capture toggle info before async call (may be cleared by subsequent toggle)
        const toggleInfo = lastToggledBlocklist;
        lastToggledBlocklist = null;

        try {
            const res = await api('POST', '/api/dns/blocklist/sources', {
                urls: enabledUrls,
            });
            // Show specific message for toggle, generic for other updates
            const msg = toggleInfo
                ? `Blocklist '${toggleInfo.name}' ${toggleInfo.enabled ? 'enabled' : 'disabled'}`
                : (res?.message || 'Blocklist update started');
            wbToast(msg, 'success');
            // Refresh after a short delay to show updated state
            setTimeout(() => loadBlocklistSources(), 2000);
        } catch (error) {
            wbToast('Failed to save blocklists: ' + error.message, 'danger');
        } finally {
            _blocklistSaving = false;
            if (_blocklistSavePending) {
                _blocklistSavePending = false;
                setTimeout(() => saveBlocklists(), 50);
            }
        }
    }

    async function updateBlocklist() {
        try {
            const res = await api('POST', '/api/dns/blocklist/update');
            wbToast(res?.message || 'Blocklist update started', 'success');
            // Refresh after a short delay, then continue polling
            setTimeout(() => loadBlocklistSources(), 2000);
        } catch (e) {
            wbToast('Update failed: ' + e.message, 'danger');
        }
    }

    function dnsRetentionLabel(days) {
        const n = Number(days);
        if (n === 0) return 'No Logs';
        if (n === 365) return '1 Year';
        return `${n} Days`;
    }

    function dnsRetentionIndexForDays(days) {
        const idx = DNS_RETENTION_VALUES.indexOf(Number(days));
        return idx >= 0 ? idx : 2; // default: 30 days
    }

    function dnsRetentionDaysFromSlider(rawValue) {
        const parsed = Number.parseInt(String(rawValue), 10);
        const idx = Number.isFinite(parsed)
            ? Math.max(0, Math.min(DNS_RETENTION_VALUES.length - 1, parsed))
            : 2;
        return DNS_RETENTION_VALUES[idx];
    }

    function updateDnsRetentionPreview(rawValue) {
        const days = dnsRetentionDaysFromSlider(rawValue);
        const labelEl = document.getElementById('dns-retention-value');
        if (labelEl) {
            labelEl.textContent = dnsRetentionLabel(days);
            // Visual warning when logging is disabled
            labelEl.className = days === 0
                ? 'badge text-bg-danger'
                : 'badge text-bg-secondary';
        }
        return days;
    }

    function getSelectedDnsRetention() {
        const slider = document.getElementById('dns-retention-slider');
        return dnsRetentionDaysFromSlider(slider?.value ?? 2);
    }

    function parseDnsUpstreamInput(raw) {
        return (raw || '')
            .split(/[,\n]+/)
            .map(v => v.trim())
            .filter(Boolean);
    }

    // DNS server format regex: IP@port#hostname
    const DNS_FORMAT_RE = /^([^@#]+)(?:@(\d+))?(?:#(.+))?$/;

    function validateDnsServerSyntax(server) {
        const match = DNS_FORMAT_RE.exec(server.trim());
        if (!match) return { valid: false, error: 'Invalid format' };

        const ip = match[1]?.trim();
        const port = match[2] ? parseInt(match[2], 10) : 853;
        const hostname = match[3]?.trim();

        // IPv4 validation with range checks
        const ipv4Re = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        const ipv4Match = ipv4Re.exec(ip);
        if (ipv4Match) {
            // Check each octet is 0-255
            for (let i = 1; i <= 4; i++) {
                const octet = parseInt(ipv4Match[i], 10);
                if (octet < 0 || octet > 255) {
                    return { valid: false, error: `Invalid IPv4 octet: ${octet}` };
                }
            }
        } else {
            // IPv6 validation (stricter - must have at least one colon and valid hex groups)
            const ipv6Re = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
            if (!ipv6Re.test(ip)) {
                return { valid: false, error: `Invalid IP address: ${ip}` };
            }
        }

        if (port < 1 || port > 65535) {
            return { valid: false, error: `Invalid port: ${port}` };
        }

        if (!hostname) {
            return { valid: false, error: 'Hostname required for DoT' };
        }

        return { valid: true };
    }

    async function validateDnsServers() {
        const btn = document.getElementById('validate-dns-btn');
        const statusEl = document.getElementById('dns-validation-status');
        const upstreamInput = document.getElementById('dns-upstream-servers');

        if (!upstreamInput) return;

        const servers = parseDnsUpstreamInput(upstreamInput.value);

        if (servers.length === 0) {
            wbToast('No DNS servers entered', 'warning');
            return;
        }

        // First: Client-side syntax validation
        const syntaxErrors = [];
        for (const server of servers) {
            const result = validateDnsServerSyntax(server);
            if (!result.valid) {
                syntaxErrors.push(`${server}: ${result.error}`);
            }
        }

        if (syntaxErrors.length > 0) {
            wbToast('Syntax errors:\n' + syntaxErrors.join('\n'), 'danger');
            return;
        }

        // Second: Backend connectivity test
        btn.disabled = true;
        statusEl.innerHTML = '<span class="spinner-border spinner-border-sm align-middle me-1"></span>Testing servers...';
        statusEl.className = 'small text-muted';

        try {
            const res = await api('POST', '/api/dns/test-upstream', { servers });

            if (res.all_success) {
                statusEl.innerHTML = '<span class="material-icons align-middle text-success" style="font-size:16px;">check_circle</span> All servers validated';
                statusEl.className = 'small text-success';
                wbToast(`All ${res.results.length} DNS servers are reachable`, 'success');
            } else {
                const failedServers = res.results
                    .filter(r => !r.success)
                    .map(r => `${r.server}: ${r.error}`)
                    .join('\n');

                statusEl.innerHTML = `<span class="material-icons align-middle text-danger" style="font-size:16px;">error</span> ${res.failed_count} server(s) failed`;
                statusEl.className = 'small text-danger';
                wbToast('DNS server validation failed:\n' + failedServers, 'danger');
            }
        } catch (error) {
            statusEl.innerHTML = '<span class="material-icons align-middle text-danger" style="font-size:16px;">error</span> Test failed';
            statusEl.className = 'small text-danger';
            wbToast('DNS validation error: ' + error.message, 'danger');
        } finally {
            btn.disabled = false;
        }
    }

    function setDnssecStatusText(data) {
        const dnssecStatus = domCache.dnssecStatus || document.getElementById('dnssec-status');
        if (!dnssecStatus) return;
        if (data?.dnssec_available) {
            dnssecStatus.textContent = data?.dnssec_active
                ? 'DNSSEC active (root key available)'
                : 'DNSSEC disabled (root key available)';
        } else {
            dnssecStatus.textContent = data?.dnssec_enabled
                ? 'DNSSEC configured but unavailable (root key missing on system)'
                : 'DNSSEC unavailable (root key missing on system)';
        }
    }

    function bindDnsConfigListeners() {
        if (dnsConfigListenersBound) return;
        // Initialize DOM cache when binding listeners
        if (!domCache.dnsUpstream) domCache.init();
        const upstreamInput = domCache.dnsUpstream;
        const dnssecToggle = domCache.dnssecToggle;
        if (!upstreamInput || !dnssecToggle) return;

        upstreamInput.addEventListener('change', function () {
            if (dnsConfigHydrating) return;
            saveDnsConfigDebounced();
        });
        dnssecToggle.addEventListener('change', async function () {
            if (dnsConfigHydrating) return;
            await saveDnsConfig();
        });
        dnsConfigListenersBound = true;
    }

    function saveDnsConfigDebounced() {
        clearTimeout(dnsConfigSaveTimeout);
        dnsConfigSaveTimeout = setTimeout(() => {
            saveDnsConfig();
        }, 500);
    }

    async function loadDnsConfig() {
        try {
            dnsConfigHydrating = true;
            const res = await api('GET', '/api/dns/config');
            const upstream = Array.isArray(res.upstream_dns) ? res.upstream_dns : [];
            const upstreamInput = document.getElementById('dns-upstream-servers');
            if (upstreamInput) upstreamInput.value = upstream.join('\n');

            dnsConfigLastUpstream = upstream.slice();

            const dnssecToggle = document.getElementById('dnssec-enabled');
            if (dnssecToggle) {
                dnssecToggle.checked = !!res.dnssec_active;
                dnssecToggle.disabled = !isAdmin || !res.dnssec_available;
            }
            setDnssecStatusText(res);

            dnsConfigLoaded = true;
        } catch (error) {
            const dnssecStatus = document.getElementById('dnssec-status');
            if (dnssecStatus) dnssecStatus.textContent = 'Failed to load DNS settings';
        } finally {
            dnsConfigHydrating = false;
        }
    }

    async function saveDnsConfig() {
        if (dnsConfigHydrating) return;
        if (dnsConfigSaving) {
            dnsConfigSavePending = true;
            return;
        }
        if (!dnsConfigLoaded) {
            await loadDnsConfig();
            if (!dnsConfigLoaded) return;
        }

        dnsConfigSaving = true;

        try {
            const upstreamInput = document.getElementById('dns-upstream-servers');
            const dnssecToggle = document.getElementById('dnssec-enabled');
            const servers = parseDnsUpstreamInput(upstreamInput?.value || '');

            // Check if upstream servers changed
            const upstreamChanged = JSON.stringify(servers) !== JSON.stringify(dnsConfigLastUpstream);

            // Validate DNS servers before saving (only if they changed and any are specified)
            if (upstreamChanged && servers.length > 0) {
                // Syntax validation
                const syntaxErrors = [];
                for (const server of servers) {
                    const result = validateDnsServerSyntax(server);
                    if (!result.valid) {
                        syntaxErrors.push(`${server}: ${result.error}`);
                    }
                }
                if (syntaxErrors.length > 0) {
                    wbToast('DNS syntax errors:\n' + syntaxErrors.join('\n'), 'danger');
                    return;
                }

                // Connectivity test
                const statusEl = document.getElementById('dns-validation-status');
                if (statusEl) {
                    statusEl.innerHTML = '<span class="spinner-border spinner-border-sm align-middle me-1"></span>Validating...';
                    statusEl.className = 'small text-muted';
                }

                try {
                    const testRes = await api('POST', '/api/dns/test-upstream', { servers });
                    if (!testRes.all_success) {
                        const failedServers = testRes.results
                            .filter(r => !r.success)
                            .map(r => `${r.server}: ${r.error}`)
                            .join('\n');
                        if (statusEl) {
                            statusEl.innerHTML = `<span class="material-icons align-middle text-danger" style="font-size:16px;">error</span> ${testRes.failed_count} failed`;
                            statusEl.className = 'small text-danger';
                        }
                        wbToast('DNS validation failed - settings not saved:\n' + failedServers, 'danger');
                        return;
                    }
                    if (statusEl) {
                        statusEl.innerHTML = '<span class="material-icons align-middle text-success" style="font-size:16px;">check_circle</span> Validated';
                        statusEl.className = 'small text-success';
                    }
                } catch (error) {
                    if (statusEl) {
                        statusEl.innerHTML = '<span class="material-icons align-middle text-danger" style="font-size:16px;">error</span> Test failed';
                        statusEl.className = 'small text-danger';
                    }
                    wbToast('DNS validation error: ' + error.message, 'danger');
                    return;
                }
            }

            const payload = {
                upstream_dns: servers,
                dnssec_enabled: !!dnssecToggle?.checked,
            };

            const res = await api('POST', '/api/dns/config', payload);
            dnsConfigLastUpstream = servers.slice();

            // Use existing dnssecToggle reference (no shadowing)
            if (dnssecToggle) {
                dnssecToggle.checked = !!res?.dnssec_active;
                dnssecToggle.disabled = !res?.dnssec_available;
            }
            setDnssecStatusText(res);

            wbToast('DNS settings saved', 'success');
        } catch (error) {
            wbToast('Failed to save DNS settings: ' + error.message, 'danger');
        } finally {
            dnsConfigSaving = false;
            // Retry pattern: ensure all pending saves are processed
            if (dnsConfigSavePending) {
                dnsConfigSavePending = false;
                // Use setTimeout to avoid recursive call stack buildup
                setTimeout(() => saveDnsConfig(), 50);
            }
        }
    }

    // Load blocklists (called by tab system)
    // Removed automatic loading - now handled by initTabs()

    /* ── Metrics Stats & Retention ─────────────────────────── */

    function formatBytes(size) {
        const n = Number(size) || 0;
        if (n >= 1024 * 1024 * 1024) return (n / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
        if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(2) + ' MB';
        if (n >= 1024) return (n / 1024).toFixed(1) + ' KB';
        return n + ' B';
    }

    function setMetricPath(elementId, rawValue) {
        const el = document.getElementById(elementId);
        if (!el) return;
        const value = rawValue || '–';
        el.textContent = value;
        if (value === '–') {
            el.removeAttribute('title');
            el.removeAttribute('aria-label');
            return;
        }
        el.title = value;
        el.setAttribute('aria-label', value);
    }

    // TSDB retention slider values (includes 0 for "No Logs")
    const TSDB_RETENTION_VALUES = [0, 7, 30, 90, 180, 365];

    function tsdbRetentionLabel(days) {
        const n = Number(days);
        if (n === 0) return 'No Logs';
        if (n === 365) return '1 Year';
        return `${n} Days`;
    }

    function tsdbRetentionIndexForDays(days) {
        const idx = TSDB_RETENTION_VALUES.indexOf(Number(days));
        return idx >= 0 ? idx : 5; // default: 365 days
    }

    function tsdbRetentionDaysFromSlider(rawValue) {
        const parsed = Number.parseInt(String(rawValue), 10);
        const idx = Number.isFinite(parsed)
            ? Math.max(0, Math.min(TSDB_RETENTION_VALUES.length - 1, parsed))
            : 5;
        return TSDB_RETENTION_VALUES[idx];
    }

    function updateTsdbRetentionPreview(rawValue) {
        const days = tsdbRetentionDaysFromSlider(rawValue);
        const labelEl = document.getElementById('tsdb-retention-value');
        if (labelEl) {
            labelEl.textContent = tsdbRetentionLabel(days);
            // Visual warning when logging is disabled
            labelEl.className = days === 0
                ? 'badge text-bg-danger'
                : 'badge text-bg-secondary';
        }
        return days;
    }

    // DNS metrics retention slider (mirrors DNS_RETENTION_VALUES)
    const DNS_METRICS_RETENTION_VALUES = [0, 7, 30, 90, 180, 365];

    function dnsMetricsRetentionLabel(days) {
        const n = Number(days);
        if (n === 0) return 'No Logs';
        if (n === 365) return '1 Year';
        return `${n} Days`;
    }

    function dnsMetricsRetentionIndexForDays(days) {
        const idx = DNS_METRICS_RETENTION_VALUES.indexOf(Number(days));
        return idx >= 0 ? idx : 2; // default: 30 days
    }

    function dnsMetricsRetentionDaysFromSlider(rawValue) {
        const parsed = Number.parseInt(String(rawValue), 10);
        const idx = Number.isFinite(parsed)
            ? Math.max(0, Math.min(DNS_METRICS_RETENTION_VALUES.length - 1, parsed))
            : 2;
        return DNS_METRICS_RETENTION_VALUES[idx];
    }

    function updateDnsMetricsRetentionPreview(rawValue) {
        const days = dnsMetricsRetentionDaysFromSlider(rawValue);
        const labelEl = document.getElementById('dns-metrics-retention-value');
        if (labelEl) {
            labelEl.textContent = dnsMetricsRetentionLabel(days);
            labelEl.className = days === 0
                ? 'badge text-bg-danger'
                : 'badge text-bg-secondary';
        }
        return days;
    }

    // Speedtest retention slider (same values as TSDB but default 365 days)
    const SPEEDTEST_RETENTION_VALUES = [0, 7, 30, 90, 180, 365];

    function speedtestRetentionLabel(days) {
        const n = Number(days);
        if (n === 0) return 'No Logs';
        if (n === 365) return '1 Year';
        return `${n} Days`;
    }

    function speedtestRetentionIndexForDays(days) {
        const idx = SPEEDTEST_RETENTION_VALUES.indexOf(Number(days));
        return idx >= 0 ? idx : 5; // default: 365 days
    }

    function speedtestRetentionDaysFromSlider(rawValue) {
        const parsed = Number.parseInt(String(rawValue), 10);
        const idx = Number.isFinite(parsed)
            ? Math.max(0, Math.min(SPEEDTEST_RETENTION_VALUES.length - 1, parsed))
            : 5;
        return SPEEDTEST_RETENTION_VALUES[idx];
    }

    function updateSpeedtestRetentionPreview(rawValue) {
        const days = speedtestRetentionDaysFromSlider(rawValue);
        const labelEl = document.getElementById('speedtest-retention-value');
        if (labelEl) {
            labelEl.textContent = speedtestRetentionLabel(days);
            labelEl.className = days === 0
                ? 'badge text-bg-danger'
                : 'badge text-bg-secondary';
        }
        return days;
    }

    let _tsdbRetentionSaving = false;
    let _dnsMetricsRetentionSaving = false;
    let _speedtestRetentionSaving = false;

    async function loadTsdbStats() {
        try {
            const stats = await api('GET', '/api/wireguard/stats/tsdb');

            const size = stats.size_bytes || 0;
            const compressedSize = stats.compressed_size_bytes || 0;
            const archiveCount = stats.archive_count || 0;

            setMetricPath('tsdb-path', stats.path);

            document.getElementById('tsdb-size').textContent = formatBytes(size);
            document.getElementById('tsdb-peers').textContent = stats.peer_count || 0;
            document.getElementById('tsdb-files').textContent = stats.file_count || 0;
            document.getElementById('tsdb-archives').textContent =
                `${archiveCount} (${formatBytes(compressedSize)})`;

            // Set retention slider
            const slider = document.getElementById('tsdb-retention-slider');
            if (slider && stats.retention_days != null) {
                slider.value = String(tsdbRetentionIndexForDays(stats.retention_days));
                updateTsdbRetentionPreview(slider.value);
            }
        } catch (e) {
            console.error('Failed to load TSDB stats:', e);
        }
    }

    async function loadDnsMetricsStats() {
        try {
            const stats = await api('GET', '/api/dns/storage');

            setMetricPath('dns-metrics-path', stats.path);

            const sizeEl = document.getElementById('dns-metrics-size');
            if (sizeEl) sizeEl.textContent = formatBytes(stats.size_bytes || 0);

            const filesEl = document.getElementById('dns-metrics-files');
            if (filesEl) filesEl.textContent = stats.file_count || 0;

            // Set retention slider
            const slider = document.getElementById('dns-metrics-retention-slider');
            if (slider && stats.retention_days != null) {
                slider.value = String(dnsMetricsRetentionIndexForDays(stats.retention_days));
                updateDnsMetricsRetentionPreview(slider.value);
            }
        } catch (e) {
            console.error('Failed to load DNS metrics stats:', e);
        }
    }

    async function loadPeerMetricsStats() {
        try {
            const stats = await api('GET', '/api/wireguard/stats/peer-metrics');

            setMetricPath('peer-metrics-path', stats.full_path || stats.path);

            const sizeEl = document.getElementById('peer-metrics-size');
            if (sizeEl) sizeEl.textContent = formatBytes(stats.size_bytes || 0);

            const totalEl = document.getElementById('peer-metrics-total');
            if (totalEl) totalEl.textContent = stats.total_peers || 0;

            const hsEl = document.getElementById('peer-metrics-handshake');
            if (hsEl) hsEl.textContent = stats.peers_with_handshake || 0;
        } catch (e) {
            console.error('Failed to load peer metrics stats:', e);
        }
    }

    async function loadSpeedtestStats() {
        try {
            const stats = await api('GET', '/api/wireguard/speedtest/storage');

            setMetricPath('speedtest-metrics-path', stats.path);

            const sizeEl = document.getElementById('speedtest-metrics-size');
            if (sizeEl) sizeEl.textContent = formatBytes(stats.size_bytes || 0);

            const recordsEl = document.getElementById('speedtest-metrics-records');
            if (recordsEl) recordsEl.textContent = stats.record_count || 0;

            // Set retention slider (admin only)
            const slider = document.getElementById('speedtest-retention-slider');
            if (slider && stats.retention_days != null) {
                slider.value = String(speedtestRetentionIndexForDays(stats.retention_days));
                updateSpeedtestRetentionPreview(slider.value);
            }
        } catch (e) {
            console.error('Failed to load speedtest stats:', e);
        }
    }

    async function saveTsdbRetention() {
        if (_tsdbRetentionSaving) return;
        _tsdbRetentionSaving = true;
        const slider = document.getElementById('tsdb-retention-slider');
        const days = tsdbRetentionDaysFromSlider(slider?.value ?? 5);

        if (days === 0) {
            const ok = await wbConfirm(
                '"No Logs" disables traffic logging and deletes existing data. Dashboard charts will show "Logging disabled". Continue?',
                'warning'
            );
            if (!ok) {
                // Revert slider
                loadTsdbStats();
                _tsdbRetentionSaving = false;
                return;
            }
        }

        try {
            await api('PATCH', '/api/wireguard/stats/tsdb/retention', { retention_days: days });
            wbToast(`Traffic retention set to ${tsdbRetentionLabel(days)}`, 'success');
        } catch (e) {
            wbToast('Failed to update traffic retention: ' + e.message, 'danger');
        } finally {
            _tsdbRetentionSaving = false;
        }
    }

    async function saveDnsMetricsRetention() {
        if (_dnsMetricsRetentionSaving) return;
        _dnsMetricsRetentionSaving = true;
        const slider = document.getElementById('dns-metrics-retention-slider');
        const days = dnsMetricsRetentionDaysFromSlider(slider?.value ?? 2);

        if (days === 0) {
            const ok = await wbConfirm(
                '"No Logs" disables DNS logging and deletes existing DNS data. Continue?',
                'warning'
            );
            if (!ok) {
                // Revert slider
                loadDnsMetricsStats();
                _dnsMetricsRetentionSaving = false;
                return;
            }
        }

        try {
            await api('POST', '/api/dns/config', { log_retention_days: days });
            wbToast(`DNS retention set to ${dnsMetricsRetentionLabel(days)}`, 'success');
        } catch (e) {
            wbToast('Failed to update DNS retention: ' + e.message, 'danger');
        } finally {
            _dnsMetricsRetentionSaving = false;
        }
    }

    async function saveSpeedtestRetention() {
        if (_speedtestRetentionSaving) return;
        _speedtestRetentionSaving = true;
        const slider = document.getElementById('speedtest-retention-slider');
        const days = speedtestRetentionDaysFromSlider(slider?.value ?? 5);

        if (days === 0) {
            const ok = await wbConfirm(
                '"No Logs" disables speedtest logging and deletes existing data. Bandwidth history chart will be empty. Continue?',
                'warning'
            );
            if (!ok) {
                // Revert slider
                loadSpeedtestStats();
                _speedtestRetentionSaving = false;
                return;
            }
        }

        try {
            await api('PATCH', '/api/wireguard/speedtest/storage/retention', { retention_days: days });
            wbToast(`Speedtest retention set to ${speedtestRetentionLabel(days)}`, 'success');
        } catch (e) {
            wbToast('Failed to update speedtest retention: ' + e.message, 'danger');
        } finally {
            _speedtestRetentionSaving = false;
        }
    }

    // Bind retention slider listeners
    (function bindMetricsRetentionListeners() {
        const tsdbSlider = document.getElementById('tsdb-retention-slider');
        if (tsdbSlider) {
            tsdbSlider.addEventListener('input', function () {
                updateTsdbRetentionPreview(this.value);
            });
            tsdbSlider.addEventListener('change', function () {
                saveTsdbRetention();
            });
        }

        const dnsSlider = document.getElementById('dns-metrics-retention-slider');
        if (dnsSlider) {
            dnsSlider.addEventListener('input', function () {
                updateDnsMetricsRetentionPreview(this.value);
            });
            dnsSlider.addEventListener('change', function () {
                saveDnsMetricsRetention();
            });
        }

        const speedtestSlider = document.getElementById('speedtest-retention-slider');
        if (speedtestSlider) {
            speedtestSlider.addEventListener('input', function () {
                updateSpeedtestRetentionPreview(this.value);
            });
            speedtestSlider.addEventListener('change', function () {
                saveSpeedtestRetention();
            });
        }
    })();

    async function purgeTrafficLogs() {
        if (!await wbConfirm('Delete all traffic metric data? This cannot be undone.', 'danger')) return;

        try {
            const res = await api('DELETE', '/api/wireguard/stats/tsdb');
            wbToast(res.message || 'Traffic metrics deleted', 'success');
            loadTsdbStats();
        } catch (e) {
            wbToast('Failed to delete traffic metrics: ' + e.message, 'danger');
        }
    }

    async function purgeDnsLogs() {
        if (!await wbConfirm('Delete all DNS query data? This cannot be undone.', 'danger')) return;

        try {
            const res = await api('DELETE', '/api/dns/logs');
            wbToast(res.message || 'DNS metrics deleted', 'success');
            loadDnsMetricsStats();
        } catch (e) {
            wbToast('Failed to delete DNS metrics: ' + e.message, 'danger');
        }
    }

    async function purgePeerLogs() {
        if (!await wbConfirm('Reset all peer connection tracking data? This cannot be undone.', 'danger')) return;

        try {
            const res = await api('DELETE', '/api/wireguard/stats/peer-logs');
            wbToast(res.message || 'Peer metrics reset', 'success');
            loadPeerMetricsStats();
        } catch (e) {
            wbToast('Failed to reset peer metrics: ' + e.message, 'danger');
        }
    }

    async function purgeSpeedtestLogs() {
        if (!await wbConfirm('Delete all speedtest data? Bandwidth history chart will be empty. This cannot be undone.', 'danger')) return;

        try {
            const res = await api('DELETE', '/api/wireguard/speedtest/storage');
            wbToast(res.message || 'Speedtest data deleted', 'success');
            loadSpeedtestStats();
            // Notify dashboard to refresh speedtest chart
            document.dispatchEvent(new CustomEvent('speedtest-completed'));
        } catch (e) {
            const errorMsg = e?.message || String(e);
            wbToast('Failed to delete speedtest data: ' + errorMsg, 'danger');
        }
    }

    /* ── Custom DNS Rules ──────────────────────────────────── */

    async function loadCustomRules() {
        try {
            const res = await api('GET', '/api/dns/custom-rules');
            const data = res.data || res;
            const input = document.getElementById('custom-rules-input');
            if (input) {
                const rulesText = typeof data.rules === 'string' ? data.rules : '';
                input.value = rulesText.trim() ? rulesText : '';
            }
            updateCustomRulesCount(data.rule_count || 0);
            showCustomRulesErrors(data.errors || []);
        } catch (e) {
            // Silently ignore — custom rules are optional
        }
    }

    function updateCustomRulesCount(count) {
        const badge = document.getElementById('custom-rules-count');
        if (badge) badge.textContent = count === 1 ? '1 rule' : `${count} rules`;
    }

    function showCustomRulesErrors(errors) {
        const container = document.getElementById('custom-rules-errors');
        if (!container) return;
        if (!errors || errors.length === 0) {
            container.style.display = 'none';
            container.replaceChildren();
            return;
        }
        container.style.display = 'block';
        container.replaceChildren();

        errors.slice(0, 5).forEach(e => {
            const div = document.createElement('div');
            div.className = 'text-danger small';

            const icon = document.createElement('span');
            icon.className = 'material-icons align-middle me-1';
            icon.style.fontSize = '14px';
            icon.textContent = 'error';

            div.appendChild(icon);
            div.appendChild(document.createTextNode(`Line ${e?.line ?? '–'}: ${e?.error ?? 'Unknown error'}`));
            container.appendChild(div);
        });

        if (errors.length > 5) {
            const extra = document.createElement('div');
            extra.className = 'text-muted small';
            extra.textContent = `… and ${errors.length - 5} more errors`;
            container.appendChild(extra);
        }
    }

    async function saveCustomRules() {
        const input = document.getElementById('custom-rules-input');
        const btn = document.getElementById('save-custom-rules-btn');
        const statusEl = document.getElementById('custom-rules-status');
        if (!input) return;

        const rules = input.value;
        if (btn) btn.disabled = true;
        if (statusEl) {
            statusEl.innerHTML = '';
            statusEl.className = 'small text-muted';
        }

        try {
            const res = await api('PATCH', '/api/dns/custom-rules', { rules });
            const data = res.data || res;
            updateCustomRulesCount(data.rule_count || 0);
            showCustomRulesErrors(data.errors || []);

            if (data.error_count > 0) {
                wbToast(`Rules saved with ${data.error_count} syntax error(s)`, 'warning');
                if (statusEl) {
                    statusEl.innerHTML = `<span class="material-icons align-middle text-warning" style="font-size:16px;">warning</span> ${data.error_count} error(s)`;
                    statusEl.className = 'small text-warning';
                }
            } else {
                wbToast('Custom rules saved', 'success');
                if (statusEl) {
                    statusEl.innerHTML = '';
                    statusEl.className = 'small text-muted';
                }
            }
        } catch (e) {
            wbToast('Failed to save custom rules: ' + e.message, 'danger');
            if (statusEl) {
                statusEl.innerHTML = '<span class="material-icons align-middle text-danger" style="font-size:16px;">error</span> Failed';
                statusEl.className = 'small text-danger';
            }
            // Also update rule count from textarea to reflect actual state
            const lines = rules.split('\n').filter(l => {
                const trimmed = l.trim();
                return trimmed && !trimmed.startsWith('!') && !trimmed.startsWith('#');
            });
            updateCustomRulesCount(lines.length);
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    // ─── SPEEDTEST / BANDWIDTH MEASUREMENT ──────────────────────

    let _speedtestRunning = false;
        const FLAG_ICON_BASE_URL = 'https://cdn.jsdelivr.net/npm/flag-icons@7.3.2/flags/4x3';
        const formatBandwidthMetric = window.WBShared.formatBandwidthMetric;
        const speedtestElements = {
            enabledToggle: document.getElementById('speedtest-enabled'),
            runBtn: document.getElementById('btn-speedtest-run'),
            running: document.getElementById('speedtest-running'),
            result: document.getElementById('speedtest-result'),
            status: document.getElementById('speedtest-status'),
            progress: document.getElementById('speedtest-progress'),
            download: document.getElementById('speedtest-result-dl'),
            upload: document.getElementById('speedtest-result-ul'),
            rtt: document.getElementById('speedtest-result-rtt'),
            server: document.getElementById('speedtest-result-server'),
            date: document.getElementById('speedtest-result-date'),
            inlineDate: document.getElementById('speedtest-result-date-inline'),
        };

        function createCountryFlagElement(countryCode) {
            const code = String(countryCode || '').trim().toLowerCase();
            if (!/^[a-z]{2}$/.test(code)) return null;

            const img = document.createElement('img');
            img.className = 'peer-flag';
            img.alt = `Country flag: ${code.toUpperCase()}`;
            img.loading = 'lazy';
            img.decoding = 'async';
            img.src = `${FLAG_ICON_BASE_URL}/${code}.svg`;
            img.addEventListener('error', () => img.remove(), { once: true });
            return img;
        }

        function setSpeedtestStatusMessage(statusEl, rawMessage) {
            if (!statusEl) return;
            statusEl.replaceChildren();

            const message = String(rawMessage || 'Running…');
            const parts = message.split(/\((https?:\/\/[^)]+)\)/g);
            for (let index = 0; index < parts.length; index++) {
                const part = parts[index];
                if (!part) continue;
                if (index % 2 === 1) {
                    const code = document.createElement('code');
                    code.className = 'small';
                    code.textContent = part;
                    statusEl.append('(', code, ')');
                    continue;
                }
                statusEl.append(document.createTextNode(part));
            }
        }

        function reportSpeedtestError(message) {
            wbToast(`Speed test failed: ${message || 'Unknown error'}`, 'danger');
        }

        function handleSpeedtestResult(data) {
            if (data?.status === 'busy') {
                wbToast('Network appears busy — measurement skipped', 'warning');
                return;
            }

            showSpeedtestResult(data);
            wbToast('Speed test completed', 'success');
            document.dispatchEvent(new CustomEvent('speedtest-completed'));
        }

        function createReportedError(message) {
            const error = new Error(message || 'Unknown error');
            error.speedtestReported = true;
            return error;
        }

        function initSpeedtestUI() {
            if (!isAdmin) return;
            speedtestElements.enabledToggle?.addEventListener('change', saveSpeedtestSettings);
            speedtestElements.runBtn?.addEventListener('click', runSpeedtest);
        }

    async function loadSpeedtestSettings() {
        try {
                const data = await api('GET', '/api/wireguard/speedtest/settings');

                const { enabledToggle } = speedtestElements;
            if (enabledToggle) {
                enabledToggle.style.transition = 'none';
                enabledToggle.checked = !!data.enabled;
                enabledToggle.offsetHeight;
                enabledToggle.style.transition = '';
            }
            
                // Use the last result embedded in the settings response if available;
                // otherwise fetch the latest result from the history endpoint.
            if (data.last_result && typeof data.last_result === 'object') {
                showSpeedtestResult(data.last_result);
            } else {
                await loadLastSpeedtest();
            }
        } catch (e) {
            console.error('Failed to load speedtest settings:', e.message);
                wbToast('Failed to load speedtest settings', 'danger');
        }
    }

    async function loadLastSpeedtest() {
        try {
                const data = await api('GET', '/api/wireguard/speedtest/history?limit=1');
            
            if (data.history && data.history.length > 0) {
                const lastResult = data.history[0];
                showSpeedtestResult(lastResult);
            }
        } catch (e) {
            // Silently fail if no history exists yet
            console.debug('No speedtest history available:', e.message);
        }
    }

    async function saveSpeedtestSettings() {
        if (!isAdmin) return;
        const payload = {};

        const { enabledToggle } = speedtestElements;
        if (enabledToggle) payload.enabled = enabledToggle.checked;

        try {
            await api('PATCH', '/api/wireguard/speedtest/settings', payload);
            const status = payload.enabled ? 'enabled' : 'disabled';
            wbToast(`Speedtest ${status}`, 'success');
        } catch (e) {
            wbToast('Failed to save speedtest settings: ' + e.message, 'danger');
        }
    }

    async function runSpeedtest() {
        if (_speedtestRunning || !isAdmin) return;
        _speedtestRunning = true;

        const {
            runBtn: btn,
            running: runningEl,
            result: resultEl,
            status: statusEl,
            progress: progressEl,
        } = speedtestElements;

        if (btn) btn.disabled = true;
        if (runningEl) runningEl.classList.remove('d-none');
        if (resultEl) resultEl.classList.add('d-none');
        if (statusEl) statusEl.textContent = 'Initializing…';
        if (progressEl) progressEl.textContent = '0%';

        try {
            await runSpeedtestWithSSE(statusEl, progressEl);
        } catch (e) {
            if (!e?.speedtestReported) {
                reportSpeedtestError(e.message);
            }
        } finally {
            _speedtestRunning = false;
            if (btn) btn.disabled = false;
            if (runningEl) runningEl.classList.add('d-none');
        }
    }

    /**
     * Run a speedtest via Server-Sent Events.
     * Resolves with the final result payload or rejects on transport failure or timeout.
     * @param {HTMLElement|null} statusEl
     * @param {HTMLElement|null} progressEl
     * @returns {Promise<object>}
     */
    function runSpeedtestWithSSE(statusEl, progressEl) {
        return new Promise((resolve, reject) => {
            const es = new EventSource('/api/wireguard/speedtest/run/stream');
            let completed = false;
            let safetyTimer = null;

            function finish(callback) {
                if (completed) return;
                completed = true;
                if (safetyTimer !== null) {
                    clearTimeout(safetyTimer);
                    safetyTimer = null;
                }
                es.close();
                callback();
            }

            es.addEventListener('progress', (e) => {
                try {
                    const data = JSON.parse(e.data);
                    setSpeedtestStatusMessage(statusEl, data.message);
                    if (progressEl) progressEl.textContent = `${Math.round(data.progress * 100)}%`;
                } catch (err) {
                    console.warn('Failed to parse progress event:', err);
                }
            });

            es.addEventListener('result', (e) => {
                finish(() => {
                    try {
                        const data = JSON.parse(e.data);
                        handleSpeedtestResult(data);
                        resolve(data);
                    } catch (err) {
                        reject(err);
                    }
                });
            });

            es.addEventListener('error', (e) => {
                // Only handle server-sent error events (e.data will be present)
                // Transport failures are handled by onerror below
                if (!e.data) return;

                finish(() => {
                    try {
                        const data = JSON.parse(e.data);
                        reportSpeedtestError(data.reason || 'Unknown error');
                        reject(createReportedError(data.reason || 'Unknown error'));
                    } catch (err) {
                        reject(err);
                    }
                });
            });

            es.onerror = () => {
                finish(() => {
                    reject(new Error('SSE connection lost'));
                });
            };

            // Safety timeout
            safetyTimer = window.setTimeout(() => {
                finish(() => {
                    reject(new Error('Timeout'));
                });
            }, 180000);
        });
    }

    /**
     * Format a speedtest timestamp as a human-readable relative label.
     * Falls back to an absolute date string for timestamps older than 24h
     * or when the timestamp lies in the future due to clock skew.
     * @param {string} timestamp
     * @returns {string}
     */
    function formatSpeedtestMeasuredLabel(timestamp) {
        const date = new Date(timestamp);
        const diffMs = Date.now() - date.getTime();
        const diffMins = Math.floor(diffMs / 60000);

        if (diffMins >= 0 && diffMins < 1) {
            return 'Just now';
        }
        if (diffMins < 0) {
            return date.toLocaleString(undefined, {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
            });
        }
        if (diffMins < 60) {
            return `${diffMins} min ago`;
        }
        if (diffMins < 1440) {
            const hours = Math.floor(diffMins / 60);
            return `${hours}h ago`;
        }

        return date.toLocaleString(undefined, {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        });
    }

    function showSpeedtestResult(data) {
        if (!data || data.status === 'busy' || data.status === 'error') {
            console.warn('[speedtest] showSpeedtestResult called with non-ok result:', data?.status);
            return;
        }

        const {
            result: resultEl,
            download: dlEl,
            upload: ulEl,
            rtt: rttEl,
            server: serverEl,
            date: dateEl,
            inlineDate: inlineDateEl,
        } = speedtestElements;
        if (!resultEl) {
            console.debug('showSpeedtestResult: #speedtest-result not found in DOM');
            return;
        }
        resultEl.classList.remove('d-none');

        if (dlEl) dlEl.textContent = formatBandwidthMetric(data.download_mbit, 2);
        if (ulEl) ulEl.textContent = formatBandwidthMetric(data.upload_mbit, 2);
        if (rttEl) rttEl.textContent = data.rtt_ms != null ? `${data.rtt_ms.toFixed(2)} ms (±${(data.jitter_ms || 0).toFixed(2)})` : '–';
        if (serverEl) {
            // Clear previous content
            serverEl.textContent = '';
            serverEl.title = data.server || '';
            
            // Add country flag if available
            const flag = createCountryFlagElement(data.country_code);
            if (flag) {
                serverEl.appendChild(flag);
                serverEl.appendChild(document.createTextNode(' '));
            }
            
            // Add server name
            serverEl.appendChild(document.createTextNode(data.server || '–'));
        }
        if (inlineDateEl) {
            inlineDateEl.textContent = '';
            inlineDateEl.removeAttribute('aria-label');
        }
        if (dateEl) {
            if (!data.ts) {
                dateEl.textContent = '–';
                if (inlineDateEl) {
                    inlineDateEl.textContent = '';
                    inlineDateEl.removeAttribute('aria-label');
                }
                dateEl.title = '';
            } else {
                const date = new Date(data.ts);
                if (Number.isNaN(date.getTime())) {
                    dateEl.textContent = '–';
                    if (inlineDateEl) {
                        inlineDateEl.textContent = '';
                        inlineDateEl.removeAttribute('aria-label');
                    }
                    dateEl.title = '';
                } else {
                    const label = formatSpeedtestMeasuredLabel(data.ts);
                    dateEl.textContent = label;
                    if (inlineDateEl) {
                        inlineDateEl.textContent = label;
                        inlineDateEl.setAttribute('aria-label', label);
                    }
                    dateEl.title = date.toLocaleString();
                }
            }
        }
    }

    window.WBSettings = {
        purgeTrafficLogs,
        purgeDnsLogs,
        purgePeerLogs,
        refreshInterfaces,
        prepareCreateInterfaceModal,
        updateBlocklist,
        saveCustomRules,
        validateDnsServers,
        refreshCertificates,
        requestCertificate,
        submitInterfaceForm,
    };

    // Cleanup debounced timers on navigation
    window.addEventListener('pagehide', () => {
        clearTimeout(wgSettingsSaveTimeout);
        clearTimeout(blocklistSaveTimeout);
        clearTimeout(dnsConfigSaveTimeout);
        _speedtestRunning = false;
    });

    // Initialize tabs on page load (await to ensure settings are loaded before user interaction)
    initSpeedtestUI();
    await initTabs();

    // ─── BACKUP MANAGEMENT ─────────────────────────────────────────────────────

    // Backup retention days mapping (slider index → days)
    const BACKUP_RETENTION_DAYS = [1, 7, 14, 21, 30];
    const BACKUP_RETENTION_LABELS = ['1 Day', '7 Days', '14 Days', '21 Days', '30 Days'];

    // Format bytes to human-readable string
    function formatBackupSize(bytes) {
        if (bytes === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        const value = bytes / Math.pow(1024, i);
        return value.toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
    }

    // Helper: Parse API error response
    async function parseBackupApiError(resp) {
        const error = await resp.json().catch(() => ({}));
        return error.detail || 'Unknown error';
    }

    function updateBackupRetentionBadge(sliderValue) {
        const badge = document.getElementById('backup-retention-value');
        if (badge) {
            badge.textContent = BACKUP_RETENTION_LABELS[sliderValue] || '30 Days';
        }
    }

    function updateRestoreButtonState() {
        const fileInput = document.getElementById('backup-restore-file');
        const restoreBtn = document.getElementById('btn-backup-restore');
        if (!fileInput || !restoreBtn || !isAdmin) return;
        restoreBtn.disabled = fileInput.files.length === 0;
    }

    // Load backup settings and status
    async function loadBackupSettings() {
        if (!isAdmin) return;
        
        try {
            const data = await api('GET', '/api/backup/settings');
            
            // Update UI with null checks
            const scheduledEl = document.getElementById('backup-scheduled-enabled');
            const countEl = document.getElementById('backup-count');
            const lastAtEl = document.getElementById('backup-last-at');
            const statsEl = document.getElementById('backup-scheduled-stats');
            const retentionSection = document.getElementById('backup-retention-section');
            const retentionSlider = document.getElementById('backup-retention-slider');
            const sizeEl = document.getElementById('backup-size');
            const diskWarningEl = document.getElementById('backup-disk-warning');
            
            if (scheduledEl) scheduledEl.checked = data.scheduled_enabled;
            if (countEl) countEl.textContent = data.backup_count.toString();
            
            // Set retention slider value
            if (retentionSlider && data.retention_days !== undefined) {
                const sliderIndex = BACKUP_RETENTION_DAYS.indexOf(data.retention_days);
                retentionSlider.value = sliderIndex >= 0 ? sliderIndex : 4; // Default to 30 days
                updateBackupRetentionBadge(retentionSlider.value);
            }
            
            // Show/hide retention slider and stats section based on scheduled status
            if (retentionSection) {
                retentionSection.classList.toggle('d-none', !data.scheduled_enabled);
            }
            if (statsEl) {
                statsEl.classList.toggle('d-none', !data.scheduled_enabled);
            }
            
            // Update backup size
            if (sizeEl && data.backup_size_bytes !== undefined) {
                sizeEl.textContent = formatBackupSize(data.backup_size_bytes);
            }
            
            // Show/hide disk warning
            if (diskWarningEl) {
                diskWarningEl.classList.toggle('d-none', !data.disk_warning);
            }
            
            if (lastAtEl) {
                if (data.last_backup_at && data.backup_count > 0) {
                    const date = new Date(data.last_backup_at);
                    lastAtEl.textContent = date.toLocaleString();
                } else {
                    lastAtEl.textContent = 'No backups yet';
                }
            }
        } catch (err) {
            console.error('Failed to load backup settings:', err);
        }
    }

    // Toggle scheduled backups
    async function toggleScheduledBackup(enabled) {
        if (!isAdmin) return;
        
        // Immediately show/hide retention slider and stats section for responsiveness
        const retentionSection = document.getElementById('backup-retention-section');
        const statsEl = document.getElementById('backup-scheduled-stats');
        if (retentionSection) {
            retentionSection.classList.toggle('d-none', !enabled);
        }
        if (statsEl) {
            statsEl.classList.toggle('d-none', !enabled);
        }
        
        try {
            await api('PATCH', '/api/backup/settings', { scheduled_enabled: enabled });
            
            // Reload settings to confirm change
            await loadBackupSettings();
            
            // Show toast
            wbToast(enabled ? 'Scheduled backups enabled' : 'Scheduled backups disabled', 'success');
        } catch (err) {
            console.error('Failed to toggle scheduled backup:', err);
            // Revert checkbox state on error
            const checkbox = document.getElementById('backup-scheduled-enabled');
            if (checkbox) checkbox.checked = !enabled;
            // Revert visibility on error
            if (retentionSection) {
                retentionSection.classList.toggle('d-none', enabled);
            }
            if (statsEl) {
                statsEl.classList.toggle('d-none', enabled);
            }
            wbToast('Failed to update backup settings: ' + err.message, 'danger');
        }
    }

    // Update backup retention period
    async function updateBackupRetention(sliderValue) {
        if (!isAdmin) return;
        
        const days = BACKUP_RETENTION_DAYS[sliderValue] || 30;
        updateBackupRetentionBadge(sliderValue);
        
        try {
            const result = await api('PATCH', '/api/backup/settings', { retention_days: days });
            
            // Check if old backups were deleted
            if (result?.deleted_backups > 0) {
                wbToast(`Retention set to ${BACKUP_RETENTION_LABELS[sliderValue]} — ${result.deleted_backups} old backup(s) removed`, 'success');
            } else {
                wbToast(`Backup retention set to ${BACKUP_RETENTION_LABELS[sliderValue]}`, 'success');
            }
            
            // Reload to update backup count and size
            await loadBackupSettings();
        } catch (err) {
            console.error('Failed to update backup retention:', err);
            wbToast('Failed to update backup retention: ' + err.message, 'danger');
            // Reload to revert slider
            await loadBackupSettings();
        }
    }

    // Download backup
    async function downloadBackup() {
        if (!isAdmin) return;
        
        const btn = document.getElementById('btn-backup-download');
        if (!btn) return;
        const originalHtml = btn.innerHTML;
        
        try {
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm align-middle me-1" role="status"></span>Creating...';
            
            const resp = await fetch('/api/backup/download', {
                method: 'POST',
                headers: { 'X-CSRF-Token': getCsrfToken() },
                credentials: 'same-origin'
            });
            
            if (!resp.ok) {
                throw new Error(await parseBackupApiError(resp));
            }
            
            // Get filename from Content-Disposition header
            const disposition = resp.headers.get('Content-Disposition');
            let filename = 'wirebuddy_backup.tar.gz';
            if (disposition) {
                const match = disposition.match(/filename="?([^";]+)"?/);
                if (match) filename = match[1].trim();
            }
            
            // Download the file
            const blob = await resp.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            // Reload settings to update last backup time
            await loadBackupSettings();
        } catch (err) {
            console.error('Failed to download backup:', err);
            wbToast('Failed to create backup: ' + err.message, 'danger');
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        }
    }

    // Restore backup
    async function restoreBackup() {
        if (!isAdmin) return;
        
        const fileInput = document.getElementById('backup-restore-file');
        if (!fileInput) return;
        const file = fileInput.files[0];
        
        if (!file) {
            wbToast('Please select a backup file first.', 'warning');
            return;
        }
        
        // Validate file extension
        if (!file.name.endsWith('.tar.gz') && !file.name.endsWith('.gz')) {
            wbToast('Invalid file type. Please select a .tar.gz backup file.', 'warning');
            return;
        }
        
        const btn = document.getElementById('btn-backup-restore');
        if (!btn) return;
        const originalHtml = btn.innerHTML;
        
        try {
            // Step 1: Validate backup file HMAC before asking for password
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm align-middle" role="status"></span> Validating...';
            
            const validateFormData = new FormData();
            validateFormData.append('file', file);
            
            const validateResp = await fetch('/api/backup/validate', {
                method: 'POST',
                headers: { 'X-CSRF-Token': getCsrfToken() },
                credentials: 'same-origin',
                body: validateFormData
            });
            
            if (!validateResp.ok) {
                throw new Error(await parseBackupApiError(validateResp));
            }
            
            // Reset button before showing modal
            btn.disabled = false;
            btn.innerHTML = originalHtml;
            updateRestoreButtonState();
            
            // Step 2: Confirm with password prompt (only if validation passed)
            const password = await wbPrompt(
                'Backup is valid. This will overwrite all configuration and restart the application. Enter your admin password to confirm:',
                { inputType: 'password', placeholder: 'Admin password', title: 'Confirm Restore' }
            );
            
            if (!password) return;
            
            // Step 3: Perform actual restore
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm align-middle" role="status"></span> Restoring...';
            
            const restoreFormData = new FormData();
            restoreFormData.append('file', file);
            restoreFormData.append('password', password);
            
            const resp = await fetch('/api/backup/restore', {
                method: 'POST',
                headers: { 'X-CSRF-Token': getCsrfToken() },
                credentials: 'same-origin',
                body: restoreFormData
            });
            
            if (!resp.ok) {
                throw new Error(await parseBackupApiError(resp));
            }
            
            const result = await resp.json();

            fileInput.value = '';
            updateRestoreButtonState();
            
            // Show success message and wait for restart
            wbAlert(result.message + ' The page will reload automatically.', 'success');
            
            // Wait a moment then start checking for server restart
            setTimeout(pollForRestart, 2000);
            
        } catch (err) {
            console.error('Failed to restore backup:', err);
            wbToast('Failed to restore backup: ' + err.message, 'danger');
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
            updateRestoreButtonState();
        }
    }

    // Poll for server restart after restore
    function pollForRestart() {
        let stopped = false;
        
        const checkInterval = setInterval(async () => {
            if (stopped) return;
            try {
                const resp = await fetch('/health', { cache: 'no-store' });
                if (resp.ok) {
                    stopped = true;
                    clearInterval(checkInterval);
                    window.location.reload();
                }
            } catch (e) {
                // Server not ready yet, keep polling
            }
        }, 1000);
        
        // Give up after 60 seconds
        setTimeout(() => {
            if (!stopped) {
                stopped = true;
                clearInterval(checkInterval);
                wbAlert('Server restart took too long. Please refresh the page manually.', 'warning');
            }
        }, 60000);
    }

    // Bind backup event listeners
    function bindBackupListeners() {
        const scheduledCheckbox = document.getElementById('backup-scheduled-enabled');
        if (scheduledCheckbox) {
            scheduledCheckbox.addEventListener('change', (e) => {
                toggleScheduledBackup(e.target.checked);
            });
        }
        
        const retentionSlider = document.getElementById('backup-retention-slider');
        if (retentionSlider) {
            // Update badge on input (while dragging)
            retentionSlider.addEventListener('input', (e) => {
                updateBackupRetentionBadge(e.target.value);
            });
            // Save on change (when released)
            retentionSlider.addEventListener('change', (e) => {
                updateBackupRetention(parseInt(e.target.value, 10));
            });
        }
        
        const downloadBtn = document.getElementById('btn-backup-download');
        if (downloadBtn) {
            downloadBtn.addEventListener('click', downloadBackup);
        }
        
        const restoreBtn = document.getElementById('btn-backup-restore');
        if (restoreBtn) {
            restoreBtn.addEventListener('click', restoreBackup);
        }

        const restoreFileInput = document.getElementById('backup-restore-file');
        const browseBtn = document.getElementById('btn-backup-browse');
        const filenameDisplay = document.getElementById('backup-restore-filename');

        if (browseBtn && restoreFileInput) {
            browseBtn.addEventListener('click', () => restoreFileInput.click());
        }

        if (restoreFileInput) {
            restoreFileInput.addEventListener('change', () => {
                if (filenameDisplay) {
                    filenameDisplay.value = restoreFileInput.files[0]?.name || '';
                }
                updateRestoreButtonState();
            });
        }

        updateRestoreButtonState();
    }

    // Initialize backup functionality
    bindBackupListeners();
    loadBackupSettings();

})();
