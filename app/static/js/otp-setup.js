    (() => {
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
        const username = document.body.dataset.username || '';
        const OTP_LENGTH = 6;
        let recoveryCodes = [];
        let recoveryDownloadToken = '';
        let submitting = false;
        let recoveryZipDownloaded = false;

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
                throw new Error(`Server error (HTTP ${resp.status})`);
            }
            if (!resp.ok) throw new Error(json.detail || 'Request failed');
            return json.data;
        }

        function showError(msg) {
            const el = document.getElementById('error-alert');
            el.textContent = msg;
            el.style.display = 'block';
        }

        function hideError() {
            document.getElementById('error-alert').style.display = 'none';
        }

        function clearSensitiveData() {
            document.getElementById('otp-secret').value = '';
            document.getElementById('otp-qr-image').src = '';
            document.querySelectorAll('.otp-digit').forEach(d => d.value = '');
        }

        function clearAllSensitiveData() {
            recoveryCodes = [];
            recoveryDownloadToken = '';
            document.getElementById('recovery-codes').textContent = '';
            clearSensitiveData();
        }

        async function loadSetup() {
            try {
                const data = await api('GET', '/api/me/otp/setup');
                document.getElementById('otp-qr-image').src = data.qr_code_data_url;
                document.getElementById('otp-secret').value = data.secret;
                document.getElementById('qr-loading').style.display = 'none';
                document.getElementById('otp-qr-image').style.display = 'block';
                document.querySelector('.otp-digit[data-index="0"]').focus();
            } catch (error) {
                showError('Failed to load OTP setup: ' + error.message);
                document.getElementById('qr-loading').style.display = 'none';
            }
        }

        function initOtpDigits() {
            const digits = document.querySelectorAll('.otp-digit');
            const confirmBtn = document.getElementById('confirm-btn');

            function getCode() {
                return Array.from(digits).map(d => d.value).join('');
            }

            function updateButton() {
                const code = getCode();
                confirmBtn.disabled = submitting || code.length !== OTP_LENGTH || !new RegExp(`^\\d{${OTP_LENGTH}}$`).test(code);
            }

            digits.forEach((input, idx) => {
                input.addEventListener('input', (e) => {
                    const val = e.target.value.replace(/\D/g, '');
                    e.target.value = val.slice(-1);

                    if (val && idx < OTP_LENGTH - 1) {
                        digits[idx + 1].focus();
                    }

                    updateButton();

                    const code = getCode();
                    if (code.length === OTP_LENGTH && new RegExp(`^\\d{${OTP_LENGTH}}$`).test(code)) {
                        submitCode(code);
                    }
                });

                input.addEventListener('keydown', (e) => {
                    if (e.key === 'Backspace' && !e.target.value && idx > 0) {
                        digits[idx - 1].focus();
                    }
                });

                input.addEventListener('paste', (e) => {
                    e.preventDefault();
                    const paste = (e.clipboardData || window.clipboardData).getData('text').replace(/\D/g, '').slice(0, OTP_LENGTH);
                    paste.split('').forEach((char, i) => {
                        if (digits[i]) digits[i].value = char;
                    });
                    updateButton();
                    // Do not auto-submit on paste; allow user to verify before submit.
                });
            });

            confirmBtn.addEventListener('click', () => submitCode(getCode()));
        }

        async function submitCode(code) {
            if (submitting) return;
            submitting = true;

            hideError();
            const confirmBtn = document.getElementById('confirm-btn');
            confirmBtn.disabled = true;
            confirmBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Verifying...';

            try {
                const data = await api('POST', '/api/me/otp/confirm', { code });
                recoveryCodes = data.recovery_codes;
                recoveryDownloadToken = String(data.recovery_download_token || '').trim();
                
                // Clear sensitive QR/secret data before showing recovery codes
                clearSensitiveData();
                
                document.getElementById('step-qr').style.display = 'none';
                document.getElementById('step-recovery').style.display = 'block';
                document.getElementById('recovery-codes').textContent = recoveryCodes.join('\n');
                recoveryZipDownloaded = false;
                document.getElementById('continue-btn').disabled = true;
                document.getElementById('download-codes-btn').disabled = false;
                document.getElementById('download-codes-btn').innerHTML = '<span class="material-icons align-middle me-1 otp-icon-sm">download</span>Download Recovery Codes (ZIP)';
            } catch (error) {
                confirmBtn.disabled = false;
                confirmBtn.innerHTML = '<span class="material-icons align-middle me-1">check_circle</span>Verify & Activate';
                // Shake + red flash, then clear for re-entry
                const allDigits = document.querySelectorAll('.otp-digit');
                allDigits.forEach(d => d.classList.add('otp-error'));
                setTimeout(() => {
                    allDigits.forEach(d => {
                        d.classList.remove('otp-error');
                        d.value = '';
                    });
                    document.querySelector('.otp-digit[data-index="0"]')?.focus();
                }, 600);
            } finally {
                submitting = false;
            }
        }

        document.getElementById('copy-secret-btn').addEventListener('click', () => {
            const secret = document.getElementById('otp-secret').value;
            const btn = document.getElementById('copy-secret-btn');
            const original = btn.innerHTML;
            navigator.clipboard.writeText(secret).then(() => {
                btn.innerHTML = '<span class="material-icons" style="font-size: 18px;">check</span>';
                setTimeout(() => {
                    btn.innerHTML = original;
                }, 1500);
            }).catch(() => {
                showError('Copy failed — please select and copy manually.');
            });
        });

        document.getElementById('download-codes-btn').addEventListener('click', async () => {
            const btn = document.getElementById('download-codes-btn');
            if (!recoveryDownloadToken) {
                showError('Recovery download token missing. Please verify OTP again.');
                return;
            }
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Preparing ZIP...';

            try {
                const response = await fetch('/api/me/otp/recovery-codes/zip', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken,
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify({ token: recoveryDownloadToken }),
                });

                if (!response.ok) {
                    let message = 'Download failed';
                    try {
                        const err = await response.json();
                        message = err.detail || message;
                    } catch (_) {
                        // Keep default message when response is not JSON
                    }
                    throw new Error(message);
                }

                const blob = await response.blob();
                const disposition = response.headers.get('Content-Disposition') || '';
                const match = disposition.match(/filename="([^"]+)"/i);
                const safeUsername = (username || 'user').replace(/[^a-zA-Z0-9_-]/g, '_');
                const fallback = `wirebuddy-recovery-codes-${safeUsername}.zip`;
                const filename = match && match[1] ? match[1] : fallback;

                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = filename;
                document.body.appendChild(link);
                link.click();
                link.remove();
                URL.revokeObjectURL(url);

                recoveryZipDownloaded = true;
                document.getElementById('continue-btn').disabled = false;
                recoveryDownloadToken = '';
                btn.innerHTML = '<span class="material-icons align-middle me-1 otp-icon-sm">check</span>ZIP Downloaded';
            } catch (error) {
                showError(error.message || 'Download failed');
                btn.disabled = false;
                btn.innerHTML = '<span class="material-icons align-middle me-1 otp-icon-sm">download</span>Download Recovery Codes (ZIP)';
            }
        });

        document.getElementById('continue-btn').addEventListener('click', () => {
            if (!recoveryZipDownloaded) {
                showError('Please download the recovery codes ZIP before continuing.');
                return;
            }
            // Clear sensitive data before navigation
            recoveryCodes = [];
            recoveryDownloadToken = '';
            document.getElementById('recovery-codes').textContent = '';
            window.location.href = '/ui/dashboard';
        });

        // Hide QR image until loaded
        document.getElementById('otp-qr-image').style.display = 'none';
        window.addEventListener('beforeunload', clearAllSensitiveData);

        // Initialize
        initOtpDigits();
        loadSetup();
    })();
    
