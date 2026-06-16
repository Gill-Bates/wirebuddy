//
// app/static/js/settings/modules/backup.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Backup settings module.
// Handles scheduled backups, retention, download/restore.
//

SettingsApp.registerModule('backup', (function () {
    'use strict';

    const { api, fetchWithAuth, toast, formatBytes } = SettingsApp;

    // Backup retention values differ from other retention sliders
    const BACKUP_RETENTION_VALUES = [1, 7, 14, 21, 30];
    const BACKUP_RETENTION_LABELS = ['1 Day', '7 Days', '14 Days', '21 Days', '30 Days'];
    const DEFAULT_BACKUP_FILENAME = 'wirebuddy_backup.tar.gz';

    let retentionSlider = null;
    let downloadInProgress = false;
    let restoreInProgress = false;

    // ========================================================================
    // Utilities
    // ========================================================================

    function bindOnce(element, event, handler, options) {
        if (!element) return;

        const normalizedEvent = String(event).toLowerCase().replace(/[^a-z0-9]+/g, '-');
        const boundAttr = `data-backup-bound-${normalizedEvent}`;
        if (element.getAttribute(boundAttr) === '1') {
            return;
        }

        element.setAttribute(boundAttr, '1');
        element.addEventListener(event, handler, options);
    }

    function sanitizeDownloadFilename(name) {
        const sanitized = String(name || DEFAULT_BACKUP_FILENAME)
            .replace(/[\\/\x00-\x1F\x7F]/g, '_')
            .trim()
            .slice(0, 160);

        if (!sanitized || /^\.+$/.test(sanitized)) {
            return DEFAULT_BACKUP_FILENAME;
        }

        return sanitized;
    }

    function filenameFromDisposition(disposition) {
        if (!disposition) {
            return null;
        }

        const encoded = disposition.match(/filename\*=UTF-8''([^;]+)/i);
        if (encoded) {
            try {
                return decodeURIComponent(encoded[1]);
            } catch {
                // Fall through to plain filename parsing.
            }
        }

        const plain = disposition.match(/filename="?([^";]+)"?/i);
        return plain ? plain[1].trim() : null;
    }

    /**
     * Parse API error from response.
     * @param {Response} resp
     * @returns {Promise<string>}
     */
    async function parseApiError(resp) {
        try {
            const json = await resp.json();
            return json.detail || json.message || `HTTP ${resp.status}`;
        } catch {
            return `HTTP ${resp.status}`;
        }
    }

    /**
     * Format backup retention label.
     * @param {number} days
     * @returns {string}
     */
    function retentionLabel(days) {
        const idx = BACKUP_RETENTION_VALUES.indexOf(days);
        return idx >= 0 ? BACKUP_RETENTION_LABELS[idx] : `${days} Days`;
    }

    // ========================================================================
    // Settings Management
    // ========================================================================

    async function loadBackupSettings() {
        try {
            const data = await api('GET', '/api/backup/settings');

            // Scheduled backup toggle
            const enabledCheckbox = document.getElementById('backup-scheduled-enabled');
            if (enabledCheckbox) {
                enabledCheckbox.checked = data.scheduled_enabled || false;
            }

            // Retention section visibility
            const retentionSection = document.getElementById('backup-retention-section');
            const statsEl = document.getElementById('backup-scheduled-stats');
            if (retentionSection) {
                retentionSection.classList.toggle('d-none', !data.scheduled_enabled);
            }
            if (statsEl) {
                statsEl.classList.toggle('d-none', !data.scheduled_enabled);
            }

            // Retention slider
            if (retentionSlider && data.retention_days != null) {
                retentionSlider.setValue(data.retention_days);
            }

            // Stats display
            const backupCountEl = document.getElementById('backup-count');
            if (backupCountEl) {
                backupCountEl.textContent = data.backup_count || 0;
            }

            const backupSizeEl = document.getElementById('backup-total-size');
            if (backupSizeEl) {
                backupSizeEl.textContent = formatBytes(data.total_size_bytes || 0);
            }

            const lastAtEl = document.getElementById('backup-last-at');
            if (lastAtEl) {
                if (data.last_backup_at) {
                    const date = new Date(data.last_backup_at);
                    lastAtEl.textContent = date.toLocaleString();
                } else {
                    lastAtEl.textContent = 'No backups yet';
                }
            }

            // TSDB metrics inclusion + range
            const includeTsdbEl = document.getElementById('backup-include-tsdb');
            if (includeTsdbEl) {
                includeTsdbEl.checked = data.include_tsdb_metrics || false;
            }
            const tsdbRangeEl = document.getElementById('backup-tsdb-range');
            if (tsdbRangeEl && data.tsdb_range) {
                tsdbRangeEl.value = data.tsdb_range;
            }
            updateTsdbRangeState();
        } catch (err) {
            console.error('Failed to load backup settings:', err);
            toast('Failed to load backup settings', 'danger');
        }
    }

    async function toggleScheduledBackup(enabled) {
        if (!SettingsApp.state.isAdmin) return;

        // Immediately update UI for responsiveness
        const retentionSection = document.getElementById('backup-retention-section');
        const statsEl = document.getElementById('backup-scheduled-stats');
        if (retentionSection) retentionSection.classList.toggle('d-none', !enabled);
        if (statsEl) statsEl.classList.toggle('d-none', !enabled);

        try {
            await api('PATCH', '/api/backup/settings', { scheduled_enabled: enabled });
            await loadBackupSettings();
            toast(enabled ? 'Scheduled backups enabled' : 'Scheduled backups disabled', 'success');
        } catch (err) {
            console.error('Failed to toggle scheduled backup:', err);
            // Revert on error
            const checkbox = document.getElementById('backup-scheduled-enabled');
            if (checkbox) checkbox.checked = !enabled;
            if (retentionSection) retentionSection.classList.toggle('d-none', enabled);
            if (statsEl) statsEl.classList.toggle('d-none', enabled);
            toast('Failed to update backup settings: ' + err.message, 'danger');
        }
    }

    async function updateRetention(days) {
        if (!SettingsApp.state.isAdmin) return;

        try {
            const result = await api('PATCH', '/api/backup/settings', { retention_days: days });

            if (result?.deleted_backups > 0) {
                toast(`Retention set to ${retentionLabel(days)} — ${result.deleted_backups} old backup(s) removed`, 'success');
            } else {
                toast(`Backup retention set to ${retentionLabel(days)}`, 'success');
            }

            await loadBackupSettings();
        } catch (err) {
            console.error('Failed to update backup retention:', err);
            toast('Failed to update backup retention: ' + err.message, 'danger');
            await loadBackupSettings(); // Revert slider
        }
    }

    function updateTsdbRangeState() {
        const includeTsdbEl = document.getElementById('backup-include-tsdb');
        const tsdbRangeSectionEl = document.getElementById('backup-tsdb-range-section');
        const tsdbRangeEl = document.getElementById('backup-tsdb-range');
        if (!tsdbRangeEl || !tsdbRangeSectionEl) return;
        const checked = !!(includeTsdbEl && includeTsdbEl.checked);
        tsdbRangeSectionEl.classList.toggle('d-none', !checked);
        tsdbRangeEl.disabled = !checked || !SettingsApp.state.isAdmin;
    }

    async function updateIncludeTsdb(enabled) {
        if (!SettingsApp.state.isAdmin) return;
        updateTsdbRangeState();
        try {
            await api('PATCH', '/api/backup/settings', { include_tsdb_metrics: enabled });
            toast(enabled ? 'Metrics history will be included in backups' : 'Metrics history excluded from backups', 'success');
        } catch (err) {
            console.error('Failed to update TSDB backup option:', err);
            const checkbox = document.getElementById('backup-include-tsdb');
            if (checkbox) checkbox.checked = !enabled;
            updateTsdbRangeState();
            toast('Failed to update backup settings: ' + err.message, 'danger');
        }
    }

    async function updateTsdbRange(range) {
        if (!SettingsApp.state.isAdmin) return;
        try {
            await api('PATCH', '/api/backup/settings', { tsdb_range: range });
            toast('Metrics time range updated', 'success');
        } catch (err) {
            console.error('Failed to update TSDB backup range:', err);
            toast('Failed to update backup settings: ' + err.message, 'danger');
            await loadBackupSettings(); // Revert select
        }
    }

    // ========================================================================
    // Download / Restore
    // ========================================================================

    async function downloadBackup() {
        if (!SettingsApp.state.isAdmin || downloadInProgress) return;

        const btn = document.getElementById('btn-backup-download');
        if (!btn) return;

        downloadInProgress = true;
        const originalHtml = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm align-middle me-1" role="status"></span>Creating...';

        try {
            const resp = await fetchWithAuth('/api/backup/download', {
                method: 'POST',
                credentials: 'same-origin',
                timeoutMs: 120000, // 2 minutes for backup creation
            });

            if (!resp.ok) {
                throw new Error(await parseApiError(resp));
            }

            // Get filename from Content-Disposition header
            const disposition = resp.headers.get('Content-Disposition');
            const filename = sanitizeDownloadFilename(
                filenameFromDisposition(disposition) || DEFAULT_BACKUP_FILENAME
            );

            // Download file
            const blob = await resp.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);

            await loadBackupSettings();
        } catch (err) {
            console.error('Failed to download backup:', err);
            toast('Failed to create backup: ' + err.message, 'danger');
        } finally {
            downloadInProgress = false;
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        }
    }

    async function restoreBackup() {
        if (!SettingsApp.state.isAdmin || restoreInProgress) return;

        const fileInput = document.getElementById('backup-restore-file');
        if (!fileInput) return;

        const file = fileInput.files[0];
        if (!file) {
            toast('Please select a backup file first.', 'warning');
            return;
        }

        // Validate file extension
        if (!file.name.endsWith('.tar.gz')) {
            toast('Invalid file type. Please select a .tar.gz backup file.', 'warning');
            return;
        }

        const btn = document.getElementById('btn-backup-restore');
        if (!btn) return;

        restoreInProgress = true;
        const originalHtml = btn.innerHTML;
        let keepBusyState = false;
        btn.disabled = true;

        try {
            let password = await wbPrompt(
                'This will overwrite all configuration and restart the application. Enter your admin password to confirm:',
                { inputType: 'password', placeholder: 'Admin password', title: 'Confirm Restore' }
            );

            if (!password) {
                return;
            }

            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm align-middle me-1" role="status"></span>Restoring...';

            const formData = new FormData();
            formData.append('file', file);
            formData.append('password', password);
            password = '';

            const resp = await fetchWithAuth('/api/backup/restore', {
                method: 'POST',
                credentials: 'same-origin',
                body: formData,
                timeoutMs: 180000, // 3 minutes for backup restore
            });

            if (!resp.ok) {
                throw new Error(await parseApiError(resp));
            }

            toast('Backup restored successfully. Reloading...', 'success');
            keepBusyState = true;
            setTimeout(() => window.location.reload(), 1500);
        } catch (err) {
            console.error('Failed to restore backup:', err);
            toast('Failed to restore backup: ' + err.message, 'danger');
        } finally {
            if (!keepBusyState) {
                restoreInProgress = false;
                btn.disabled = false;
                btn.innerHTML = originalHtml;
            }
        }
    }

    function updateRestoreButtonState() {
        const fileInput = document.getElementById('backup-restore-file');
        const restoreBtn = document.getElementById('btn-backup-restore');
        if (!fileInput || !restoreBtn) return;

        const hasFile = fileInput.files && fileInput.files.length > 0;
        restoreBtn.disabled = !hasFile || !SettingsApp.state.isAdmin;
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    function initSlider() {
        if (document.getElementById('backup-retention-slider')) {
            retentionSlider = RetentionSlider({
                sliderId: 'backup-retention-slider',
                badgeId: 'backup-retention-value',
                values: BACKUP_RETENTION_VALUES,
                labelFormatter: retentionLabel,
                defaultIndex: 4, // 30 days
                warningValue: 1,
                warningClass: 'text-bg-warning',
                onSave: updateRetention
            });
        }
    }

    function bindListeners() {
        const scheduledCheckbox = document.getElementById('backup-scheduled-enabled');
        if (scheduledCheckbox) {
            bindOnce(scheduledCheckbox, 'change', (e) => {
                toggleScheduledBackup(e.target.checked);
            });
        }

        const downloadBtn = document.getElementById('btn-backup-download');
        if (downloadBtn) {
            bindOnce(downloadBtn, 'click', downloadBackup);
        }

        const includeTsdbEl = document.getElementById('backup-include-tsdb');
        if (includeTsdbEl) {
            bindOnce(includeTsdbEl, 'change', (e) => updateIncludeTsdb(e.target.checked));
        }

        const tsdbRangeEl = document.getElementById('backup-tsdb-range');
        if (tsdbRangeEl) {
            bindOnce(tsdbRangeEl, 'change', (e) => updateTsdbRange(e.target.value));
        }

        const restoreBtn = document.getElementById('btn-backup-restore');
        if (restoreBtn) {
            bindOnce(restoreBtn, 'click', restoreBackup);
        }

        const restoreFileInput = document.getElementById('backup-restore-file');
        const browseBtn = document.getElementById('btn-backup-browse');
        const filenameDisplay = document.getElementById('backup-restore-filename');

        if (browseBtn && restoreFileInput) {
            bindOnce(browseBtn, 'click', () => restoreFileInput.click());
        }

        if (restoreFileInput) {
            bindOnce(restoreFileInput, 'change', () => {
                if (filenameDisplay) {
                    filenameDisplay.value = restoreFileInput.files[0]?.name || '';
                }
                updateRestoreButtonState();
            });
        }

        updateRestoreButtonState();
    }

    // ========================================================================
    // Module API
    // ========================================================================

    return {
        init() {
            initSlider();
            bindListeners();
        },

        async load() {
            await loadBackupSettings();
        },

        // Expose for external use
        loadBackupSettings
    };
})());
