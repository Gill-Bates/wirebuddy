//
// app/static/js/settings/modules/backup.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//
// Backup settings module.
// Handles scheduled backups, retention, download/restore.
//

SettingsApp.registerModule('backup', (function () {
    'use strict';

    const { api, toast, formatBytes } = SettingsApp;

    // Backup retention values differ from other retention sliders
    const BACKUP_RETENTION_VALUES = [1, 7, 14, 21, 30];
    const BACKUP_RETENTION_LABELS = ['1 Day', '7 Days', '14 Days', '21 Days', '30 Days'];

    let retentionSlider = null;

    // ========================================================================
    // Utilities
    // ========================================================================

    /**
     * Get CSRF token from meta tag or body data attribute.
     * @returns {string}
     */
    function getCsrfToken() {
        return document.querySelector('meta[name="csrf-token"]')?.content
            || document.body?.dataset?.csrfToken
            || '';
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
        } catch (err) {
            console.error('Failed to load backup settings:', err);
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

    // ========================================================================
    // Download / Restore
    // ========================================================================

    async function downloadBackup() {
        if (!SettingsApp.state.isAdmin) return;

        const btn = document.getElementById('btn-backup-download');
        if (!btn) return;

        const originalHtml = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm align-middle me-1" role="status"></span>Creating...';

        try {
            const resp = await fetch('/api/backup/download', {
                method: 'POST',
                headers: { 'X-CSRF-Token': getCsrfToken() },
                credentials: 'same-origin'
            });

            if (!resp.ok) {
                throw new Error(await parseApiError(resp));
            }

            // Get filename from Content-Disposition header
            const disposition = resp.headers.get('Content-Disposition');
            let filename = 'wirebuddy_backup.tar.gz';
            if (disposition) {
                const match = disposition.match(/filename="?([^";]+)"?/);
                if (match) filename = match[1].trim();
            }

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
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        }
    }

    async function restoreBackup() {
        if (!SettingsApp.state.isAdmin) return;

        const fileInput = document.getElementById('backup-restore-file');
        if (!fileInput) return;

        const file = fileInput.files[0];
        if (!file) {
            toast('Please select a backup file first.', 'warning');
            return;
        }

        // Validate file extension
        if (!file.name.endsWith('.tar.gz') && !file.name.endsWith('.gz')) {
            toast('Invalid file type. Please select a .tar.gz backup file.', 'warning');
            return;
        }

        const btn = document.getElementById('btn-backup-restore');
        if (!btn) return;

        const originalHtml = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm align-middle me-1" role="status"></span>Restoring...';

        try {
            const formData = new FormData();
            formData.append('file', file);

            const resp = await fetch('/api/backup/restore', {
                method: 'POST',
                headers: { 'X-CSRF-Token': getCsrfToken() },
                credentials: 'same-origin',
                body: formData
            });

            if (!resp.ok) {
                throw new Error(await parseApiError(resp));
            }

            toast('Backup restored successfully. Reloading...', 'success');
            setTimeout(() => window.location.reload(), 1500);
        } catch (err) {
            console.error('Failed to restore backup:', err);
            toast('Failed to restore backup: ' + err.message, 'danger');
            btn.disabled = false;
            btn.innerHTML = originalHtml;
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
            scheduledCheckbox.addEventListener('change', (e) => {
                toggleScheduledBackup(e.target.checked);
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
