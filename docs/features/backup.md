---
title: Backup & Restore
---

# Backup & Restore

WireBuddy provides comprehensive backup and restore functionality to protect your configuration and data.

## Overview

The Backup module provides:

- 💾 **Manual Backups** - Create and download configuration snapshots on demand
- ⏰ **Scheduled Backups** - Automatic daily backups at 03:00 local time
- 🔄 **One-Click Restore** - Restore from any backup with HMAC verification
- 📅 **Configurable Retention** - Choose retention period: 1, 7, 14, 21, or 30 days
- 🔐 **Integrity Protection** - HMAC signing prevents tampering and stays compatible with the configured `WIREBUDDY_SECRET_KEY`
- ⚠️ **Disk Monitoring** - Warnings when disk space is low
- 📊 **Backup Content Control** - Choose between settings only or include metrics history (7 days up to 1 year)

## What's Included

Each backup (format v2) contains a signed `.tar.gz` with the following structure:

| Archive Path | Description |
|---|---|
| `backup.json` | Manifest with version, timestamp, HMAC, and options |
| `data/schema.sql` | SQLite DDL (all tables, indexes, views, triggers) |
| `data/data.sql` | INSERT statements for all configuration tables |
| `data/tsdb/` | Time-series metrics — **only when a metrics range is selected** |

**Configuration tables** captured in `data/data.sql`:
`users`, `passkeys`, `settings`, `interfaces`, `peers`, `nodes`, `node_interfaces`, `schema_version`

!!! note "Excluded Data"
    Ephemeral tables (`auth_tokens`, `passkey_challenges`, `login_attempts`, `node_commands`) are excluded — they contain runtime-only state that would be stale after a restore.
    GeoIP databases (GeoLite2) are also not included; they are re-downloaded on startup.

!!! info "Backup Format"
    Backups are stored as `.tar.gz` archives with an HMAC signature embedded in the filename for integrity verification.

    Filename format: `wirebuddy_backup_YYYYMMDD_HHMMSS_<hmac>.tar.gz`

## Backup Content

The **Backup content** selector (available in both the Download Backup and Scheduled Backups cards) controls what data is included:

| Option | Description |
|---|---|
| **Settings only** | Schema + configuration data only. Smallest archive, fastest. |
| **+ Metrics: last 7 days** | Adds TSDB metrics from the past 7 days |
| **+ Metrics: last 30 days** | Adds TSDB metrics from the past 30 days |
| **+ Metrics: last 90 days** | Adds TSDB metrics from the past 90 days |
| **+ Metrics: last 180 days** | Adds TSDB metrics from the past 180 days |
| **+ Metrics: last 1 year** | Adds TSDB metrics from the past year |

!!! tip
    Selecting a range longer than your configured metrics retention yields only what is still on disk — the backup is never padded with empty data.

## Manual Backup

### Creating a Backup

**Navigate to:** Settings → Backup

1. Click **Create & Download Backup**
2. The backup is generated and downloaded automatically
3. Store the `.tar.gz` file in a secure location

The backup filename includes a timestamp and HMAC: `wirebuddy_backup_20260323_145230_a1b2c3d4e5f6.tar.gz`

### Backup Statistics

The backup card displays:

- **Last Backup** - Timestamp of the most recent backup (manual or scheduled)
- **Stored Backups** - Number of scheduled backups on the server
- **Total Backup Size** - Total size of all stored backups

## Scheduled Backups

### Enabling Automatic Backups

**Navigate to:** Settings → Backup → Scheduled Backups

1. Toggle **Daily Backups (03:00 local time)** on
2. Use the **Retention Period** slider to choose how long to keep backups:
   - 1 day, 7 days, 14 days, 21 days, or 30 days
3. Backups run automatically every night at 03:00 in the server's local timezone

!!! tip "Timezone Configuration"
    The backup time uses the server's local timezone, configured via the `TZ` environment variable.
    See [Environment Variables](../configuration/environment.md#tz) for details.

### Retention Policy

- Scheduled backups are stored in `data/backup/`
- Backups older than the configured retention period are automatically deleted
- **Immediate cleanup:** When you reduce the retention period (e.g., from 30 to 7 days), old backups are deleted immediately
- Manual downloads are not affected by retention

### Disk Space Monitoring

WireBuddy monitors available disk space and displays a warning when:

- Less than 500MB free space remains
- Free space is less than 2× the current backup size

!!! tip "Offsite Backups"
    Scheduled backups remain on the server. For disaster recovery, periodically download manual backups and store them offsite.

## Restoring a Backup

!!! danger "Destructive Operation"
    Restoring a backup **overwrites all current configuration** including peers, users, interfaces, DNS rules, and certificates. The application will restart automatically after restore.

### Restore Process

**Navigate to:** Settings → Backup → Restore (Danger Zone)

1. Click **Choose File** and select your backup file (`.tar.gz`)
2. Click **Restore Backup**
3. WireBuddy validates the backup's HMAC signature
4. If valid, enter your **admin password** to confirm
5. Wait for the application to restart

### Restore Verification

WireBuddy performs several safety checks during restore:

- **HMAC Verification** - Ensures the backup matches the configured `WIREBUDDY_SECRET_KEY`; legacy backups from older releases are also accepted when the embedded database snapshot matches the current secret key
- **Archive Integrity** - Validates the tar.gz structure
- **Path Traversal Protection** - Prevents malicious file extraction outside data directory

!!! warning "Secret Key Compatibility"
    New backups are signed from `WIREBUDDY_SECRET_KEY`, so they can be restored on a replacement WireBuddy installation configured with the same secret key.
    Legacy backups created by older releases remain restorable on the original instance and are also accepted when the embedded backup database matches the current secret key.

### Automatic Rollback

If the restore fails mid-process, WireBuddy attempts to roll back to the previous state to prevent data loss.

## API Endpoints

For automation and scripting, the backup functionality is available via REST API:

### Get Backup Settings

```http
GET /api/backup/settings
```

Returns current backup configuration and statistics.

**Response:**
```json
{
  "scheduled_enabled": true,
  "last_backup_at": "2026-03-23T14:52:30.123456",
  "backup_count": 12,
  "retention_days": 30,
  "backup_size_bytes": 52428800,
  "disk_free_bytes": 10737418240,
  "disk_warning": false,
  "include_tsdb_metrics": true,
  "tsdb_range": "30d"
}
```

### Update Backup Settings

```http
PATCH /api/backup/settings
Content-Type: application/json

{
  "scheduled_enabled": true,
  "retention_days": 14,
  "include_tsdb_metrics": true,
  "tsdb_range": "30d"
}
```

Valid `retention_days` values: `1`, `7`, `14`, `21`, `30`

Valid `tsdb_range` values: `"7d"`, `"30d"`, `"90d"`, `"180d"`, `"1y"`

Set `include_tsdb_metrics: false` to create settings-only backups (equivalent to "Settings only" in the UI).

### Create & Download Backup

```http
POST /api/backup/download
```

Returns the backup archive as a streaming response with `Content-Disposition` header.

### Validate Backup

```http
POST /api/backup/validate
Content-Type: multipart/form-data

file: <backup.tar.gz>
```

Validates the HMAC signature without restoring. Use this to verify backup integrity before prompting for password.

### Restore Backup

```http
POST /api/backup/restore
Content-Type: multipart/form-data

file: <backup.tar.gz>
password: <admin_password>
```

Requires admin password for confirmation. The application will restart after successful restore.

!!! note "Admin Required"
    All backup endpoints require admin authentication.

## Troubleshooting

### Disk Space Warning

If you see the "Low disk space" warning:

1. Delete old manual backups from your local machine
2. Reduce the retention period using the slider
3. Free up disk space on the server
4. Check that the backup directory isn't filling up with other files

### Backup Creation Fails

- **Disk Space** - Ensure at least 100MB free space in the data directory
- **Database Lock** - If another process holds a write lock, wait and retry
- **Permissions** - The data directory must be writable by the WireBuddy process

### Restore Fails with HMAC Mismatch

The backup was created by a different WireBuddy instance. Each installation has a unique signing key generated on first run.

**Solutions:**

1. Use a backup from the same installation
2. For migration: manually export/import peers and interfaces through the UI

### Application Doesn't Restart After Restore

If the auto-restart fails:

```bash
# Docker
docker restart wirebuddy

# Systemd
sudo systemctl restart wirebuddy
```

## Best Practices

1. **Regular Downloads** - Download manual backups weekly and store offsite
2. **Test Restores** - Periodically verify backups work in a test environment
3. **Before Updates** - Always create a backup before upgrading WireBuddy
4. **Secure Storage** - Backups contain sensitive data (private keys, passwords) - encrypt at rest
