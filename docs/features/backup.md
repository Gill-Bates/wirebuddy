---
title: Backup & Restore
---

# Backup & Restore

WireBuddy provides comprehensive backup and restore functionality to protect your configuration and data.

## Overview

The Backup module provides:

- 💾 **Manual Backups** - Create and download configuration snapshots on demand
- ⏰ **Scheduled Backups** - Automatic daily backups at 03:00 UTC
- 🔄 **One-Click Restore** - Restore from any backup with HMAC verification
- 🗑️ **Automatic Rotation** - Old backups are automatically purged after 30 days
- 🔐 **Integrity Protection** - HMAC signing prevents tampering and ensures backups are from the same instance

## What's Included

Each backup contains a complete snapshot of your WireBuddy installation:

| Component | Description |
|-----------|-------------|
| **Database** | All peers, interfaces, users, and settings (`wirebuddy.db`) |
| **DNS Data** | Custom rules, blocklist state, and DNS configuration |
| **Certificates** | Let's Encrypt certificates and private keys |
| **GeoLite2** | GeoIP database files |
| **Traffic Data** | Time-series metrics and statistics |

!!! info "Backup Format"
    Backups are stored as `.tar.gz` archives with an embedded HMAC signature for integrity verification.

## Manual Backup

### Creating a Backup

**Navigate to:** Settings → Backup

1. Click **Create & Download Backup**
2. The backup is generated and downloaded automatically
3. Store the `.tar.gz` file in a secure location

The backup filename includes a timestamp: `wirebuddy_backup_20260323_145230.tar.gz`

### Backup Statistics

The backup card displays:

- **Last Backup** - Timestamp of the most recent backup (manual or scheduled)
- **Stored Backups** - Number of scheduled backups on the server

## Scheduled Backups

### Enabling Automatic Backups

**Navigate to:** Settings → Backup → Scheduled Backups

1. Toggle **Daily Backups (03:00 UTC)** on
2. Backups run automatically every night

### Retention Policy

- Scheduled backups are stored in `data/backup/`
- Backups older than **30 days** are automatically deleted
- Manual downloads are not affected by retention

!!! tip "Offsite Backups"
    Scheduled backups remain on the server. For disaster recovery, periodically download manual backups and store them offsite.

## Restoring a Backup

!!! danger "Destructive Operation"
    Restoring a backup **overwrites all current configuration** including peers, users, interfaces, DNS rules, and certificates. The application will restart automatically after restore.

### Restore Process

**Navigate to:** Settings → Backup → Restore (Danger Zone)

1. Select your backup file (`.tar.gz`)
2. Type `RESTORE` in the confirmation field
3. Click **Restore Backup**
4. Wait for the application to restart

### Restore Verification

WireBuddy performs several safety checks during restore:

- **HMAC Verification** - Ensures the backup was created by this WireBuddy instance
- **Archive Integrity** - Validates the tar.gz structure
- **Path Traversal Protection** - Prevents malicious file extraction outside data directory

!!! warning "Instance Lock-In"
    Backups are cryptographically signed with an instance-specific secret. You cannot restore a backup from a different WireBuddy installation.

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
  "backup_count": 12
}
```

### Update Backup Settings

```http
PATCH /api/backup/settings
Content-Type: application/json

{
  "scheduled_enabled": true
}
```

### Create & Download Backup

```http
POST /api/backup/download
```

Returns the backup archive as a streaming response with `Content-Disposition` header.

### Restore Backup

```http
POST /api/backup/restore
Content-Type: multipart/form-data

file: <backup.tar.gz>
```

!!! note "Admin Required"
    All backup endpoints require admin authentication.

## Troubleshooting

### Backup Creation Fails

- **Disk Space** - Ensure sufficient space in `/tmp` and `data/` directories
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
