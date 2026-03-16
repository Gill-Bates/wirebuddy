# User Management

WireBuddy supports multi-user environments with role-based access control.

## User Roles

| Role | Permissions |
|------|-------------|
| **Admin** | Full access: create/modify/delete interfaces, peers, users, and settings |
| **User** | Read-only: view dashboard, peers, DNS logs; cannot modify configuration |

## User Administration

### Adding Users

**Navigate to:** Settings → Users → Add User

**Required:**

- **Username:** Unique alphanumeric identifier (3-32 characters)
- **Email:** Valid email address (used for notifications, future MFA recovery)
- **Password:** Must meet complexity requirements
- **Role:** Admin or User

**Optional:**

- **Full Name:** Display name
- **Description:** Notes about the user

### Password Requirements

Passwords must meet these criteria:

- Minimum 8 characters
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one number (0-9)
- At least one special character (!@#$%^&*)

### Editing Users

**Settings → Users → [Select User] → Edit**

Admins can modify:

- Email address
- Full name
- Role
- Password (force reset)

Users cannot:

- Change their own role
- Delete their own account (requires another admin)

### Deleting Users

**Settings → Users → [Select User] → Delete**

- Permanently removes user account
- Invalidates all sessions
- Disables MFA and passkeys
- Cannot be undone

!!! warning "Admin Account"
    At least one admin account must exist. You cannot delete the last admin.

## Multi-Factor Authentication (MFA)

### TOTP (Time-based One-Time Password)

**Setup:**

1. User navigates to **Profile → Security → Enable 2FA**
2. Scan QR code with authenticator app:
   - Google Authenticator
   - Authy
   - Microsoft Authenticator
   - 1Password
   - Bitwarden
3. Enter 6-digit code to verify
4. Save recovery codes (10 single-use codes)

**Login with MFA:**

1. Enter username and password
2. Enter 6-digit TOTP code
3. Optionally check "Trust this device for 30 days"

**Disable MFA:**

- User: Profile → Security → Disable 2FA (requires current code)
- Admin: Settings → Users → [Select User] → Disable MFA

### Passkeys (WebAuthn)

For passwordless authentication, see [Passkeys Documentation](../security/passkeys.md).

## Recovery Codes

When enabling MFA, users receive 10 recovery codes.

**Usage:**

- Each code can be used once
- Used in place of TOTP code during login
- Example: `ABCD-1234-EFGH`

**Lost Recovery Codes:**

1. Login with passkey or password+TOTP
2. Navigate to Profile → Security → Recovery Codes
3. Click **Regenerate** (invalidates old codes)

**Admin Recovery:**

Admins can disable MFA for locked-out users:

1. Settings → Users → [Select User]
2. Click **Disable MFA**
3. User can login with password only
4. User should re-enable MFA immediately

## Session Management

### Session Duration

**Settings → Security → Session Timeout**

Options:

- 15 minutes (high security)
- 30 minutes (default)
- 1 hour (convenience)
- 4 hours (maximum)

Sessions automatically renew on activity.

### Active Sessions

**Profile → Security → Active Sessions**

View all active login sessions:

| Device | Location | IP Address | Last Activity | Actions |
|--------|----------|------------|---------------|---------|
| Chrome (Linux) | San Francisco | 203.0.113.42 | 2 minutes ago | Current |
| Firefox (Windows) | New York | 198.51.100.10 | 1 hour ago | [Revoke] |

**Revoke Session:**

Click **Revoke** to immediately log out that session.

**Revoke All:**

Click **Revoke All Other Sessions** to keep only current session active.

## Login Tracking

WireBuddy logs all authentication events:

- Successful logins
- Failed login attempts
- Password changes
- MFA enrollment/disable
- Passkey registration/use

**View Login History:**

**Profile → Security → Login History**

| Timestamp | Event | IP Address | Status | Details |
|-----------|-------|------------|--------|---------|
| 2026-03-15 14:23 | Login | 203.0.113.42 | Success | Password + TOTP |
| 2026-03-15 09:15 | Login | 203.0.113.42 | Success | Passkey |
| 2026-03-14 22:10 | Login | 198.51.100.99 | Failed | Invalid password |

## API Tokens

For programmatic access, users can generate API tokens.

### Creating API Tokens

**Profile → API Tokens → Create Token**

**Configuration:**

- **Name:** Descriptive label (e.g., "Ansible Automation")
- **Expiration:** Never, 30 days, 90 days, 1 year
- **Permissions:** Read-only or Full access (admin only)
- **IP Whitelist:** Optional IP restrictions

**Token Security:**

- Tokens are shown only once after creation
- Stored as SHA-256 hash in database
- Cannot be retrieved after initial display

### Using API Tokens

Include token in `Authorization` header:

```bash
curl -H "Authorization: Bearer your_token_here" \
  https://vpn.example.com/api/peers
```

### Revoking Tokens

**Profile → API Tokens → [Select Token] → Revoke**

Immediately invalidates the token.

## Read-Only Users

Users with "User" role have read-only access:

**Allowed:**

- ✅ View dashboard
- ✅ View peer list and status
- ✅ View traffic statistics
- ✅ View DNS logs
- ✅ Export data

**Denied:**

- ❌ Create/edit/delete peers
- ❌ Start/stop interfaces
- ❌ Modify settings
- ❌ Manage users
- ❌ Access API with write permissions

This is useful for:

- NOC (Network Operations Center) monitoring
- Helpdesk support staff
- Auditors
- Customers (in managed VPN scenarios)

## Best Practices

### Admin Accounts

- Limit number of admin accounts (principle of least privilege)
- Each admin should have their own account (no shared accounts)
- Enable MFA on all admin accounts
- Regularly review admin access

### Password Policy

- Enforce strong passwords (WireBuddy does this by default)
- Require password changes after suspected compromise
- Use passkeys where possible (more secure than passwords)

### Session Security

- Use 30-minute session timeout (default)
- Revoke unused sessions regularly
- Enable "Remember this device" only on trusted devices
- Always log out on shared computers

### API Token Management

- Use minimal permissions (read-only when possible)
- Set expiration dates (avoid "never expire")
- Use IP whitelisting for automated systems
- Rotate tokens annually
- Revoke tokens immediately when no longer needed

### Audit

- Review login history regularly
- Investigate failed login attempts
- Monitor for unusual activity patterns
- Enable alerts for suspicious logins (future feature)

## Next Steps

- [Passkeys (WebAuthn)](../security/passkeys.md) - Passwordless authentication
- [Authentication Guide](../security/authentication.md) - Technical details
- [Security Best Practices](../security/best-practices.md) - Hardening guide
- [API Reference](../api/authentication.md) - API token usage
