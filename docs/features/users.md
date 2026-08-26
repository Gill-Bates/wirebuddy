# User Management

WireBuddy supports multiple local accounts with administrator and read-only
roles. Administrators manage accounts from the top-level **Users** page.

## Roles

| Role | Access |
|---|---|
| **Administrator** | Full UI and API access, including users, interfaces, peers, DNS, nodes, and settings |
| **User** | Read-only operational access; configuration-changing API calls remain restricted |

The last administrator cannot be demoted or deleted. Administrators also
cannot demote, deactivate, or delete their own account through user management.

## Creating a User

Open **Users → Add User**. A user consists of:

- a unique username
- a password
- the administrator-role switch

WireBuddy does not currently store user email addresses, full names, or profile
descriptions.

Usernames are normalized to lowercase and must:

- contain 3–64 characters
- start and end with a letter or number
- contain only letters, numbers, `-`, or `_`
- avoid consecutive `-`/`_` characters

## Password Policy

Passwords must:

- contain at least 8 characters
- fit within 72 UTF-8 bytes
- avoid control characters and known common passwords
- satisfy at least three of these four categories:
  - uppercase letter
  - lowercase letter
  - number
  - supported special character

The initial `admin` password is generated on first startup and written once to
the application log. First login requires replacing it.

An administrator reset also invalidates the user's sessions and requires the
user to choose a different password at next login. A user changing their own
password must provide the current password.

## Editing and Deleting

Administrators can change another account's username, role, and active status.
Deleting or deactivating an account invalidates its access. Deletion also
removes the account's OTP and passkey records through database relationships.

Users may update their own username through the API, but the current web user
management page is administrator-only.

## TOTP Multi-Factor Authentication

Users can enroll TOTP with an authenticator application. Administrators can
initiate enrollment for another user; that user completes setup on their next
login.

Enrollment flow:

1. Open **Users → OTP Settings** for the account.
2. Start OTP enrollment.
3. The account owner scans the QR code on the OTP setup page.
4. Confirm with a valid 6–8 digit TOTP code.
5. Download and store the one-time recovery-code ZIP.

WireBuddy generates eight single-use recovery codes. Recovery codes are not
returned by later API calls and cannot be regenerated from stored hashes.

Disabling OTP requires reauthentication:

- Account owner: current password or a valid OTP code
- Administrator acting on another user: the administrator's own password

Enabling, confirming, or disabling OTP revokes existing sessions where needed.

## Passkeys

From **Users → Passkey Settings**, an account owner can register and remove
passkeys and optionally assign a device name. Administrators can initiate
passkey onboarding, inspect a user's registered passkeys, disable onboarding,
or reset all passkeys for another user.

The maximum is controlled by `MAX_PASSKEYS_PER_USER` and defaults to 20.

See [Passkeys](../security/passkeys.md) for setup and environment options.

## Sessions

Login creates an opaque session token stored as a hash in SQLite and delivered
to the browser in the `auth_token` cookie.

- Initial idle expiry: 1 hour
- Cookie-authenticated activity extends the idle expiry
- Absolute lifetime: 24 hours from login
- Bearer-token API use does not refresh expiry

Logging out removes the current token. Password changes, password resets, and
security-state changes revoke relevant account sessions.

There is currently no UI for listing devices, revoking an individual remote
session, or changing session duration.

## Login Information

The user table shows the most recent login timestamp and IP address, including
available GeoIP details. WireBuddy does not currently provide a per-user login
history page or a general audit-log export UI.

## API Access

WireBuddy does not have a separate long-lived API-token subsystem. Automation
uses the same opaque session token returned by login:

```bash
curl -H "Authorization: Bearer SESSION_TOKEN" \
  https://vpn.example.com/api/wireguard/peers
```

Bearer use is subject to the same session expiry and account permissions as
browser authentication. See [API Authentication](../api/authentication.md).

## Current User Endpoints

- `GET /api/users`
- `POST /api/users`
- `GET /api/users/{user_id}`
- `PATCH /api/users/{user_id}`
- `DELETE /api/users/{user_id}`
- `POST /api/users/{user_id}/change-password`
- `POST /api/users/me/complete-required-change`
- `POST /api/users/{user_id}/reset-password`
- `POST /api/users/{user_id}/otp/enable`
- `POST /api/users/{user_id}/otp/confirm`
- `POST /api/users/{user_id}/otp/disable`

Permissions differ by endpoint; consult [API Endpoints](../api/endpoints.md)
and Swagger for schemas.

## Best Practices

- Use a separate account for each administrator.
- Register passkeys or enable TOTP for administrator accounts.
- Keep recovery-code downloads offline and protected.
- Disable accounts immediately when access is no longer needed.
- Use HTTPS and configure trusted proxy CIDRs precisely.

## Related

- [Authentication](../security/authentication.md)
- [Passkeys](../security/passkeys.md)
- [Security Best Practices](../security/best-practices.md)
