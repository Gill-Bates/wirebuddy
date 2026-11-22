<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->

# models

## Purpose
Pydantic request/response models for users/authentication and WireGuard peers; their validators normalise and reject unsafe input before it reaches the API and DB layers.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Package docstring; re-exports the main user and peer models |
| `users.py` | `LoginRequest`, `MFAVerifyRequest`, `OTPConfirmRequest`, `OTPDisableRequest`, `RecoveryDownloadRequest`, `UserCreate/Update/Public`, password change/reset requests; username, TOTP-code, opaque-token and password-strength validators |
| `peers.py` | `PeerCreate`, `PeerUpdate`, `PeerPublic`, `PeerConfig`, `PeerStats` and validators for keys, CIDR/IP lists, hostnames, endpoints, interface lists, blocklist and node IDs |

## For AI Agents

### Working In This Directory
- Keep validation here consistent with the DB-layer `_validate_*` helpers; loosening one without the other creates gaps.
- `*Public` models must never include secrets (password hashes, private keys, OTP secrets).

### Testing Requirements
- `pytest` in `/opt/wirebuddy/tests` (`test_user_security.py` covers user/password validation).

### Common Patterns
- `field_validator` functions with module-level `_validate_*` helpers; comma-separated strings are parsed by `_parse_comma_separated_list`.

## Dependencies

### Internal
- `app/utils/crypto.py` (`MAX_PASSWORD_BYTES`); consumed by `app/api/*` and `app/tasks/scheduled.py`.

### External
- Pydantic v2.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
