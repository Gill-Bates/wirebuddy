<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->

# models

## Purpose
Pydantic request/response models with field validation for users/authentication and WireGuard peers. Validators normalise and reject unsafe input (usernames, password strength, WireGuard keys, CIDR/IP lists, hostnames, endpoints, blocklist IDs) before it reaches the API and DB layers.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Package docstring |
| `users.py` | `LoginRequest`, `MFAVerifyRequest`, `OTPConfirmRequest`, `OTPDisableRequest`, `RecoveryDownloadRequest`, `TokenResponse`, `UserCreate/Update/Public`, password change/reset requests; username and password-strength validators |
| `peers.py` | `PeerCreate`, `PeerUpdate`, `PeerPublic`, `PeerConfig`, `PeerStats` and validators for keys, CIDR/IP lists, hostnames, endpoints, interface lists, blocklist and node IDs |

## For AI Agents

### Working In This Directory
- Python files use **tabs** and start with the standard header block (`#!/usr/bin/env python3`, file path, `Copyright (C) 2026 Gill-Bates`, SPDX MIT); keep that style.
- Keep validation here consistent with the DB-layer `_validate_*` helpers; loosening one without the other creates gaps.
- `*Public` models must never include secrets (password hashes, private keys, OTP secrets).

### Testing Requirements
- `pytest` in `/opt/wirebuddy/tests` (`test_user_security.py` covers user/password validation).

### Common Patterns
- `field_validator` functions with module-level `_validate_*` helpers; comma-separated strings are parsed by `_parse_comma_separated_list`.

## Dependencies

### Internal
- Consumed by `app/api/*`; may share validation rules with `app/db`.

### External
- Pydantic v2.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
