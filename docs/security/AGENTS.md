<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# security

## Purpose
Explains WireBuddy's security model and how operators should harden a deployment: authentication and MFA, passkeys, sessions/CSRF, rate limiting and lockouts, and deployment best practices.

## Key Files
| File | Description |
|------|-------------|
| `overview.md` | Security overview: authz, sessions and browser protection, secrets at rest, proxy/host trust, rate limiting, container/network boundary, operational controls |
| `authentication.md` | Authentication methods, core login flow, password security, MFA, passkeys, session model, API notes, CSRF |
| `passkeys.md` | WebAuthn passkeys: how they work, supported authenticators and browsers, setup, management, configuration, current API endpoints |
| `rate-limiting.md` | Goals, effective limits, lockout behaviour, response semantics, operational guidance, automation example |
| `best-practices.md` | Hardening checklist: protect the secret key, replace bootstrap password, strong auth, HTTPS, network exposure, host networking, WireGuard and DNS hardening |

## For AI Agents

### Working In This Directory
- Claims must match code (`app/` auth, sessions, rate limiting); when behaviour changes, update the matching pages here and in `../configuration/security.md`.
- Never document real secrets; describe generation only.

### Testing Requirements
- `mkdocs build -f docs/mkdocs.yml --strict`. Related code is covered by `tests/test_login_lockout.py`, `tests/test_user_security.py`, `tests/test_audit_hardening.py`.

### Common Patterns
- Concept explanation followed by operator recommendations.

## Dependencies

### Internal
- `../configuration/security.md`, `../configuration/environment.md`, `../features/users.md`, `../api/authentication.md`.

### External
- WebAuthn browser/authenticator support; TOTP apps.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
