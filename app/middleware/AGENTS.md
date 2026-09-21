<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->

# middleware

## Purpose
Starlette middleware specific to WireBuddy. Currently only CSRF protection for UI and cookie-authenticated API requests. (`RequestIDMiddleware` lives in `app/utils/request_id.py`; `TrustedHostMiddleware` is configured in `app/main.py`.)

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Package docstring / exports |
| `csrf.py` | `CSRFMiddleware`: checks Origin/Referer and a CSRF token for unsafe methods on `/ui/`, `/login`, `/api/` prefixes; header-only bearer requests and listed exempt API paths (e.g. `/api/login`) are skipped; sets the CSRF cookie |

## For AI Agents

### Working In This Directory
- Python files use **tabs** and start with the standard header block (`#!/usr/bin/env python3`, file path, `Copyright (C) 2026 Gill-Bates`, SPDX MIT); keep that style.
- Any new state-changing public endpoint that must work without cookies has to be added to the exempt set deliberately and justified.
- Middleware is registered in `create_app` in `app/main.py`; order matters.

### Testing Requirements
- `pytest tests/test_csrf_middleware.py` locks every CSRF decision against a minimal app; extend it for any change here, covering both cookie-auth and bearer-only requests.

### Common Patterns
- Subclass `BaseHTTPMiddleware`; return `JSONResponse` for API paths and rejections.
- Compare origins as (scheme, host, port) tuples via `_origin_tuple`.

## Dependencies

### Internal
- `app/main.py` (registration), `app/api/frontend_shared.py` (token provisioning).

### External
- Starlette, FastAPI.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
