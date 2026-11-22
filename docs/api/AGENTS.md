<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# api

## Purpose
Reference documentation for the WireBuddy REST API: base URL and endpoint families, how clients authenticate (session/token and node sync), and the full `/api` route list.

## Key Files
| File | Description |
|------|-------------|
| `overview.md` | Base URL, authentication summary, endpoint-family table, OpenAPI docs location (`/swagger`), example call, rate limiting |
| `authentication.md` | Authentication modes, obtaining an auth token, node sync authentication (enrollment token, Bearer secret, optional trusted-proxy certificate fingerprint), error semantics, security recommendations, examples |
| `endpoints.md` | Method/path tables grouped by resource, generated from `app.openapi()` of `create_app()`; carries a `Generated:` date and `Total endpoints:` count; `include_in_schema=False` routes are not listed |

## For AI Agents

### Working In This Directory
- Verify each route, method and auth requirement against `app/api/` before documenting; the live OpenAPI schema is authoritative.
- When routes change, regenerate the `endpoints.md` tables from `app.openapi()` (only `/api` paths) and update its `Generated:` date and `Total endpoints:` count together.
- Use placeholder tokens in examples (`YOUR_AUTH_TOKEN`, `$TOKEN`), never real ones.

### Testing Requirements
- Strict Zensical build, see `../AGENTS.md`.

### Common Patterns
- Tables of path or method/path, curl examples, "Next Steps" footer.

## Dependencies

### Internal
- `app/api/` routers, `../security/authentication.md`, `../security/rate-limiting.md`, `../features/multi-node.md`.

### External
- None (FastAPI-generated OpenAPI).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
