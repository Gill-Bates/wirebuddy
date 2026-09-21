<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# api

## Purpose
Reference documentation for the WireBuddy REST API: base URL and endpoint families, how clients authenticate (session/token and node sync), and a resource-by-resource endpoint list.

## Key Files
| File | Description |
|------|-------------|
| `overview.md` | Base URL, authentication summary, endpoint families, OpenAPI docs location, example call, rate limiting |
| `authentication.md` | Authentication modes, obtaining an auth token, node sync authentication, error semantics, security recommendations, examples |
| `endpoints.md` | Authentication model and endpoints grouped by resource, plus notes |

## For AI Agents

### Working In This Directory
- Verify each route, method and auth requirement against `app/api/` before documenting; the live OpenAPI schema is authoritative.
- Use placeholder tokens in examples, never real ones.

### Testing Requirements
- `mkdocs build -f docs/mkdocs.yml --strict` to validate links.

### Common Patterns
- Tables of method/path/description, curl examples, "Next Steps" footer.

## Dependencies

### Internal
- `app/api/` routers, `../security/authentication.md`, `../security/rate-limiting.md`, `../features/multi-node.md`.

### External
- None (FastAPI-generated OpenAPI).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
