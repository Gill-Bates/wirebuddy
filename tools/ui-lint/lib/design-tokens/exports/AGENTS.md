<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# exports

## Purpose

Serialisable views of a token snapshot for audits and browser injection.

## Key Files

| File | Description |
|---|---|
| `serializable.mjs` | `buildSerializableTokenPayload(snapshot,{category})` (structured clone) |
| `audit-snapshots.mjs` | `buildAuditTokenSnapshot` |
| `browser-payloads.mjs` | `buildBrowserTokenPayload` |

## For AI Agents

### Working In This Directory

- No special constraints beyond the parent directory guidance.

### Testing Requirements

- Covered by `tests/config/design-token-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- No special constraints beyond the parent directory guidance.

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
