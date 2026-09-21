<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# components

## Purpose

Component contracts describing expected badge, card, KPI card, modal, slider, form, About and status styling.

## Key Files

| File | Description |
|---|---|
| `contracts.mjs` | `BADGE_CONTRACT`, `CARD_CONTRACT`, `KPI_CARD_CONTRACT`, `MODAL_CONTRACT`, `SLIDER_CONTRACT`, `FORM_CONTRACT`, `ABOUT_CONTRACT`, `STATUS_CONTRACT`, `COMPONENT_CONTRACTS` |

## For AI Agents

### Working In This Directory

- Changing a contract value changes lint verdicts across the whole app; check the matching CSS token first.

### Testing Requirements

- Covered by `tests/config/config-platform.spec.js`, `tests/findings/layout-policy.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../tokens/resolver.mjs`

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
