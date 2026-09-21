<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# fragments

## Purpose
HTML fragments that are not full pages and are loaded lazily by JavaScript rather than extended or included at render time.

## Key Files
| File | Description |
|------|-------------|
| `onboarding_modal.html` | Bootstrap "Welcome to WireBuddy" modal (`#wbOnboardingModal`), fetched by `static/js/onboarding.js` |

## For AI Agents
### Working In This Directory
- Keep IDs in sync with `static/js/onboarding.js`; markup must be self-contained (no `extends`).

### Testing Requirements
`node tools/ui-lint/run-ui-lint.mjs`; trigger onboarding in the browser.

### Common Patterns
- Root element is the Bootstrap modal; styling classes live in the global CSS.

## Dependencies
### Internal
- `../../static/js/onboarding.js`, `../../static/css/`.
### External
- Bootstrap modal JS.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
