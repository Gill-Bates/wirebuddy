<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-10-01 | Updated: 2026-10-01 -->
# stylelint

## Purpose

Standalone Stylelint setup (private ES-module package `wirebuddy-stylelint`) for the app's own CSS under `app/static/css/`. It catches source-level defects (duplicate selectors, descending specificity, unscoped overrides) before rendering; `../ui-lint` audits the rendered result in a browser instead. Vendored CSS in `app/static/vendor/` is ignored.

## Key Files

| File | Description |
|---|---|
| `package.json` | Scripts `lint` and `lint:fix` (both lint `../../app/static/css/**/*.css` with `stylelint.config.mjs`); dependencies `stylelint` and `stylelint-config-standard` |
| `package-lock.json` | Lock file for those dependencies |
| `stylelint.config.mjs` | Extends `stylelint-config-standard`; each rule override carries its reasoning in a comment (`!important` allowed, `no-descending-specificity` and `no-duplicate-selectors` on, ID/class patterns that tolerate camelCase IDs and one BEM `--modifier`, deprecated `word-break` keyword as warning) |

## For AI Agents

### Working In This Directory

- Never descend into or edit `node_modules/` (git-ignored).
- Fix the CSS rather than loosening a rule. A new override belongs in `stylelint.config.mjs` with its reasoning beside it.
- The selector patterns mirror names used verbatim in templates and `app/static/js/*.js`; do not rename a selector to satisfy a pattern without changing the HTML/JS side too.
- Do not run `lint:fix` blindly on `dashboard.css` and `pages/dashboard.css`: they are mid-migration to the components/pages split and define KPI selectors twice, which `--fix` cannot resolve.

### Testing Requirements

- No CI workflow runs this tool, and `npm run lint` is not a gate yet; the config states the promotion criterion.
- Run locally:

  ```bash
  cd tools/stylelint
  npm install
  npm run lint        # report only
  npm run lint:fix    # apply safe autofixes, then review the diff
  ```

### Common Patterns

- Config comments explain why a rule is relaxed, not what it does; keep that style.

## Dependencies

### Internal

- `../../app/static/css/` (the linted tree); `../../app/static/vendor/` is excluded.
- `../ui-lint/` is the complementary rendered-output audit.

### External

- Node.js (ES modules), `stylelint`, `stylelint-config-standard`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
