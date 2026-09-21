//
// tools/stylelint/stylelint.config.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//
// Lints app/static/css/**/*.css. Complements tools/ui-lint, which audits the
// *rendered* result (design-token drift, layout, accessibility) in a browser;
// this catches source-level CSS defects before anything is ever rendered -
// most importantly the class of bug found in a review of wb-ui-system.css:
// two same-specificity selectors for the same property landing in cascade
// order rather than by design (no-duplicate-selectors,
// no-descending-specificity), and unscoped `!important` overrides of
// Bootstrap utility classes that silently win over more specific responsive
// variants.
//
// Most of the tree is clean; see tools/stylelint/AGENTS.md for the fixes that
// took (icon/text margin doubling in wb-ui-system.css, a missing
// core/tokens.css import on the status pages, a dropdown escaping its clipped
// .card ancestor - all found by running this for the first time). What is
// still open is concentrated in dashboard.css/pages/dashboard.css, which is
// mid-migration to the components/pages split and currently defines its KPI
// card selectors twice in sequence (a base layout pass, then a "KPI
// refinement" pass) rather than once - no-duplicate-selectors and
// no-descending-specificity correctly flag that, and it is real duplication
// worth resolving, just not by a mechanical --fix while the migration is
// still moving. `npm run lint` is not yet a gate for this reason; see
// AGENTS.md for the promotion criterion.

export default {
    extends: ['stylelint-config-standard'],
    rules: {
        // The Bootstrap Sass source (vendored as compiled CSS, not linted
        // here) and this project's own low-specificity utility layers
        // (utilities/*.css, wb-ui-system.css Section 22-23) rely on
        // `!important` to reliably win over Bootstrap's own utility classes.
        // Banning it outright would fight the existing architecture; the
        // real risk - two `!important` declarations for the same property
        // whose winner depends on source order rather than intent - is
        // covered by no-duplicate-selectors and no-descending-specificity
        // instead, which flag the actual conflict rather than the tool used
        // to win it.
        'declaration-no-important': null,

        // Catches exactly the wb-ui-system.css class of bug: two selectors
        // of equal specificity targeting the same element for the same
        // property, where the second one's precedence is an accident of
        // file order rather than a documented decision. When a later rule is
        // genuinely meant to narrow an earlier one (e.g. `:not(...)` opt-outs
        // living in Section 5/13 of wb-ui-system.css), express that with a
        // more specific selector or a comment - not by relying on cascade
        // order between equal-specificity rules.
        'no-descending-specificity': true,

        // A second rule block for the same selector in one file is either a
        // leftover from editing or a real conflict; both should be merged
        // into one rule so cascade order is not doing unintended work.
        'no-duplicate-selectors': true,

        // pages/*.css are deliberately @import-only aggregators (see
        // dashboard.css/pages/dashboard.css, dns.css/pages/dns.css - the
        // project is mid-migration to that split). @import is therefore a
        // real part of the architecture here, not a performance smell to ban.
        'no-invalid-position-at-import-rule': true,

        // The project's own custom properties (--wb-*) intentionally have no
        // registered syntax, so this only needs to know the two vendor
        // prefixes already in use project-wide.
        'custom-property-pattern': null,

        // Two conventions coexist by design, not by accident: most IDs are
        // kebab-case (#peer-filter, #log-table-wrap), but a handful -
        // #settingsTabs, #settingsTabContent, #wbToastContainer,
        // #wbReconnectModal, #keyMismatchBanner - are camelCase because they
        // are referenced by that exact string in templates and in several
        // app/static/js/*.js files (document.getElementById(...),
        // querySelector('#settingsTabs ...')). Auto-fixing the CSS selector to
        // kebab-case would silently detach these rules from the markup they
        // style; --fix cannot touch the HTML/JS side of that reference. The
        // rule now enforces kebab-case-or-camelCase, which still catches the
        // one real defect this was written for: mixed case within a single
        // multi-word segment (fooBar-baz), which is neither convention and is
        // a stylelint-config-standard finding worth keeping.
        'selector-id-pattern': '^([a-z][a-z0-9]*)(-[a-z][a-z0-9]*)*$|^[a-z][a-zA-Z0-9]*$',

        // `word-break: break-word` is deprecated in the spec in favour of
        // `overflow-wrap: anywhere`, but every occurrence in this project
        // (pages/nodes.css, pages/settings.css) already sets both, in that
        // order, as a deliberate fallback for engines that do not honour
        // `anywhere` - removing the deprecated line would remove the
        // fallback, not modernise it. Flagged with a comment at each site
        // instead of disabled globally, so a genuinely new,
        // fallback-free use of the deprecated keyword still gets caught.
        'declaration-property-value-keyword-no-deprecated': [true, { severity: 'warning' }],

        // Almost the whole project is plain kebab-case, but
        // pages/dashboard.css uses BEM modifier syntax
        // (.dashboard-kpi-metric--down / --up), matched verbatim in
        // templates/dashboard.html. Same reasoning as selector-id-pattern
        // above: fixing the CSS side alone would desync it from the HTML.
        // Allows one `--modifier` suffix in addition to plain kebab-case,
        // rather than opening the pattern up generally.
        'selector-class-pattern': '^([a-z][a-z0-9]*)(-[a-z0-9]+)*(--[a-z][a-z0-9]*)?$',

        // Tabs vs. spaces and similar house-style calls are deliberately left
        // to stylelint-config-standard's defaults rather than re-litigated
        // here; narrow per-line exceptions belong at the declaration, not in
        // a growing local override list.
    },
    ignoreFiles: [
        // Vendored, not authored here; upstream's formatting is out of scope.
        '../../app/static/vendor/**/*.css',
    ],
};
