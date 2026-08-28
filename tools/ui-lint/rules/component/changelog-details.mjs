//
// tools/ui-lint/rules/component/changelog-details.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Rule: The About page changelog keeps its disclosure semantics intact.

import { registerRule, RuleBuilder } from '../../lib/rule-registry.mjs';

export const meta = {
    id: 'changelog-details',
    category: 'component',
    severity: 'error',
    browsers: ['chromium', 'webkit', 'firefox'],
    devices: ['desktop', 'tablet', 'mobile'],
    requires: ['dom-snapshot'],
    capabilities: ['dom'],
    performanceCost: 'cheap',
    tags: ['about', 'changelog', 'disclosure'],
    executionMode: 'parallel',
    scopes: ['about'],
};

const changelogDetailsRule = RuleBuilder.component(
    'changelog-details',
    'Changelog disclosure semantics',
    async ({ page, browser, scope }) => {
        const diagnostics = await page.evaluate(() => {
            const root = document.querySelector('.about-changelog-col');
            if (!root) return { present: false };
            const details = root.querySelector(':scope > details, details');
            if (!details) return { present: true, hasDetails: false };
            return {
                present: true,
                hasDetails: true,
                hasSummary: Boolean(details.querySelector(':scope > summary')),
            };
        });

        if (!diagnostics.present || (diagnostics.hasDetails && diagnostics.hasSummary)) return [];

        const kind = !diagnostics.hasDetails ? 'changelog-details-missing' : 'changelog-summary-missing';
        return [{
            severity: 'error',
            kind,
            message: !diagnostics.hasDetails
                ? 'Changelog must be wrapped in a details disclosure'
                : 'Changelog details must have a summary label',
            selector: '.about-changelog-col details',
            details: { browser: browser || null, scope: scope || null },
        }];
    },
);

changelogDetailsRule.meta = meta;

registerRule(changelogDetailsRule);

export default changelogDetailsRule;
