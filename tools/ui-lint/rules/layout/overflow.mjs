//
// tools/ui-lint/rules/layout/overflow.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Rule: Detect horizontal overflow and content clipping issues.
//

import { registerRule, RuleBuilder } from '../../lib/rule-registry.mjs';
import {
    classifyOverflowIssue,
    collectOverflowDiagnostics,
} from '../../lib/layout-diagnostics.mjs';

export const meta = {
    id: 'horizontal-overflow',
    category: 'layout',
    severity: 'warning',
    browsers: ['chromium', 'webkit', 'firefox'],
    devices: ['desktop', 'tablet', 'mobile'],
    requires: ['dom-snapshot'],
    optional: ['interaction'],
    capabilities: ['dom'],
    performanceCost: 'cheap',
    tags: ['layout', 'responsive', 'scroll'],
    executionMode: 'parallel',
    severityByBrowser: {
        webkit: 'serious',
    },
};

/**
 * Elements that are allowed to have overflow.
 */
const OVERFLOW_ALLOWED = [
    '.leaflet-tile-container',
    '.leaflet-tile',
    '#settingsTabs .nav-item',
    '#settingsTabs .nav-link',
    '.code-block',
    'pre',
    'code',
];

const overflowRule = RuleBuilder.layout(
    'horizontal-overflow',
    'Horizontal overflow detection',
    async (context) => {
        const { page } = context;
        const findings = [];

        const diagnostics = await page.evaluate(collectOverflowDiagnostics, {
            allowedSelectors: OVERFLOW_ALLOWED,
            tolerance: 2,
            browser: context.browser || null,
            scope: context.scope || null,
        });

        const viewport = page.viewportSize() || { width: 1440, height: 1100 };

        for (const issue of diagnostics.issues) {
            const finding = classifyOverflowIssue(issue, {
                browser: context.browser || null,
                component: context.component || context.scope || null,
                scope: context.scope || null,
                viewport,
                tolerance: 2,
            });

            if (!finding) continue;

            findings.push(finding);
        }

        return findings;
    }
);

overflowRule.meta = meta;

registerRule(overflowRule);

export default overflowRule;
