//
// tools/ui-lint/rules/layout/overflow.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//
// Rule: Detect horizontal overflow and content clipping issues.
//

import { registerRule, RuleBuilder } from '../../lib/rule-registry.mjs';

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

        const overflowIssues = await page.evaluate((allowedSelectors) => {
            const issues = [];
            const viewportWidth = window.innerWidth;
            const TOLERANCE = 2; // px

            const isAllowed = (el) => {
                for (const sel of allowedSelectors) {
                    try {
                        if (el.matches(sel) || el.closest(sel)) return true;
                    } catch (e) { }
                }
                return false;
            };

            const contentRoot = document.querySelector('main.main-content') || document.body;
            const elements = contentRoot.querySelectorAll('*');

            for (const el of elements) {
                if (isAllowed(el)) continue;

                const rect = el.getBoundingClientRect();

                // Check if element extends beyond viewport
                if (rect.right > viewportWidth + TOLERANCE) {
                    const overflow = rect.right - viewportWidth;
                    issues.push({
                        tag: el.tagName,
                        id: el.id || null,
                        className: typeof el.className === 'string' ? el.className.slice(0, 100) : null,
                        overflow: Math.round(overflow),
                        width: Math.round(rect.width),
                        viewportWidth,
                    });
                }
            }

            return issues.slice(0, 20); // Limit results
        }, OVERFLOW_ALLOWED);

        for (const issue of overflowIssues) {
            findings.push({
                severity: issue.overflow > 50 ? 'error' : 'warning',
                message: `Element overflows viewport by ${issue.overflow}px`,
                selector: issue.id ? `#${issue.id}` : issue.className ? `.${issue.className.split(' ')[0]}` : issue.tag,
                details: issue,
            });
        }

        return findings;
    }
);

registerRule(overflowRule);

export default overflowRule;
