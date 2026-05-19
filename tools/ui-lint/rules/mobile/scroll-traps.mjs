//
// tools/ui-lint/rules/mobile/scroll-traps.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//
// Rule: Detect scroll traps and nested scroll containers (iOS/Safari issues).
//

import { registerRule, RuleBuilder } from '../../lib/rule-registry.mjs';

const scrollTrapsRule = RuleBuilder.mobile(
    'scroll-traps',
    'Nested scroll containers and scroll traps',
    async (context) => {
        const { page, snapshot } = context;
        const findings = [];

        // Check for nested scroll containers
        const scrollContainers = snapshot.collections.scrollContainers;

        // Detect nested scrollers
        const nestedIssues = await page.evaluate(() => {
            const issues = [];

            const isScrollable = (el) => {
                const style = window.getComputedStyle(el);
                const hasOverflow = ['auto', 'scroll'].includes(style.overflowY) ||
                    ['auto', 'scroll'].includes(style.overflowX);
                return hasOverflow && (el.scrollHeight > el.clientHeight || el.scrollWidth > el.clientWidth);
            };

            const scrollers = document.querySelectorAll('[style*="overflow"], .overflow-auto, .overflow-scroll');

            for (const el of scrollers) {
                if (!isScrollable(el)) continue;

                // Check for nested scrollers
                const nestedScroller = el.querySelector('[style*="overflow"], .overflow-auto, .overflow-scroll');
                if (nestedScroller && isScrollable(nestedScroller)) {
                    issues.push({
                        parent: {
                            tag: el.tagName,
                            id: el.id || null,
                            className: el.className?.slice?.(0, 50) || null,
                        },
                        child: {
                            tag: nestedScroller.tagName,
                            id: nestedScroller.id || null,
                            className: nestedScroller.className?.slice?.(0, 50) || null,
                        },
                    });
                }
            }

            return issues.slice(0, 10);
        });

        for (const issue of nestedIssues) {
            findings.push({
                severity: 'warning',
                message: `Nested scroll containers detected - may cause scroll traps on iOS`,
                selector: issue.parent.id ? `#${issue.parent.id}` : issue.parent.className,
                details: issue,
            });
        }

        // Check for missing -webkit-overflow-scrolling
        const webkitIssues = await page.evaluate(() => {
            const issues = [];

            const scrollers = document.querySelectorAll('.overflow-auto, .overflow-scroll, [style*="overflow: auto"], [style*="overflow: scroll"]');

            for (const el of scrollers) {
                const style = window.getComputedStyle(el);
                // webkitOverflowScrolling is deprecated but still useful on older iOS
                const hasScrollMomentum = style.webkitOverflowScrolling === 'touch';
                const hasOverscrollBehavior = style.overscrollBehavior !== 'auto';

                if (!hasScrollMomentum && !hasOverscrollBehavior) {
                    const rect = el.getBoundingClientRect();
                    // Only flag if actually scrollable and visible
                    if (el.scrollHeight > el.clientHeight + 10 && rect.height > 100) {
                        issues.push({
                            tag: el.tagName,
                            id: el.id || null,
                            className: el.className?.slice?.(0, 50) || null,
                        });
                    }
                }
            }

            return issues.slice(0, 10);
        });

        for (const issue of webkitIssues) {
            findings.push({
                severity: 'info',
                message: `Scroll container may lack momentum scrolling on iOS`,
                selector: issue.id ? `#${issue.id}` : issue.className,
                details: {
                    suggestion: 'Consider adding -webkit-overflow-scrolling: touch or overscroll-behavior: contain',
                    ...issue,
                },
            });
        }

        return findings;
    }
);

registerRule(scrollTrapsRule);

export default scrollTrapsRule;
