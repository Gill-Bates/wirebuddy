//
// tools/ui-lint/rules/mobile/scroll-traps.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Rule: Detect scroll traps and nested scroll containers (iOS/Safari issues).
//

import { registerRule, RuleBuilder } from '../../lib/rule-registry.mjs';
import {
    classifyScrollTrapIssue,
    collectScrollTrapDiagnostics,
} from '../../lib/scroll-diagnostics.mjs';

export const meta = {
    id: 'scroll-traps',
    category: 'mobile',
    severity: 'serious',
    browsers: ['chromium', 'webkit', 'firefox'],
    devices: ['tablet', 'mobile'],
    requires: ['dom-snapshot'],
    optional: ['interaction', 'visualViewport'],
    capabilities: ['dom', 'touch', 'visualViewport'],
    performanceCost: 'high',
    tags: ['mobile', 'ios', 'scroll'],
    executionMode: 'serial',
    severityByBrowser: {
        webkit: 'serious',
    },
};

const SCROLL_CONTAINER_ALLOWED = [
    '.leaflet-control-container',
    '.leaflet-pane',
    '.table-responsive',
    '.modal-body',
    '.offcanvas-body',
    '.code-block',
    'pre',
    'code',
];

const scrollTrapsRule = RuleBuilder.mobile(
    'scroll-traps',
    'Nested scroll containers and scroll traps',
    async (context) => {
        const { page } = context;
        const findings = [];

        const diagnostics = await collectScrollTrapDiagnostics(page, {
            allowedSelectors: SCROLL_CONTAINER_ALLOWED,
            tolerance: 2,
            browser: context.browser || null,
            scope: context.scope || null,
        });

        for (const issue of diagnostics.issues) {
            const finding = classifyScrollTrapIssue(issue, {
                browser: context.browser || null,
                component: context.component || context.scope || null,
                scope: context.scope || null,
                viewport: diagnostics.viewport,
                bodyLocked: diagnostics.bodyLocked,
                tolerance: 2,
            });

            if (!finding) continue;

            findings.push(finding);

            const needsMomentumHint = String(issue.browser || context.browser || '').toLowerCase() === 'webkit'
                && (issue.vertical || issue.axis === 'both')
                && issue.webkitOverflowScrolling !== 'touch'
                && issue.overscrollBehaviorY === 'auto'
                && (issue.nestingDepth > 0 || issue.modalContext || issue.bodyLocked);

            if (needsMomentumHint && finding.kind !== 'webkit-scroll-momentum') {
                findings.push({
                    severity: 'info',
                    kind: 'webkit-scroll-momentum',
                    message: `${finding.details.component || 'Scroll container'} may need momentum scrolling on iOS`,
                    selector: issue.selector || null,
                    details: {
                        component: finding.details.component || null,
                        browser: issue.browser || context.browser || null,
                        scope: context.scope || null,
                        webkitOverflowScrolling: issue.webkitOverflowScrolling || null,
                        overscrollBehaviorY: issue.overscrollBehaviorY || null,
                        touchAction: issue.touchAction || null,
                        nestingDepth: issue.nestingDepth || 0,
                        modalContext: Boolean(issue.modalContext),
                        bodyLocked: Boolean(issue.bodyLocked),
                        scrollAncestors: issue.scrollAncestors || [],
                    },
                });
            }
        }

        return findings;
    }
);

scrollTrapsRule.meta = meta;

registerRule(scrollTrapsRule);

export default scrollTrapsRule;
