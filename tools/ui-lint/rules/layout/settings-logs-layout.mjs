//
// tools/ui-lint/rules/layout/settings-logs-layout.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Rule: Keep Settings > Logs metrics and delete-footer layout stable.

import { registerRule, RuleBuilder } from '../../lib/rule-registry.mjs';

const ROW_TOP_TOLERANCE_PX = 2;
const MIN_HAIRLINE_MARGIN_BOTTOM_PX = 3;
const MIN_DELETE_PADDING_TOP_PX = 8;

export const meta = {
    id: 'settings-logs-layout',
    category: 'layout',
    severity: 'warning',
    browsers: ['chromium', 'webkit', 'firefox'],
    devices: ['desktop', 'tablet', 'mobile'],
    requires: ['dom-snapshot'],
    optional: ['viewport'],
    capabilities: ['dom'],
    performanceCost: 'cheap',
    tags: ['layout', 'settings', 'logs'],
    executionMode: 'parallel',
};

const settingsLogsLayoutRule = RuleBuilder.layout(
    'settings-logs-layout',
    'Settings logs layout stability',
    async ({ page, scope, browser }) => {
        const findings = [];

        const diagnostics = await page.evaluate(() => {
            const root = document.querySelector('#logs-pane');
            if (!root) {
                return {
                    present: false,
                    viewportWidth: window.innerWidth,
                    rows: [],
                    deleteBlocks: [],
                };
            }

            const rows = Array.from(root.querySelectorAll('.logs-metrics-row')).map((row, rowIndex) => {
                const style = window.getComputedStyle(row);
                const items = Array.from(row.querySelectorAll('.logs-metric-item'));
                const tops = items.map((item) => item.getBoundingClientRect().top);
                const topSpread = tops.length > 1 ? Math.max(...tops) - Math.min(...tops) : 0;
                return {
                    rowIndex,
                    display: style.display,
                    flexWrap: style.flexWrap,
                    itemCount: items.length,
                    topSpread,
                };
            });

            const deleteBlocks = Array.from(root.querySelectorAll('.metrics-delete')).map((block, blockIndex) => {
                const hr = block.querySelector('hr');
                const inner = block.querySelector('.metrics-delete-inner');
                const hrStyle = hr ? window.getComputedStyle(hr) : null;
                const innerStyle = inner ? window.getComputedStyle(inner) : null;
                return {
                    blockIndex,
                    hasHr: Boolean(hr),
                    hasInner: Boolean(inner),
                    hrMarginBottom: hrStyle ? (Number.parseFloat(hrStyle.marginBottom) || 0) : null,
                    innerPaddingTop: innerStyle ? (Number.parseFloat(innerStyle.paddingTop) || 0) : null,
                };
            });

            return {
                present: true,
                viewportWidth: window.innerWidth,
                rows,
                deleteBlocks,
            };
        });

        if (!diagnostics.present) return findings;

        const desktopLike = diagnostics.viewportWidth >= 768;

        for (const row of diagnostics.rows) {
            if (row.display !== 'flex') {
                findings.push({
                    severity: 'error',
                    kind: 'settings-logs-metrics-row-display',
                    message: 'Logs metrics row must use flex layout',
                    selector: '#logs-pane .logs-metrics-row',
                    details: {
                        component: 'settings-logs',
                        browser: browser || null,
                        scope: scope || null,
                        rowIndex: row.rowIndex,
                        display: row.display,
                    },
                });
            }

            if (row.flexWrap !== 'nowrap') {
                findings.push({
                    severity: desktopLike ? 'error' : 'warning',
                    kind: 'settings-logs-metrics-row-wrap',
                    message: 'Logs metrics row must stay on one line',
                    selector: '#logs-pane .logs-metrics-row',
                    details: {
                        component: 'settings-logs',
                        browser: browser || null,
                        scope: scope || null,
                        rowIndex: row.rowIndex,
                        flexWrap: row.flexWrap,
                        viewportWidth: diagnostics.viewportWidth,
                    },
                });
            }

            if (desktopLike && row.itemCount > 1 && row.topSpread > ROW_TOP_TOLERANCE_PX) {
                findings.push({
                    severity: 'error',
                    kind: 'settings-logs-metrics-row-stacked',
                    message: 'Logs metrics items are stacked instead of aligned in one row',
                    selector: '#logs-pane .logs-metrics-row .logs-metric-item',
                    details: {
                        component: 'settings-logs',
                        browser: browser || null,
                        scope: scope || null,
                        rowIndex: row.rowIndex,
                        topSpread: row.topSpread,
                        tolerance: ROW_TOP_TOLERANCE_PX,
                        viewportWidth: diagnostics.viewportWidth,
                    },
                });
            }
        }

        for (const block of diagnostics.deleteBlocks) {
            if (block.hasHr && block.hrMarginBottom !== null && block.hrMarginBottom < MIN_HAIRLINE_MARGIN_BOTTOM_PX) {
                findings.push({
                    severity: 'warning',
                    kind: 'settings-logs-delete-hairline-gap',
                    message: 'Spacing below the logs delete hairline is too tight',
                    selector: '#logs-pane .metrics-delete hr',
                    details: {
                        component: 'settings-logs',
                        browser: browser || null,
                        scope: scope || null,
                        blockIndex: block.blockIndex,
                        marginBottom: block.hrMarginBottom,
                        minimum: MIN_HAIRLINE_MARGIN_BOTTOM_PX,
                    },
                });
            }

            if (block.hasInner && block.innerPaddingTop !== null && block.innerPaddingTop < MIN_DELETE_PADDING_TOP_PX) {
                findings.push({
                    severity: 'warning',
                    kind: 'settings-logs-delete-padding-top',
                    message: 'Spacing above logs delete actions is too tight',
                    selector: '#logs-pane .metrics-delete-inner',
                    details: {
                        component: 'settings-logs',
                        browser: browser || null,
                        scope: scope || null,
                        blockIndex: block.blockIndex,
                        paddingTop: block.innerPaddingTop,
                        minimum: MIN_DELETE_PADDING_TOP_PX,
                    },
                });
            }
        }

        return findings;
    }
);

settingsLogsLayoutRule.meta = meta;

registerRule(settingsLogsLayoutRule);

export default settingsLogsLayoutRule;
