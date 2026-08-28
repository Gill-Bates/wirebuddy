//
// tools/ui-lint/rules/component/dashboard-light-surfaces.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Rule: Dashboard KPI cards must use a light surface in the light theme.

import { registerRule, RuleBuilder } from '../../lib/rule-registry.mjs';

const DARK_LUMINANCE_LIMIT = 0.18;

export const meta = {
    id: 'dashboard-light-surfaces',
    category: 'component',
    severity: 'error',
    browsers: ['chromium', 'webkit', 'firefox'],
    devices: ['desktop', 'tablet', 'mobile'],
    requires: ['dom-snapshot'],
    capabilities: ['dom'],
    performanceCost: 'cheap',
    tags: ['dashboard', 'theme', 'light-mode', 'cards'],
    executionMode: 'parallel',
    scopes: ['dashboard'],
};

function luminance({ red, green, blue }) {
    const channel = (value) => {
        const normalized = value / 255;
        return normalized <= 0.03928
            ? normalized / 12.92
            : ((normalized + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue);
}

const dashboardLightSurfacesRule = RuleBuilder.component(
    'dashboard-light-surfaces',
    'Dashboard light-theme surfaces',
    async ({ page, browser, scope }) => {
        const diagnostics = await page.evaluate(() => {
            const theme = document.documentElement.getAttribute('data-bs-theme')
                || document.body.getAttribute('data-bs-theme')
                || '';
            if (theme !== 'light') return { theme, cards: [] };

            const parseRgb = (value) => {
                const match = String(value || '').match(/rgba?\(\s*([\d.]+)[, ]+\s*([\d.]+)[, ]+\s*([\d.]+)/i);
                return match
                    ? { red: Number(match[1]), green: Number(match[2]), blue: Number(match[3]) }
                    : null;
            };

            return {
                theme,
                cards: Array.from(document.querySelectorAll('.wb-kpi-card, .dashboard-kpi-card'))
                    .filter((card) => card.getAttribute('data-ui-lint-allow') !== 'dark-surface')
                    .map((card) => ({
                        id: card.id || null,
                        background: window.getComputedStyle(card).backgroundColor,
                        rgb: parseRgb(window.getComputedStyle(card).backgroundColor),
                    })),
            };
        });

        return diagnostics.cards
            .filter((card) => card.rgb && luminance(card.rgb) < DARK_LUMINANCE_LIMIT)
            .map((card) => ({
                severity: 'error',
                kind: 'dashboard-light-surface-dark',
                message: 'Dashboard KPI card has a dark surface in the light theme',
                selector: card.id ? `#${card.id}` : '.wb-kpi-card, .dashboard-kpi-card',
                details: { ...card, browser: browser || null, scope: scope || null },
            }));
    },
);

dashboardLightSurfacesRule.meta = meta;

registerRule(dashboardLightSurfacesRule);

export default dashboardLightSurfacesRule;
