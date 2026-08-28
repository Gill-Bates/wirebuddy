//
// tools/ui-lint/rules/accessibility/control-contracts.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Rule: Interactive controls declare their type and decorative icons stay out
// of the accessible name calculation.

import { registerRule, RuleBuilder } from '../../lib/rule-registry.mjs';

export const meta = {
    id: 'control-contracts',
    category: 'accessibility',
    severity: 'error',
    browsers: ['chromium', 'webkit', 'firefox'],
    devices: ['desktop', 'tablet', 'mobile'],
    requires: ['dom-snapshot'],
    capabilities: ['dom'],
    performanceCost: 'cheap',
    tags: ['a11y', 'buttons', 'icons', 'forms'],
    executionMode: 'parallel',
};

const controlContractsRule = RuleBuilder.accessibility(
    'control-contracts',
    'Button and icon accessibility contracts',
    async ({ page, browser, scope }) => {
        const diagnostics = await page.evaluate(() => ({
            buttonsWithoutType: Array.from(document.querySelectorAll('button'))
                .filter((button) => !button.getAttribute('type'))
                .map((button) => ({
                    id: button.id || null,
                    text: (button.textContent || '').trim().slice(0, 80),
                })),
            visibleIconsInButtons: Array.from(document.querySelectorAll('button .material-icons'))
                .filter((icon) => icon.getAttribute('aria-hidden') !== 'true')
                .map((icon) => ({
                    id: icon.id || null,
                    text: (icon.textContent || '').trim(),
                    buttonId: icon.closest('button')?.id || null,
                })),
        }));

        const findings = [];
        for (const button of diagnostics.buttonsWithoutType) {
            findings.push({
                severity: 'error',
                kind: 'button-type-missing',
                message: 'Button must declare an explicit type',
                selector: button.id ? `#${button.id}` : 'button',
                details: { ...button, browser: browser || null, scope: scope || null },
            });
        }
        for (const icon of diagnostics.visibleIconsInButtons) {
            findings.push({
                severity: 'error',
                kind: 'button-icon-not-hidden',
                message: 'Decorative Material Icon inside a button must have aria-hidden="true"',
                selector: icon.buttonId ? `#${icon.buttonId} .material-icons` : 'button .material-icons',
                details: { ...icon, browser: browser || null, scope: scope || null },
            });
        }
        return findings;
    },
);

controlContractsRule.meta = meta;

registerRule(controlContractsRule);

export default controlContractsRule;
