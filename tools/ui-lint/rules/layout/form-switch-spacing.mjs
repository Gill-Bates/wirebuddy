//
// tools/ui-lint/rules/layout/form-switch-spacing.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Rule: Keep helper text directly attached to its form switch row.

import { registerRule, RuleBuilder } from '../../lib/rule-registry.mjs';

export const FORM_SWITCH_DESCRIPTION_MARGIN_MAX_PX = 1;

export function collectFormSwitchSpacingDiagnostics(options = {}) {
    const maxMargin = Number.isFinite(options.maxMargin)
        ? options.maxMargin
        : 1;

    return Array.from(document.querySelectorAll('.form-check.form-switch'))
        .map((switchElement, switchIndex) => {
            const input = switchElement.querySelector('.form-check-input');
            const description = switchElement.nextElementSibling;
            const describedIds = (input?.getAttribute('aria-describedby') || '')
                .split(/\s+/)
                .filter(Boolean);
            const isDescription = Boolean(description && (
                description.matches('small, .form-text')
                || (description.id && describedIds.includes(description.id))
            ));

            if (!isDescription) return null;

            const switchStyle = window.getComputedStyle(switchElement);
            const descriptionStyle = window.getComputedStyle(description);
            const marginBottom = Number.parseFloat(switchStyle.marginBottom || '0');
            const descriptionMarginTop = Number.parseFloat(descriptionStyle.marginTop || '0');

            if (marginBottom <= maxMargin && descriptionMarginTop <= maxMargin) {
                return null;
            }

            return {
                switchIndex,
                selector: input?.id ? `#${input.id}` : '.form-check.form-switch',
                label: switchElement.querySelector('.form-check-label')?.textContent?.trim() || null,
                descriptionId: description.id || null,
                marginBottom,
                descriptionMarginTop,
                maxMargin,
            };
        })
        .filter(Boolean);
}

export const meta = {
    id: 'form-switch-spacing',
    category: 'layout',
    severity: 'warning',
    browsers: ['chromium', 'webkit', 'firefox'],
    devices: ['desktop', 'tablet', 'mobile'],
    requires: ['dom-snapshot'],
    capabilities: ['dom'],
    performanceCost: 'cheap',
    tags: ['layout', 'forms', 'switches', 'spacing'],
    executionMode: 'parallel',
};

const formSwitchSpacingRule = RuleBuilder.layout(
    'form-switch-spacing',
    'Form switch description spacing',
    async ({ page, browser, scope }) => {
        const diagnostics = await page.evaluate(collectFormSwitchSpacingDiagnostics, {
            maxMargin: FORM_SWITCH_DESCRIPTION_MARGIN_MAX_PX,
        });

        return diagnostics.map((issue) => ({
            severity: 'warning',
            kind: 'form-switch-description-gap',
            message: `Switch helper text has extra vertical spacing (${issue.marginBottom}px + ${issue.descriptionMarginTop}px)`,
            selector: issue.selector,
            details: {
                component: 'form-switch',
                browser: browser || null,
                scope: scope || null,
                ...issue,
            },
        }));
    },
);

formSwitchSpacingRule.meta = meta;

registerRule(formSwitchSpacingRule);

export default formSwitchSpacingRule;
