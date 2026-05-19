//
// tools/ui-lint/rules/accessibility/focus-indicators.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Rule: Focusable elements must have visible focus indicators (WCAG 2.4.7).
//

import { registerRule, RuleBuilder } from '../../lib/rule-registry.mjs';

const focusIndicatorRule = RuleBuilder.accessibility(
    'focus-indicators',
    'Visible focus indicators',
    async (context) => {
        const { page, snapshot, tokens } = context;
        const findings = [];

        // This rule requires page interaction to test focus states
        // For each focusable element, we focus it and check for visual changes

        const focusable = snapshot.collections.focusable.slice(0, 50); // Limit for performance

        for (const el of focusable) {
            if (el.disabled) continue;
            if (!el.id) continue; // Need ID for reliable focusing

            try {
                const result = await page.evaluate(async (elementId) => {
                    const element = document.getElementById(elementId);
                    if (!element) return null;

                    const getStyleSnapshot = (el) => {
                        const s = window.getComputedStyle(el);
                        return {
                            outlineStyle: s.outlineStyle,
                            outlineWidth: parseFloat(s.outlineWidth || '0'),
                            outlineColor: s.outlineColor,
                            boxShadow: s.boxShadow,
                            borderColor: s.borderTopColor,
                            backgroundColor: s.backgroundColor,
                        };
                    };

                    const before = getStyleSnapshot(element);

                    element.focus();
                    await new Promise(r => setTimeout(r, 50));

                    const after = getStyleSnapshot(element);

                    element.blur();

                    // Check if any visual property changed
                    const hasChange =
                        (after.outlineStyle !== 'none' && after.outlineWidth > 0 &&
                            (before.outlineStyle !== after.outlineStyle || before.outlineWidth !== after.outlineWidth)) ||
                        (before.boxShadow !== after.boxShadow && after.boxShadow !== 'none') ||
                        (before.borderColor !== after.borderColor) ||
                        (before.backgroundColor !== after.backgroundColor);

                    return { hasChange, before, after };
                }, el.id);

                if (result && !result.hasChange) {
                    findings.push({
                        severity: 'warning',
                        message: `Missing visible focus indicator`,
                        selector: `#${el.id}`,
                        details: {
                            tag: el.tag,
                            classList: el.classList?.slice(0, 5),
                            text: el.text?.slice(0, 30),
                        },
                    });
                }
            } catch (e) {
                // Skip elements that can't be focused
            }
        }

        return findings;
    }
);

registerRule(focusIndicatorRule);

export default focusIndicatorRule;
