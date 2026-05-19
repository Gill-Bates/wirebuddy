//
// tools/ui-lint/rules/accessibility/click-targets.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//
// Rule: Click targets must meet minimum touch target size (WCAG 2.5.5).
//

import { registerRule, RuleBuilder } from '../../lib/rule-registry.mjs';

/**
 * Selectors that should meet minimum click target size.
 */
const CLICK_TARGET_SELECTORS = [
    'button',
    '.btn',
    '[role="button"]',
    'summary',
    'input[type="button"]',
    'input[type="submit"]',
    'input[type="reset"]',
    'select.form-select:not(.form-select-sm)',
];

/**
 * Elements that are intentionally compact.
 */
const COMPACT_CONTROL_EXCEPTIONS = [
    '.leaflet-control-zoom a',
    '.leaflet-bar a',
    '.form-select-sm',
    '.btn-sm',
    '.btn-close',
    '.dropdown-item',
];

/**
 * Inline links are not treated as button-like touch targets.
 */
function isInlineLink(el) {
    if (el.tag !== 'A') return false;
    if (el.classList?.includes('btn')) return false;
    if (el.role === 'button') return false;
    // Footer links are intentionally compact
    if (el.classList?.includes('wb-footer-link')) return true;
    return false;
}

/**
 * Check if element is a compact control exception.
 */
function isCompactException(el) {
    for (const selector of COMPACT_CONTROL_EXCEPTIONS) {
        // Simplified check using class matching
        const parts = selector.split(/[.\s]+/).filter(Boolean);
        for (const part of parts) {
            if (el.classList?.includes(part)) return true;
        }
    }
    return false;
}

const clickTargetRule = RuleBuilder.accessibility(
    'click-targets',
    'Minimum click target size',
    async (context) => {
        const { snapshot, tokens } = context;
        const findings = [];

        const minSize = tokens.interaction.touchTargetMin;

        // Check interactive elements
        for (const el of snapshot.collections.interactive) {
            // Skip exceptions
            if (isInlineLink(el)) continue;
            if (isCompactException(el)) continue;
            if (el.disabled) continue;

            const { width, height } = el.rect;

            // Check minimum dimensions
            if (width < minSize || height < minSize) {
                const smaller = Math.min(width, height);

                // Only report if significantly smaller
                if (smaller < minSize - 4) {
                    findings.push({
                        severity: smaller < minSize - 10 ? 'error' : 'warning',
                        message: `Click target too small: ${width}x${height}px (minimum: ${minSize}px)`,
                        selector: el.id ? `#${el.id}` : `.${el.classList?.join('.')}`,
                        details: {
                            tag: el.tag,
                            width,
                            height,
                            required: minSize,
                            text: el.text?.slice(0, 30),
                        },
                    });
                }
            }
        }

        return findings;
    }
);

registerRule(clickTargetRule);

export default clickTargetRule;
