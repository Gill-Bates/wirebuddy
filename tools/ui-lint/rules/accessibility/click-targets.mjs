//
// tools/ui-lint/rules/accessibility/click-targets.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Rule: Click targets must meet minimum touch target size (WCAG 2.5.5).
//

import { registerRule, RuleBuilder } from '../../lib/rule-registry.mjs';
import {
    buildInteractionSelector,
    getDensityMultiplier,
    getInteractionDensity,
    getInteractionImportance,
    getViewportAwareTouchTarget,
    groupInteractionViolations,
    inspectInteractionTargets,
} from '../../lib/interaction-utils.mjs';

export const meta = {
    id: 'click-targets',
    category: 'accessibility',
    severity: 'warning',
    browsers: ['chromium', 'webkit', 'firefox'],
    devices: ['desktop', 'tablet', 'mobile'],
    requires: ['dom-snapshot', 'interaction'],
    optional: ['viewport'],
    capabilities: ['dom', 'interaction'],
    performanceCost: 'high',
    tags: ['a11y', 'interaction', 'mobile'],
    executionMode: 'serial',
    severityByBrowser: {
        webkit: 'serious',
    },
};

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
    '.btn-close',
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
        const { page, snapshot, tokens } = context;
        const findings = [];

        const viewport = page.viewportSize() || {
            width: 1440,
            height: 1100,
        };
        const baseMinSize = getViewportAwareTouchTarget(tokens, viewport);

        // Check interactive elements
        const targets = [];
        for (const el of snapshot.collections.interactive) {
            // Skip exceptions
            if (isInlineLink(el)) continue;
            if (isCompactException(el)) continue;
            if (el.disabled) continue;

            const selector = buildInteractionSelector(el);
            if (!selector) continue;

            targets.push({
                selector,
                tag: el.tag,
                id: el.id,
                classList: el.classList,
                role: el.role,
                ariaLabel: el.ariaLabel,
                dataAction: el.dataAction,
                dataUiComponent: el.dataUiComponent,
                dataUiDensity: el.dataUiDensity,
                dataUiImportance: el.dataUiImportance,
                dataUiRole: el.dataUiRole,
                dataPeerId: el.dataPeerId,
                dataNodeId: el.dataNodeId,
                rect: el.rect,
            });
        }

        const inspectedTargets = await inspectInteractionTargets(page, targets);

        for (const target of inspectedTargets) {
            if (!target.exists) continue;

            const density = getInteractionDensity(target);
            const importance = getInteractionImportance(target);
            const required = Math.round(baseMinSize * getDensityMultiplier(density));
            const { width, height } = target;
            const smaller = Math.min(width, height);
            const tooSmall = smaller < required - 4;
            const interactionFailure = !target.clickable || target.occluded || target.pointerEvents === 'none' || target.hidden || target.disabled || target.inert;

            if (!tooSmall && !interactionFailure) continue;

            const severity = interactionFailure || importance === 'primary' || smaller < required - 10 ? 'error' : 'warning';
            const kind = interactionFailure ? 'click-target-occluded' : 'click-target-too-small';

            findings.push({
                severity,
                kind,
                message: interactionFailure
                    ? `${target.component || 'UI'} control is not actually clickable`
                    : `Click target too small: ${width}x${height}px (minimum: ${required}px)`,
                selector: target.selector,
                details: {
                    tag: target.tag,
                    component: target.component || target.dataUiComponent || null,
                    density,
                    importance,
                    width,
                    height,
                    required,
                    clickable: target.clickable,
                    occluded: target.occluded,
                    pointerEvents: target.pointerEvents,
                    viewport: viewport.width ? (viewport.width < 768 ? 'mobile' : viewport.width < 992 ? 'tablet' : 'desktop') : 'desktop',
                    text: target.text?.slice(0, 30),
                    target,
                },
            });
        }

        return groupInteractionViolations(findings).map((group) => ({
            severity: group.severity,
            kind: group.kind,
            message: group.message,
            selector: group.selector,
            count: group.count,
            details: {
                count: group.count,
                component: group.component || null,
                density: group.density || null,
                importance: group.importance || null,
                viewport: group.viewport || null,
                clickable: group.clickable,
                occluded: group.occluded,
                hidden: group.hidden,
                disabled: group.disabled,
                inert: group.inert,
                width: group.width,
                height: group.height,
                required: group.required,
                items: group.items,
            },
        }));
    }
);

clickTargetRule.meta = meta;

registerRule(clickTargetRule);

export default clickTargetRule;
