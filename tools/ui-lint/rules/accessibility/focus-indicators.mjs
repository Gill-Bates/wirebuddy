//
// tools/ui-lint/rules/accessibility/focus-indicators.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Rule: Focusable elements must have visible focus indicators (WCAG 2.4.7).
//

import { registerRule, RuleBuilder } from '../../lib/rule-registry.mjs';
import { getViewportAwareTouchTarget } from '../../lib/interaction-utils.mjs';
import { simulateTabNavigation } from '../../lib/focus-flow.mjs';
import { isFocusVisibleEnough } from '../../lib/focus-visibility.mjs';

export const meta = {
    id: 'focus-indicators',
    category: 'accessibility',
    severity: 'warning',
    browsers: ['chromium', 'webkit', 'firefox'],
    devices: ['desktop', 'tablet', 'mobile'],
    requires: ['dom-snapshot', 'interaction'],
    optional: ['visualViewport'],
    capabilities: ['dom', 'interaction', 'visualViewport'],
    performanceCost: 'high',
    tags: ['a11y', 'keyboard', 'focus'],
    executionMode: 'serial',
    severityByBrowser: {
        webkit: 'warning',
    },
};

const FOCUS_IMPORTANCE_MULTIPLIER = {
    primary: 1.35,
    secondary: 1,
    tertiary: 0.9,
};

const focusIndicatorRule = RuleBuilder.accessibility(
    'focus-indicators',
    'Visible focus indicators',
    async (context) => {
        const { page, snapshot, tokens } = context;
        const findings = [];

        const viewport = page.viewportSize() || { width: 1440, height: 1100 };
        const isMobile = viewport.width < 768;
        const isTablet = viewport.width >= 768 && viewport.width < 992;
        const baseMinSize = getViewportAwareTouchTarget(tokens, viewport);

        const focusable = snapshot.collections.focusable
            .filter((el) => !el.disabled && el.tabIndex !== -1)
            .filter((el) => {
                const matchesSelector = el.id || el.dataAction || el.dataUiComponent || el.dataUiRole;
                return Boolean(matchesSelector);
            })
            .slice(0, 50);

        if (!focusable.length) return findings;

        await page.evaluate(() => {
            const active = document.activeElement;
            if (active instanceof HTMLElement) {
                active.blur();
            }
        }).catch(() => { });

        const tabStates = await simulateTabNavigation(page, Math.min(focusable.length + 2, 30));

        for (const state of tabStates) {
            if (!state || state.hidden || state.disabled || state.inert) {
                findings.push({
                    severity: 'error',
                    kind: 'focus-hidden',
                    message: 'Focusable control is hidden or removed from the keyboard flow',
                    selector: state?.selector || null,
                    details: {
                        component: state?.component || null,
                        importance: state?.importance || null,
                        viewport: isMobile ? 'mobile' : isTablet ? 'tablet' : 'desktop',
                        hidden: state?.hidden ?? false,
                        disabled: state?.disabled ?? false,
                        inert: state?.inert ?? false,
                        focusVisible: state?.focusVisible ?? false,
                        tabIndex: state?.tabIndex ?? null,
                        width: state?.rect?.width ?? 0,
                        height: state?.rect?.height ?? 0,
                        required: baseMinSize,
                    },
                });
                continue;
            }

            const visibleEnough = isFocusVisibleEnough({
                before: {
                    outlineStyle: 'none',
                    outlineWidth: 0,
                    outlineColor: 'rgba(0, 0, 0, 0)',
                    boxShadow: 'none',
                    borderColor: state.computed.borderColor,
                    backgroundColor: state.computed.backgroundColor,
                },
                after: state.computed,
                tokens,
                elementRect: state.rect,
                focusRect: state.rect,
            });

            const importanceMultiplier = FOCUS_IMPORTANCE_MULTIPLIER[state.importance || 'secondary'] || 1;
            const requiredContrast = (tokens?.wcag?.contrastAALarge || 3) * importanceMultiplier;
            const contrastRatio = visibleEnough.contrastRatio ?? 0;
            const focusArea = visibleEnough.focusRingArea || 0;
            const minArea = Math.max(16, Math.round(state.rect.width + state.rect.height));

            const broken = !visibleEnough.visible || !visibleEnough.sufficientContrast || focusArea < minArea;

            if (!broken) continue;

            const severity = state.importance === 'primary' || !visibleEnough.visible || focusArea < minArea - 4 ? 'error' : 'warning';
            findings.push({
                severity,
                kind: 'focus-visibility',
                message: state.component
                    ? `${state.component} focus indicator is not sufficiently visible`
                    : 'Missing visible focus indicator',
                selector: state.selector || null,
                details: {
                    component: state.component || null,
                    importance: state.importance || null,
                    viewport: isMobile ? 'mobile' : isTablet ? 'tablet' : 'desktop',
                    focusVisible: state.focusVisible,
                    focusWithin: state.focusWithin,
                    hidden: state.hidden,
                    disabled: state.disabled,
                    inert: state.inert,
                    contrastRatio,
                    requiredContrast,
                    focusRingArea: focusArea,
                    minArea,
                    outlineWidth: parseFloat(state.computed.outlineWidth || '0') || 0,
                    outlineOffset: parseFloat(state.computed.outlineOffset || '0') || 0,
                    outlineColor: state.computed.outlineColor,
                    boxShadow: state.computed.boxShadow,
                    backgroundColor: state.computed.backgroundColor,
                    borderColor: state.computed.borderColor,
                    width: state.rect.width,
                    height: state.rect.height,
                    tabIndex: state.tabIndex,
                    text: state.text,
                },
            });
        }

        const hasModal = await page.evaluate(() => Boolean(document.querySelector('.modal.show, .modal:not(.d-none)')));
        const modalComponent = hasModal
            ? await page.evaluate(() => document.querySelector('.modal.show, .modal:not(.d-none)')?.getAttribute('data-ui-component') || 'modal')
            : null;
        const modalIssue = hasModal && tabStates.find((state) => state?.insideModal === false && !state.hidden && !state.disabled && !state.inert);
        if (modalIssue) {
            findings.push({
                severity: 'error',
                kind: 'modal-focus-escape',
                message: 'Focus escaped the active modal during tab navigation',
                selector: modalIssue.selector || null,
                details: {
                    component: modalComponent,
                    viewport: isMobile ? 'mobile' : isTablet ? 'tablet' : 'desktop',
                    text: modalIssue.text,
                    focusVisible: modalIssue.focusVisible,
                    tabIndex: modalIssue.tabIndex,
                },
            });
        }

        return findings;
    }
);

focusIndicatorRule.meta = meta;

registerRule(focusIndicatorRule);

export default focusIndicatorRule;
