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

        // This only sizes the tab-press budget below; simulateTabNavigation
        // walks the real, live tab order regardless of which elements are in
        // this list. The previous filter checked el.dataAction/dataUiComponent/
        // dataUiRole, but those live under el.semantic.* in the snapshot, not
        // at the top level, so it silently matched almost nothing but el.id -
        // undercounting the budget long before the separate 50/30 caps even
        // applied.
        const focusable = snapshot.collections.focusable.filter((el) => !el.disabled && el.tabIndex !== -1);

        if (!focusable.length) return findings;

        await page.evaluate(() => {
            const active = document.activeElement;
            if (active instanceof HTMLElement) {
                active.blur();
            }
        }).catch(() => { });

        // Cover every focusable element, not just the first 30 tab stops;
        // keep a generous ceiling only as a runaway guard against a focus
        // trap bug turning this into an unbounded loop.
        const tabStates = await simulateTabNavigation(page, Math.min(focusable.length + 2, 300));

        for (const state of tabStates) {
            if (!state || state.hidden || state.disabled || state.inert) {
                findings.push({
                    severity: 'error',
                    kind: 'focus-hidden',
                    message: 'Focusable control is hidden or removed from the keyboard flow',
                    selector: state?.selector || null,
                    details: {
                        tag: state?.tag || null,
                        id: state?.id || null,
                        text: state?.text || null,
                        component: state?.component || null,
                        importance: state?.importance || null,
                        viewport: isMobile ? 'mobile' : isTablet ? 'tablet' : 'desktop',
                        hidden: state?.hidden ?? false,
                        disabled: state?.disabled ?? false,
                        inert: state?.inert ?? false,
                        focusVisible: state?.focusVisible ?? false,
                        tabIndex: state?.tabIndex ?? null,
                        left: state?.rect?.left ?? 0,
                        top: state?.rect?.top ?? 0,
                        right: state?.rect?.right ?? 0,
                        bottom: state?.rect?.bottom ?? 0,
                        width: state?.rect?.width ?? 0,
                        height: state?.rect?.height ?? 0,
                        required: baseMinSize,
                    },
                });
                continue;
            }

            const importanceMultiplier = FOCUS_IMPORTANCE_MULTIPLIER[state.importance || 'secondary'] || 1;
            const requiredContrast = (tokens?.wcag?.contrastAALarge || 3) * importanceMultiplier;

            const visibleEnough = isFocusVisibleEnough({
                // Real unfocused baseline (captured by briefly blurring the
                // element), not a fabricated "no outline/shadow" stand-in -
                // that fake baseline missed indicators built from border or
                // background changes and could mistake a permanent box-shadow
                // for a focus indicator.
                before: state.unfocusedComputed || state.computed,
                after: state.computed,
                tokens,
                elementRect: state.rect,
                focusRect: state.rect,
                // Weight the pass/fail threshold by importance so it actually
                // affects the outcome, not just the reported number.
                minContrast: requiredContrast,
            });

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
                    tag: state.tag || null,
                    id: state.id || null,
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
                    left: state.rect.left,
                    top: state.rect.top,
                    right: state.rect.right,
                    bottom: state.rect.bottom,
                    width: state.rect.width,
                    height: state.rect.height,
                    tabIndex: state.tabIndex,
                    text: state.text,
                },
            });
        }

        // Bootstrap modals sit in the DOM at all times and only gain `.show`
        // (plus display:block) once opened; `.modal:not(.d-none)` matches a
        // closed modal too, since Bootstrap never adds `.d-none` to it. Also
        // confirm the element is actually rendered, not just class-flagged.
        const activeModalComponent = await page.evaluate(() => {
            const modal = document.querySelector('.modal.show[aria-modal="true"], .modal.show');
            if (!modal) return null;
            const style = window.getComputedStyle(modal);
            if (style.display === 'none' || style.visibility === 'hidden') return null;
            return modal.getAttribute('data-ui-component') || 'modal';
        });
        const hasModal = activeModalComponent !== null;
        const modalComponent = activeModalComponent;
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
