//
// tools/ui-lint/lib/findings/policies/accessibility-policy.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { countFindingRule, customFindingRule } from '../engine/policy-engine.mjs';

export function buildAccessibilityPolicy() {
    return {
        id: 'accessibility-policy',
        owner: 'platform-ui',
        rules: [
            countFindingRule({
                id: 'duplicate-ids',
                type: 'duplicate-ids',
                category: 'accessibility',
                severity: 'error',
                wcag: ['4.1.1'],
                metricPath: 'metrics.duplicateIds',
                legacyKey: (context, count) => `duplicateIds=${count}`,
                message: 'Duplicate IDs detected',
                explanation: 'Multiple elements share the same id value, which breaks unique element targeting.',
                remediation: 'Make each id unique within the document.',
            }),
            countFindingRule({
                id: 'empty-aria-labels',
                type: 'empty-aria-labels',
                category: 'accessibility',
                severity: 'warning',
                wcag: ['4.1.2'],
                metricPath: 'metrics.emptyAriaLabels',
                legacyKey: (context, count) => `emptyAriaLabels=${count}`,
                message: 'Empty aria-label values detected',
                explanation: 'Empty accessible names can create ambiguous or silent controls.',
                remediation: 'Provide a meaningful aria-label or remove the attribute.',
            }),
            countFindingRule({
                id: 'unlabeled-controls',
                type: 'unlabeled-controls',
                category: 'accessibility',
                severity: 'error',
                wcag: ['4.1.2'],
                metricPath: 'metrics.unlabeledControls',
                legacyKey: (context, count) => `unlabeledControls=${count}`,
                message: 'Unlabeled controls detected',
                explanation: 'Interactive controls without names are not announced reliably by assistive technology.',
                remediation: 'Associate each control with a visible label or accessible name.',
            }),
            countFindingRule({
                id: 'nameless-buttons',
                type: 'nameless-buttons',
                category: 'accessibility',
                severity: 'error',
                wcag: ['4.1.2'],
                metricPath: 'metrics.namelessButtons',
                legacyKey: (context, count) => `namelessButtons=${count}`,
                message: 'Nameless buttons detected',
                explanation: 'Buttons without text or an accessible label are not understandable to assistive technologies.',
                remediation: 'Add visible text or an aria-label that describes the action.',
            }),
            countFindingRule({
                id: 'heading-skips',
                type: 'heading-skips',
                category: 'accessibility',
                severity: 'warning',
                wcag: ['1.3.1'],
                metricPath: 'metrics.headingSkips',
                legacyKey: (context, count) => `headingSkips=${count}`,
                message: 'Heading level skips detected',
                explanation: 'Skipping heading levels weakens document structure and navigation.',
                remediation: 'Keep heading levels in order and reserve jumps for deliberate structure changes.',
            }),
            countFindingRule({
                id: 'tables-without-headers',
                type: 'tables-without-headers',
                category: 'accessibility',
                severity: 'warning',
                wcag: ['1.3.1'],
                metricPath: 'metrics.tablesWithoutHeaders',
                legacyKey: (context, count) => `tablesWithoutHeaders=${count}`,
                message: 'Tables without headers detected',
                explanation: 'Data tables without headers are difficult to parse for non-visual users.',
                remediation: 'Add header cells or a proper ARIA table pattern.',
            }),
            countFindingRule({
                id: 'table-cell-overlaps',
                type: 'table-cell-overlaps',
                category: 'layout',
                severity: 'error',
                metricPath: 'metrics.tableCellOverlapIssues',
                legacyKey: (context, count) => `tableCellOverlaps=${count}`,
                message: 'Table cell overlap detected',
                explanation: 'Overlapping cells indicate an invalid or unstable table layout.',
                remediation: 'Fix table sizing and overflow so cells can render without collision.',
            }),
            countFindingRule({
                id: 'hidden-interactive',
                type: 'hidden-interactive',
                category: 'accessibility',
                severity: 'error',
                metricPath: 'metrics.hiddenInteractiveElements',
                legacyKey: (context, count) => `hiddenInteractive=${count}`,
                message: 'Hidden interactive elements detected',
                explanation: 'Controls hidden by layout or visibility state can still be focus traps or dead UI.',
                remediation: 'Remove the control, disable it, or make the hidden state explicit and inaccessible.',
                wcag: ['2.4.3'],
            }),
            countFindingRule({
                id: 'focus-order',
                type: 'focus-order',
                category: 'accessibility',
                severity: 'warning',
                metricPath: 'metrics.focusOrderIssues',
                legacyKey: (context, count) => `focusOrderIssues=${count}`,
                message: 'Focus order issues detected',
                explanation: 'The keyboard tab sequence does not follow the expected visual or logical flow.',
                remediation: 'Ensure DOM order matches the desired keyboard navigation order.',
                wcag: ['2.4.3'],
            }),
            countFindingRule({
                id: 'focus-indicator-missing',
                type: 'focus-indicator-missing',
                category: 'accessibility',
                severity: 'warning',
                metricPath: 'metrics.focusIndicatorMissing',
                legacyKey: (context, count) => `focusIndicatorMissing=${count}`,
                message: 'Focus indicator is missing',
                explanation: 'Keyboard users need a visible indicator for the active element.',
                remediation: 'Restore a visible focus style with sufficient contrast and size.',
                wcag: ['2.4.7'],
            }),
            customFindingRule({
                id: 'touch-target-issues',
                type: 'click-target-too-small',
                category: 'accessibility',
                build(context) {
                    const findings = [];
                    const count = context.metrics.clickTargetsTooSmall?.length || 0;
                    if (count) {
                        findings.push({
                            id: 'click-target-too-small',
                            type: 'click-target-too-small',
                            category: 'accessibility',
                            severity: 'error',
                            wcag: ['2.5.5'],
                            count,
                            message: 'Click targets are too small',
                            explanation: 'Interactive targets are below the minimum size for reliable input.',
                            remediation: 'Increase padding or hit area so the control meets the touch target minimum.',
                            legacyKey: `clickTargetsTooSmall=${count}`,
                            confidence: 0.93,
                        });
                    }

                    const iconButtonsTouchBlocked = context.metrics.iconButtonsTouchBlocked?.length || 0;
                    if (iconButtonsTouchBlocked) {
                        findings.push({
                            id: 'icon-buttons-touch-blocked',
                            type: 'icon-buttons-touch-blocked',
                            category: 'accessibility',
                            severity: 'error',
                            wcag: ['2.5.5'],
                            count: iconButtonsTouchBlocked,
                            message: 'Icon buttons are touch blocked',
                            explanation: 'Icon-only controls lack reliable touch affordance or are obstructed by layout.',
                            remediation: 'Add adequate hit area and avoid clipping or overlay collisions.',
                            legacyKey: `iconButtonsTouchBlocked=${iconButtonsTouchBlocked}`,
                            confidence: 0.9,
                        });
                    }

                    return findings;
                },
            }),
            countFindingRule({
                id: 'deprecated-button-classes',
                type: 'deprecated-button-classes',
                category: 'accessibility',
                severity: 'error',
                metricPath: 'metrics.deprecatedButtonClasses',
                legacyKey: (context, count) => `deprecatedButtonClasses=${count}`,
                message: 'Deprecated button classes detected',
                explanation: 'Legacy button styling often indicates inconsistent semantics or interaction states.',
                remediation: 'Replace deprecated button classes with the current component contract.',
            }),
        ],
    };
}
