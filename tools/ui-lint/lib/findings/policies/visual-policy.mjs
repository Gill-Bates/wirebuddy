//
// tools/ui-lint/lib/findings/policies/visual-policy.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { countFindingRule, customFindingRule, thresholdFindingRule } from '../engine/policy-engine.mjs';

export function buildVisualPolicy() {
    return {
        id: 'visual-policy',
        owner: 'platform-ui',
        rules: [
            countFindingRule({
                id: 'contrast-problems',
                type: 'contrast-problems',
                category: 'visual',
                severity: 'error',
                metricPath: 'metrics.contrastProblems',
                legacyKey: (context, count) => `contrastProblems=${count}`,
                message: 'Contrast problems detected',
                explanation: 'Foreground and background colors fail the contrast policy.',
                remediation: 'Increase contrast or use approved token combinations.',
                wcag: ['1.4.3'],
            }),
            countFindingRule({
                id: 'badge-style-mismatches',
                type: 'badge-style-mismatches',
                category: 'visual',
                severity: 'warning',
                metricPath: 'metrics.badgeStyleMismatches',
                legacyKey: (context, count) => `badgeStyleMismatches=${count}`,
                message: 'Badge style mismatches detected',
                explanation: 'Badge styles deviate from the expected visual language.',
                remediation: 'Apply the badge token set consistently.',
            }),
            countFindingRule({
                id: 'monospace-tone-mismatches',
                type: 'monospace-tone-mismatches',
                category: 'visual',
                severity: 'warning',
                metricPath: 'metrics.monospaceToneMismatches',
                legacyKey: (context, count) => `monospaceToneMismatches=${count}`,
                message: 'Monospace tone mismatches detected',
                explanation: 'Monospace content is not using the expected tonal treatment.',
                remediation: 'Use the monospace color and typography tokens consistently.',
            }),
            countFindingRule({
                id: 'monospace-vertical-inset-mismatch',
                type: 'monospace-vertical-inset-mismatch',
                category: 'visual',
                severity: 'warning',
                metricPath: 'metrics.monospaceVerticalInsetMismatches',
                legacyKey: (context, count) => `monospaceVerticalInsetMismatches=${count}`,
                message: 'Monospace box vertical insets are unbalanced',
                explanation: 'The visible top and bottom insets of a monospace content box are not balanced.',
                remediation: 'Render the content inside a dedicated block element and normalize line-height and padding.',
            }),
            customFindingRule({
                id: 'modal-backdrop',
                type: 'modal-backdrop',
                category: 'visual',
                severity: 'warning',
                scopes: ['dashboard', 'settings', 'users', 'nodes', 'dns', 'status', 'about', 'peers', 'auth', 'general'],
                build(context) {
                    const backdrop = context.metrics.modalBackdrop;
                    if (!backdrop || context.statusUnavailableExpected) return [];
                    const findings = [];
                    if (!backdrop.blurMatchesReference) {
                        findings.push({
                            id: 'modal-backdrop-blur',
                            type: 'modal-backdrop',
                            category: 'visual',
                            severity: 'warning',
                            count: 1,
                            value: backdrop.blurPx,
                            message: 'Modal backdrop blur mismatch',
                            explanation: 'Backdrop blur does not match the reference treatment.',
                            remediation: 'Align backdrop blur with the design token.',
                            legacyKey: `modalBackdropBlur=${backdrop.blurPx ?? 'missing'}`,
                        });
                    }
                    if (!backdrop.saturateMatchesReference) {
                        findings.push({
                            id: 'modal-backdrop-saturate',
                            type: 'modal-backdrop',
                            category: 'visual',
                            severity: 'warning',
                            count: 1,
                            value: backdrop.saturate,
                            message: 'Modal backdrop saturate mismatch',
                            explanation: 'Backdrop saturation does not match the reference treatment.',
                            remediation: 'Align backdrop saturation with the design token.',
                            legacyKey: `modalBackdropSaturate=${backdrop.saturate ?? 'missing'}`,
                        });
                    }
                    if (!backdrop.alphaMatchesReference) {
                        findings.push({
                            id: 'modal-backdrop-alpha',
                            type: 'modal-backdrop',
                            category: 'visual',
                            severity: 'warning',
                            count: 1,
                            value: backdrop.alpha,
                            message: 'Modal backdrop alpha mismatch',
                            explanation: 'Backdrop opacity does not match the reference treatment.',
                            remediation: 'Align backdrop alpha with the design token.',
                            legacyKey: `modalBackdropAlpha=${backdrop.alpha ?? 'missing'}`,
                        });
                    }
                    return findings;
                },
            }),
            customFindingRule({
                id: 'color-scheme-consistency',
                type: 'color-scheme-consistency',
                category: 'visual',
                severity: 'warning',
                build(context) {
                    const issues = context.metrics.colorSchemeConsistency || [];
                    return issues.map((issue) => ({
                        id: `color-scheme-${issue.type}`,
                        type: 'color-scheme-consistency',
                        category: 'visual',
                        severity: 'warning',
                        count: 1,
                        value: issue,
                        message: `Color scheme issue: ${issue.type}`,
                        explanation: 'The current color treatment does not match the expected brand/system relationship.',
                        remediation: 'Adjust the token choice or refactor the affected component styles.',
                        legacyKey: issue.type === 'missingGaugeElements' ? 'colorScheme:missingElements' : `colorScheme:${issue.type}:distance=${issue.distance}`,
                    }));
                },
            }),
            countFindingRule({
                id: 'deprecated-color-usage',
                type: 'deprecated-color-usage',
                category: 'visual',
                severity: 'error',
                metricPath: 'metrics.deprecatedColorUsage',
                legacyKey: (context, count) => `deprecatedColorUsage=${count}`,
                message: 'Deprecated color usage detected',
                explanation: 'A selector is using a deprecated color token or literal value.',
                remediation: 'Replace the color literal with the current token or semantic color.',
            }),
            thresholdFindingRule({
                id: 'visual-drift',
                type: 'visual-drift',
                category: 'visual',
                severity: 'error',
                metricPath: 'diff.ratio',
                threshold: () => 0.01,
                legacyKey: (context, value) => `visualDrift=${Number(value).toFixed(4)}`,
                message: 'Visual drift detected',
                explanation: 'The screenshot diff exceeded the allowed visual drift budget.',
                remediation: 'Inspect the diff and update the layout or baseline intentionally.',
            }),
            thresholdFindingRule({
                id: 'kpi-height-variance',
                type: 'kpi-height-variance',
                category: 'layout',
                severity: 'warning',
                when: (context) => context.scope !== 'dashboard',
                metricPath: 'metrics.spacing.kpiHeightVariance',
                threshold: () => 4,
                legacyKey: (context, value) => `kpiHeightVariance=${value}`,
                message: 'KPI height variance detected',
                explanation: 'The KPI cards do not share the same vertical rhythm.',
                remediation: 'Normalize the card heights and spacing tokens.',
            }),
        ],
    };
}
