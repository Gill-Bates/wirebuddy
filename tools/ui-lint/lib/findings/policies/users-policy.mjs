//
// tools/ui-lint/lib/findings/policies/users-policy.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { customFindingRule } from '../engine/policy-engine.mjs';
import { isMobileUsersScope } from '../scopes/users.mjs';

function buildContractFinding({
    id,
    type,
    severity,
    count,
    value,
    message,
    explanation,
    remediation,
    legacyKey,
}) {
    return {
        id,
        type,
        category: 'layout',
        severity,
        count,
        value,
        message,
        explanation,
        remediation,
        legacyKey,
    };
}

function buildContractViolations({
    contract,
    type,
    value,
    checks,
}) {
    if (!contract || contract.count <= 0) {
        return [];
    }

    const findings = [];
    for (const check of checks) {
        const count = Number(contract[check.countKey] || 0);
        if (count <= 0) {
            continue;
        }

        findings.push(buildContractFinding({
            id: check.id,
            type,
            severity: check.severity,
            count,
            value,
            message: check.message,
            explanation: check.explanation,
            remediation: check.remediation,
            legacyKey: `${check.legacyKey}=${count}`,
        }));
    }

    return findings;
}

export function buildUsersPolicy() {
    return {
        id: 'users-policy',
        owner: 'users-team',
        rules: [
            customFindingRule({
                id: 'users-mobile-action-toggle-contract',
                type: 'users-mobile-action-toggle-contract',
                category: 'layout',
                scopes: ['users'],
                build(context) {
                    if (!isMobileUsersScope(context)) {
                        return [];
                    }

                    const contract = context.metrics.spacing?.usersMobileActionToggleContract;
                    return buildContractViolations({
                        contract,
                        type: 'users-mobile-action-toggle-contract',
                        value: contract?.sample,
                        checks: [
                            {
                                id: 'users-mobile-action-toggle-square',
                                countKey: 'squareMismatchCount',
                                severity: 'warning',
                                legacyKey: 'usersMobileActionToggleSquare',
                                message: 'Users mobile action toggle is not square',
                                explanation: 'The mobile overflow toggle drifts away from the intended square shape and causes visual inconsistency.',
                                remediation: 'Set identical width and height values for .users-mobile-actions-toggle.',
                            },
                            {
                                id: 'users-mobile-action-toggle-touch-target',
                                countKey: 'touchTargetMismatchCount',
                                severity: 'error',
                                legacyKey: 'usersMobileActionToggleTouchTarget',
                                message: 'Users mobile action toggle misses touch target minimum',
                                explanation: 'The mobile overflow toggle falls below the minimum hit area required for reliable touch interaction.',
                                remediation: 'Use the touch-target token for both width and height on .users-mobile-actions-toggle.',
                            },
                            {
                                id: 'users-mobile-action-toggle-radius',
                                countKey: 'radiusMismatchCount',
                                severity: 'warning',
                                legacyKey: 'usersMobileActionToggleRadius',
                                message: 'Users mobile action toggle radius mismatches button token',
                                explanation: 'The toggle corner radius deviates from the shared button radius token and weakens visual consistency.',
                                remediation: 'Use var(--wb-btn-radius) for .users-mobile-actions-toggle border-radius.',
                            },
                            {
                                id: 'users-mobile-action-toggle-anchor',
                                countKey: 'anchorMismatchCount',
                                severity: 'warning',
                                legacyKey: 'usersMobileActionToggleAnchor',
                                message: 'Users mobile action toggle is not anchored to card top-right',
                                explanation: 'The overflow toggle is drifting from the expected top-right anchor and destabilizes the row layout.',
                                remediation: 'Align .users-mobile-actions positioning so the toggle remains near the card top-right corner.',
                            },
                        ],
                    });
                },
            }),
            customFindingRule({
                id: 'users-action-buttons-contract',
                type: 'users-action-buttons-contract',
                category: 'layout',
                scopes: ['users'],
                build(context) {
                    const contract = context.metrics.spacing?.usersActionButtons;
                    return buildContractViolations({
                        contract,
                        type: 'users-action-buttons-contract',
                        value: contract?.sample,
                        checks: [
                            {
                                id: 'users-action-buttons-missing-class',
                                countKey: 'missingClassCount',
                                severity: 'error',
                                legacyKey: 'usersActionButtonsMissingClass',
                                message: 'Users action buttons are missing shared class contract',
                                explanation: 'Action buttons must keep the shared class to preserve compact spacing and consistent interaction behavior.',
                                remediation: 'Apply .users-action-btn to all users action buttons in the row action set.',
                            },
                            {
                                id: 'users-action-buttons-missing-icon-size',
                                countKey: 'missingIconMdCount',
                                severity: 'warning',
                                legacyKey: 'usersActionButtonsMissingIconMd',
                                message: 'Users action button icon size class is missing',
                                explanation: 'Missing icon sizing classes cause inconsistent icon rhythm in the users action cluster.',
                                remediation: 'Apply .icon-md to all material icons inside users action buttons.',
                            },
                            {
                                id: 'users-action-buttons-touch-target',
                                countKey: 'undersizedCount',
                                severity: 'error',
                                legacyKey: 'usersActionButtonsUndersized',
                                message: 'Users action button touch target is too small',
                                explanation: 'Action buttons that fall below the minimum click target make the user management actions harder to use.',
                                remediation: 'Increase action button dimensions to meet the shared click target minimum.',
                            },
                            {
                                id: 'users-action-buttons-alignment',
                                countKey: 'alignmentMismatchCount',
                                severity: 'warning',
                                legacyKey: 'usersActionButtonsAlignmentMismatch',
                                message: 'Users action button content is not centered',
                                explanation: 'Centered icon alignment is part of the users action button design contract.',
                                remediation: 'Use inline-flex + align-items:center + justify-content:center for users action buttons.',
                            },
                            {
                                id: 'users-action-buttons-icon-pointer-events',
                                countKey: 'iconPointerMismatchCount',
                                severity: 'warning',
                                legacyKey: 'usersActionButtonsIconPointerMismatch',
                                message: 'Users action icon pointer-events contract mismatch',
                                explanation: 'Material icons should not intercept pointer events inside button controls.',
                                remediation: 'Set pointer-events:none on icons inside .users-action-btn controls.',
                            },
                            {
                                id: 'users-action-buttons-size-consistency',
                                countKey: 'sizeMismatchCount',
                                severity: 'warning',
                                legacyKey: 'usersActionButtonsSizeMismatch',
                                message: 'Users action buttons differ in size',
                                explanation: 'Inconsistent button sizes break visual grouping and muscle-memory for row actions.',
                                remediation: 'Normalize width and height across all users action buttons in each row.',
                            },
                            {
                                id: 'users-action-buttons-radius-consistency',
                                countKey: 'borderRadiusMismatchCount',
                                severity: 'warning',
                                legacyKey: 'usersActionButtonsRadiusMismatch',
                                message: 'Users action button radius is inconsistent',
                                explanation: 'Button radius inconsistencies create visual drift inside the users management action cluster.',
                                remediation: 'Use one shared radius token for all users action buttons.',
                            },
                        ],
                    });
                },
            }),
            customFindingRule({
                id: 'users-mobile-meta-contract',
                type: 'users-mobile-meta-contract',
                category: 'layout',
                scopes: ['users'],
                build(context) {
                    if (!isMobileUsersScope(context)) {
                        return [];
                    }

                    const contract = context.metrics.spacing?.usersMobileMetaContract;
                    return buildContractViolations({
                        contract,
                        type: 'users-mobile-meta-contract',
                        value: contract?.sample,
                        checks: [
                            {
                                id: 'users-mobile-meta-missing-structure',
                                countKey: 'missingStructureCount',
                                severity: 'error',
                                legacyKey: 'usersMobileMetaMissingStructure',
                                message: 'Users mobile key/value structure is incomplete',
                                explanation: 'Mobile users rows must provide both label and value blocks to keep the management card readable.',
                                remediation: 'Render each .users-mobile-meta row with .users-mobile-meta-label and .users-mobile-meta-value.',
                            },
                            {
                                id: 'users-mobile-meta-inline-contract',
                                countKey: 'inlineLayoutMismatchCount',
                                severity: 'warning',
                                legacyKey: 'usersMobileMetaInlineLayoutMismatch',
                                message: 'Users mobile key/value rows are not laid out inline',
                                explanation: 'The users mobile card contract expects labels on the left and values on the right in one row.',
                                remediation: 'Keep .users-mobile-meta as a horizontal flex row with separated label and value anchors.',
                            },
                            {
                                id: 'users-mobile-meta-value-alignment',
                                countKey: 'valueAlignmentMismatchCount',
                                severity: 'warning',
                                legacyKey: 'usersMobileMetaValueAlignmentMismatch',
                                message: 'Users mobile values are not right-aligned',
                                explanation: 'Right-aligned values are required for the compact card scan pattern in users mobile layout.',
                                remediation: 'Set .users-mobile-meta-value to align to the right edge (text-align:right and margin-left:auto).',
                            },
                            {
                                id: 'users-mobile-ip-structure',
                                countKey: 'ipStructureMismatchCount',
                                severity: 'warning',
                                legacyKey: 'usersMobileIpStructureMismatch',
                                message: 'Users mobile IP row is missing flag/code structure',
                                explanation: 'The IP row should include country marker plus monospace IP value for quick visual parsing.',
                                remediation: 'Render .users-mobile-ip-value with .users-mobile-ip-flag (or fallback) and code.ipv6.',
                            },
                            {
                                id: 'users-mobile-ip-order',
                                countKey: 'ipOrderMismatchCount',
                                severity: 'warning',
                                legacyKey: 'usersMobileIpOrderMismatch',
                                message: 'Users mobile IP flag and value order is incorrect',
                                explanation: 'Country marker must appear before the IP code to preserve the expected left-to-right scanning pattern.',
                                remediation: 'Place the flag/fallback element before code.ipv6 in .users-mobile-ip-value.',
                            },
                        ],
                    });
                },
            }),
        ],
    };
}
