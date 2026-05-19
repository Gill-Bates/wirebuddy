//
// tools/ui-lint/lib/findings/engine/decision-tree.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { createFinding } from './policy-engine.mjs';

export function correlateFindings(findings, context) {
    const correlated = [...findings];
    const typeSet = new Set(findings.map((finding) => finding.type));

    if (typeSet.has('horizontal-overflow') && (typeSet.has('clipped-buttons') || typeSet.has('hidden-interactive'))) {
        correlated.push(createFinding({
            id: 'interaction-containment-failure',
            type: 'interaction-containment-failure',
            category: 'layout',
            severity: 'error',
            riskLevel: 'blocker',
            scope: context.scope,
            owner: 'ui-lint',
            confidence: 0.92,
            message: 'Interaction containment failure detected',
            explanation: 'Overflow, clipping, and hidden controls are co-occurring and likely blocking interaction.',
            remediation: 'Resolve overflow first, then re-check clipping and focusability.',
            rootCauseChain: ['horizontal-overflow', 'clipped-buttons', 'hidden-interactive'],
            legacyKey: 'interactionContainmentFailure',
            source: 'decision-tree',
        }));
    }

    return correlated;
}
