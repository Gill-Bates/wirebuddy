//
// tools/ui-lint/lib/findings/policies/network-policy.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { countFindingRule } from '../engine/policy-engine.mjs';

export function buildNetworkPolicy() {
    return {
        id: 'network-policy',
        owner: 'platform-ui',
        rules: [
            countFindingRule({
                id: 'console-entries',
                type: 'console-entries',
                category: 'network',
                severity: 'error',
                metricPath: 'network.consoleEntries',
                legacyKey: (context, count) => `console=${count}`,
                message: 'Console entries captured during the run',
                explanation: 'The page emitted console output that should be investigated.',
                remediation: 'Remove debug output or address the runtime error.',
            }),
            countFindingRule({
                id: 'page-errors',
                type: 'page-errors',
                category: 'network',
                severity: 'error',
                metricPath: 'network.pageErrors',
                legacyKey: (context, count) => `pageErrors=${count}`,
                message: 'Page errors captured during the run',
                explanation: 'Unhandled page errors indicate a runtime issue in the audited UI.',
                remediation: 'Fix the script or component that raises the error.',
            }),
            countFindingRule({
                id: 'failed-requests',
                type: 'failed-requests',
                category: 'network',
                severity: 'error',
                metricPath: 'network.requestFailures',
                legacyKey: (context, count) => `failedRequests=${count}`,
                message: 'Failed requests captured during the run',
                explanation: 'Network requests failed and may affect the correctness of the rendered page.',
                remediation: 'Check endpoints, caching, and authentication for the failing requests.',
            }),
            countFindingRule({
                id: 'bad-responses',
                type: 'bad-responses',
                category: 'network',
                severity: 'error',
                metricPath: 'network.badResponses',
                legacyKey: (context, count) => `badResponses=${count}`,
                message: 'Bad responses captured during the run',
                explanation: 'The audited page received unexpected response codes.',
                remediation: 'Inspect the affected endpoints and response handling.',
            }),
            countFindingRule({
                id: 'duplicate-requests',
                type: 'duplicate-requests',
                category: 'network',
                severity: 'warning',
                metricPath: 'network.duplicateRequests',
                legacyKey: (context, count) => `duplicateRequests=${count}`,
                message: 'Duplicate GET requests detected',
                explanation: 'The same resources are being fetched repeatedly and may indicate inefficient loading.',
                remediation: 'Deduplicate fetches or cache the shared resource data.',
            }),
        ],
    };
}
