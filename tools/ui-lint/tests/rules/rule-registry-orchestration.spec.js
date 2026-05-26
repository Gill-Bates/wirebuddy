//
// tools/ui-lint/tests/rules/rule-registry-orchestration.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import { loadRules } from '../../rules/index.mjs';
import {
    RuleBuilder,
    createContext,
    exportRegistry,
    getExecutionGraph,
    getRuleHealth,
    getRuleMetadata,
    getRuleTelemetry,
    getRulesByCapability,
    registerRule,
    runRules,
    unregisterRule,
    whyDidRuleFail,
} from '../../lib/rule-registry.mjs';

test.beforeAll(async () => {
    await loadRules();
});

test('rule registry normalizes rich metadata contracts and capability discovery', async () => {
    const rule = RuleBuilder.layout('registry-contract-temp', 'Registry contract temp rule', async () => []);
    rule.meta = {
        ...rule.meta,
        version: '2.1.0',
        subcategory: 'overflow',
        severity: {
            default: 'warning',
            mobile: 'error',
        },
        wcag: ['1.4.10'],
        impacts: ['layout', 'interaction', 'scrolling'],
        affects: ['mobile', 'desktop'],
        tags: ['overflow', 'responsive', 'viewport'],
        owner: 'ui-platform',
        cost: 'medium',
        stability: 'stable',
        confidence: 0.94,
        requiresSnapshot: true,
        requiresPage: false,
        requiresInteraction: false,
        experimental: false,
        deprecated: false,
        dependencies: [],
        conflictsWith: [],
        remediation: ['Apply min-width:0', 'Avoid fixed pixel widths'],
        featureFlags: ['advanced-overflow-analysis'],
        environments: ['ci', 'local'],
        supportsRegressionTracking: true,
        historicalWeight: 1.5,
        priority: 'critical',
        executionMode: 'parallel',
        capabilities: ['dom'],
        ciPolicy: { failBuild: true, allowWarnings: 3 },
    };

    registerRule(rule);
    try {
        const metadata = getRuleMetadata('registry-contract-temp');
        expect(metadata).toMatchObject({
            id: 'registry-contract-temp',
            version: '2.1.0',
            subcategory: 'overflow',
            owner: 'ui-platform',
            cost: 'medium',
            stability: 'stable',
            confidence: 0.94,
            requiresSnapshot: true,
            requiresPage: false,
            requiresInteraction: false,
            experimental: false,
            deprecated: false,
            priority: 'critical',
            executionMode: 'parallel',
        });
        expect(metadata.wcag).toEqual(['1.4.10']);
        expect(metadata.impacts).toEqual(['layout', 'interaction', 'scrolling']);
        expect(metadata.affects).toEqual(['mobile', 'desktop']);
        expect(metadata.tags).toEqual(['overflow', 'responsive', 'viewport']);
        expect(metadata.featureFlags).toEqual(['advanced-overflow-analysis']);
        expect(metadata.environments).toEqual(['ci', 'local']);
        expect(metadata.ciPolicy).toEqual({ failBuild: true, allowWarnings: 3 });
        expect(getRulesByCapability('dom').some((candidate) => candidate.id === 'registry-contract-temp')).toBe(true);
        expect(exportRegistry().capabilities.dom).toContain('registry-contract-temp');
    } finally {
        unregisterRule('registry-contract-temp');
    }
});

test('rule registry plans dependencies before execution and tracks telemetry', async () => {
    const executionOrder = [];

    const rootRule = RuleBuilder.layout('registry-dependency-root', 'Registry dependency root rule', async () => {
        executionOrder.push('root');
        return [{
            severity: 'warning',
            kind: 'registry-root',
            message: 'Root rule executed',
            details: { explanation: 'Root rule completed', remediation: 'No action required' },
        }];
    });
    rootRule.meta = {
        ...rootRule.meta,
        version: '1.0.0',
        owner: 'ui-platform',
        cost: 'low',
        priority: 'critical',
        executionMode: 'parallel',
        capabilities: ['dom'],
        dependencies: [],
        requiresSnapshot: false,
    };

    const dependentRule = RuleBuilder.layout('registry-dependency-child', 'Registry dependency child rule', async () => {
        executionOrder.push('child');
        return [{
            severity: 'warning',
            kind: 'registry-child',
            message: 'Child rule executed',
            details: { explanation: 'Child rule completed', remediation: 'No action required' },
        }];
    });
    dependentRule.meta = {
        ...dependentRule.meta,
        version: '1.0.0',
        owner: 'ui-platform',
        cost: 'medium',
        priority: 'standard',
        executionMode: 'serial',
        capabilities: ['dom'],
        dependencies: ['registry-dependency-root'],
        requiresSnapshot: false,
    };

    registerRule(rootRule);
    registerRule(dependentRule);

    try {
        const context = createContext({
            scope: 'dashboard',
            options: {
                browser: 'webkit',
                device: 'mobile',
                environment: 'ci',
            },
        });

        const graph = getExecutionGraph(['registry-dependency-child', 'registry-dependency-root'], context);
        expect(graph.plannedRuleIds).toEqual(['registry-dependency-root', 'registry-dependency-child']);
        expect(graph.executionGraph[0].ruleIds).toContain('registry-dependency-root');

        const findings = await runRules(['registry-dependency-child', 'registry-dependency-root'], context);
        expect(executionOrder).toEqual(['root', 'child']);
        expect(findings.map((finding) => finding.rule)).toEqual(['registry-dependency-root', 'registry-dependency-child']);

        const telemetry = getRuleTelemetry('registry-dependency-root');
        expect(telemetry).toMatchObject({
            executionCount: 1,
            lastStatus: 'completed',
            health: 'stable',
        });
        expect(getRuleHealth('registry-dependency-root')).toBe('stable');

        const explanation = whyDidRuleFail(rootRule, findings.filter((finding) => finding.rule === 'registry-dependency-root'), telemetry, context);
        expect(explanation).toMatchObject({
            ruleId: 'registry-dependency-root',
            owner: 'ui-platform',
            category: 'layout',
        });
        expect(explanation.telemetry).toMatchObject({
            health: 'stable',
            pageEvaluations: 0,
            domReads: 0,
        });
    } finally {
        unregisterRule('registry-dependency-root');
        unregisterRule('registry-dependency-child');
    }
});
