//
// tools/ui-lint/tests/rules/index.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import {
    createExecutionGraphWithState,
    createRuleRegistryState,
    registerRuleWithState,
} from '../../lib/rule-orchestration/index.mjs';
import { RULE_MANIFEST } from '../../rules/manifest.mjs';
import {
    getAllRules,
    getRuleCatalog,
    loadRules,
} from '../../rules/index.mjs';

test('rule manifest and catalog stay aligned', async () => {
    await loadRules();

    const manifestIds = RULE_MANIFEST.map((entry) => entry.id).sort();
    const catalog = getRuleCatalog().sort((left, right) => left.id.localeCompare(right.id));

    expect(getAllRules().map((rule) => rule.id).sort()).toEqual(manifestIds);
    expect(catalog.map((entry) => entry.id).sort()).toEqual(manifestIds);
    expect(catalog.find((entry) => entry.id === 'horizontal-overflow')).toMatchObject({
        category: 'layout',
        performanceCost: 'cheap',
        executionMode: 'parallel',
    });
    expect(catalog.find((entry) => entry.id === 'form-switch-spacing')).toMatchObject({
        category: 'layout',
        performanceCost: 'cheap',
        executionMode: 'parallel',
        tags: expect.arrayContaining(['forms', 'switches', 'spacing']),
    });
    expect(catalog.find((entry) => entry.id === 'scroll-traps')).toMatchObject({
        category: 'mobile',
        tags: expect.arrayContaining(['mobile', 'ios', 'scroll']),
        severityByBrowser: expect.objectContaining({ webkit: 'serious' }),
    });
    expect(catalog.find((entry) => entry.id === 'settings-logs-layout')).toMatchObject({
        category: 'layout',
        performanceCost: 'cheap',
        executionMode: 'parallel',
        tags: expect.arrayContaining(['settings', 'logs']),
    });
    expect(catalog.find((entry) => entry.id === 'control-contracts')).toMatchObject({
        category: 'accessibility',
        performanceCost: 'cheap',
        executionMode: 'parallel',
        tags: expect.arrayContaining(['buttons', 'icons']),
    });
    expect(catalog.find((entry) => entry.id === 'changelog-details')).toMatchObject({
        category: 'component',
        executionMode: 'parallel',
        tags: expect.arrayContaining(['changelog', 'disclosure']),
    });
    expect(catalog.find((entry) => entry.id === 'dashboard-light-surfaces')).toMatchObject({
        category: 'component',
        executionMode: 'parallel',
        tags: expect.arrayContaining(['dashboard', 'light-mode']),
    });
});

function planRule(id, extra = {}) {
    return { id, run: async () => [], meta: { id, ...extra } };
}

test('planner filters rules by view scope and rejects dependency cycles', async () => {
    await loadRules();
    const catalog = getRuleCatalog();
    expect(catalog.find((entry) => entry.id === 'changelog-details')?.scopes).toEqual(['about']);

    const state = createRuleRegistryState();
    registerRuleWithState(state, planRule('about-only', { scopes: ['about'] }));
    registerRuleWithState(state, planRule('everywhere'));
    const idsFor = (scope) => createExecutionGraphWithState(state, undefined, { scope }).plannedRuleIds.sort();
    expect(idsFor('about')).toEqual(['about-only', 'everywhere']);
    expect(idsFor('dashboard')).toEqual(['everywhere']);

    const selfState = createRuleRegistryState();
    registerRuleWithState(selfState, planRule('self', { dependencies: ['self'] }));
    expect(() => createExecutionGraphWithState(selfState, undefined, {})).toThrow('dependency cycle');

    const cycleState = createRuleRegistryState();
    registerRuleWithState(cycleState, planRule('a', { dependencies: ['b'] }));
    registerRuleWithState(cycleState, planRule('b', { dependencies: ['a'] }));
    registerRuleWithState(cycleState, planRule('free'));
    expect(() => createExecutionGraphWithState(cycleState, undefined, {})).toThrow(/cycle.*a, b/);
});
