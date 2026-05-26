//
// tools/ui-lint/tests/rules/index.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

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
});