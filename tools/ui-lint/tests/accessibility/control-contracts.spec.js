//
// tools/ui-lint/tests/accessibility/control-contracts.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import controlContractsRule from '../../rules/accessibility/control-contracts.mjs';

test('control contracts accept explicit button types and hidden button icons', async ({ page }) => {
    await page.setContent(`
        <button type="button" aria-label="Refresh">
            <span class="material-icons" aria-hidden="true">refresh</span>
        </button>
    `);

    const findings = await controlContractsRule.run({ page, browser: 'chromium', scope: 'about' });

    expect(findings).toEqual([]);
});

test('control contracts flag missing button type and exposed decorative icon', async ({ page }) => {
    await page.setContent(`
        <button id="bad-control">
            <span class="material-icons">refresh</span>
            Refresh
        </button>
    `);

    const findings = await controlContractsRule.run({ page, browser: 'chromium', scope: 'about' });

    expect(findings).toHaveLength(2);
    expect(findings.map((finding) => finding.kind)).toEqual([
        'button-type-missing',
        'button-icon-not-hidden',
    ]);
});
