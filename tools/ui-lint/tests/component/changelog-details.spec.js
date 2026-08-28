//
// tools/ui-lint/tests/component/changelog-details.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import changelogDetailsRule from '../../rules/component/changelog-details.mjs';

test('changelog disclosure accepts a details element with a summary', async ({ page }) => {
    await page.setContent(`
        <div class="about-changelog-col">
            <details><summary>Previous versions...</summary><p>1.5.4</p></details>
        </div>
    `);

    const findings = await changelogDetailsRule.run({ page, browser: 'chromium', scope: 'about' });

    expect(findings).toEqual([]);
});

test('changelog disclosure flags missing details markup', async ({ page }) => {
    await page.setContent('<div class="about-changelog-col"><p>1.6.0</p></div>');

    const findings = await changelogDetailsRule.run({ page, browser: 'chromium', scope: 'about' });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
        kind: 'changelog-details-missing',
        selector: '.about-changelog-col details',
    });
});

test('changelog disclosure flags a details element without a summary', async ({ page }) => {
    await page.setContent('<div class="about-changelog-col"><details><p>1.5.4</p></details></div>');

    const findings = await changelogDetailsRule.run({ page, browser: 'chromium', scope: 'about' });

    expect(findings[0].kind).toBe('changelog-summary-missing');
});
