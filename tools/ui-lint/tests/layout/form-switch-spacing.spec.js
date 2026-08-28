//
// tools/ui-lint/tests/layout/form-switch-spacing.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import formSwitchSpacingRule from '../../rules/layout/form-switch-spacing.mjs';

function buildSwitchFixture({ switchMargin = 0, descriptionMargin = 0, includeDescription = true } = {}) {
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <style>
    .form-check.form-switch {
      min-height: 44px;
      margin-bottom: ${switchMargin}px;
    }

    .switch-help {
      display: block;
      margin-top: ${descriptionMargin}px;
    }
  </style>
</head>
<body>
  <div class="form-check form-switch">
    <input class="form-check-input" type="checkbox" id="example-switch" aria-describedby="example-switch-help">
    <label class="form-check-label" for="example-switch">Example switch</label>
  </div>
  ${includeDescription ? '<small class="text-muted switch-help" id="example-switch-help">Example description</small>' : ''}
</body>
</html>`;
}

test('form switch spacing rule accepts helper text without extra margins', async ({ page }) => {
    await page.setContent(buildSwitchFixture());

    const findings = await formSwitchSpacingRule.run({
        page,
        browser: 'chromium',
        scope: 'settings',
    });

    expect(findings).toEqual([]);
});

test('form switch spacing rule flags margin before helper text', async ({ page }) => {
    await page.setContent(buildSwitchFixture({ switchMargin: 8 }));

    const findings = await formSwitchSpacingRule.run({
        page,
        browser: 'chromium',
        scope: 'settings',
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
        kind: 'form-switch-description-gap',
        selector: '#example-switch',
        details: {
            marginBottom: 8,
            descriptionMarginTop: 0,
        },
    });
});

test('form switch spacing rule flags margin applied to helper text', async ({ page }) => {
    await page.setContent(buildSwitchFixture({ descriptionMargin: 8 }));

    const findings = await formSwitchSpacingRule.run({
        page,
        browser: 'chromium',
        scope: 'nodes',
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].details).toMatchObject({
        marginBottom: 0,
        descriptionMarginTop: 8,
    });
});

test('form switch spacing rule ignores standalone switches with section spacing', async ({ page }) => {
    await page.setContent(buildSwitchFixture({ switchMargin: 16, includeDescription: false }));

    const findings = await formSwitchSpacingRule.run({
        page,
        browser: 'chromium',
        scope: 'settings',
    });

    expect(findings).toEqual([]);
});
