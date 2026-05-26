//
// tools/ui-lint/tests/accessibility/focus-indicators.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import { collectDOMSnapshot } from '../../lib/dom-snapshot.mjs';
import { simulateTabNavigation } from '../../lib/focus-flow.mjs';
import { computeContrastRatio } from '../../lib/focus-visibility.mjs';
import { runRule } from '../../lib/rule-registry.mjs';
import '../../rules/accessibility/focus-indicators.mjs';
import { tokens } from '../../lib/design-tokens.mjs';

test('focus visibility helper measures contrast ratios from computed colors', async () => {
    expect(computeContrastRatio('rgb(255, 255, 255)', 'rgb(255, 255, 255)')).toBe(1);
    expect(computeContrastRatio('rgb(0, 0, 0)', 'rgb(255, 255, 255)')).toBeGreaterThan(20);
});

test('tab navigation visits focusable controls in DOM order', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.setContent(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <style>
    body {
      margin: 0;
      padding: 20px;
      font-family: sans-serif;
    }
  </style>
</head>
<body>
  <main class="main-content">
    <button id="first" type="button">First</button>
    <button id="second" type="button">Second</button>
    <button id="third" type="button">Third</button>
  </main>
</body>
</html>`);

    const states = await simulateTabNavigation(page, 3);

    expect(states.map((state) => state.selector)).toEqual(['#first', '#second', '#third']);
    expect(states.every((state) => state.focusVisible)).toBeTruthy();
});

test('focus indicator rule flags low-contrast rings and modal focus escape', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.setContent(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <style>
    body {
      margin: 0;
      padding: 20px;
      background: #ffffff;
      font-family: sans-serif;
    }

    button {
      width: 44px;
      height: 44px;
      margin: 0 0 12px 0;
      border: 1px solid #d1d5db;
      border-radius: 12px;
      background: #ffffff;
      color: #111827;
    }

    button:focus-visible {
      outline: 1px solid #ffffff;
      outline-offset: 1px;
      box-shadow: none;
    }

    .modal {
      display: none;
    }

    .modal.show {
      display: block;
      margin-top: 16px;
      padding: 16px;
      border: 1px solid #d1d5db;
      background: #f9fafb;
    }

    .modal .modal-actions {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }
  </style>
</head>
<body>
  <main class="main-content">
    <button id="outside" type="button" data-ui-component="shell-actions" data-ui-importance="secondary">Outside</button>

    <section class="modal show" data-ui-component="auth-modal" role="dialog" aria-modal="true">
      <div class="modal-actions">
        <button id="confirm" type="button" data-ui-component="auth-modal" data-ui-importance="primary">Confirm</button>
        <button id="cancel" type="button" data-ui-component="auth-modal" data-ui-importance="secondary">Cancel</button>
      </div>
    </section>
  </main>
</body>
</html>`);

    const snapshot = await collectDOMSnapshot(page);
    const findings = await runRule('focus-indicators', {
        page,
        snapshot,
        tokens,
    });

    expect(findings.some((finding) => finding.kind === 'focus-visibility')).toBeTruthy();
    expect(findings.some((finding) => finding.kind === 'modal-focus-escape')).toBeTruthy();

    const focusFinding = findings.find((finding) => finding.kind === 'focus-visibility');
    expect(focusFinding?.details.contrastRatio).toBeLessThan(3);
    expect(focusFinding?.details.component).toBeTruthy();

    const modalFinding = findings.find((finding) => finding.kind === 'modal-focus-escape');
    expect(modalFinding?.details.component).toBe('auth-modal');
});