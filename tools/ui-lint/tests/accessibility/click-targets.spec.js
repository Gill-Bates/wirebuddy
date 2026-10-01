//
// tools/ui-lint/tests/accessibility/click-targets.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import clickTargetRule from '../../rules/accessibility/click-targets.mjs';
import { collectDOMSnapshot } from '../../lib/dom-snapshot.mjs';
import { getViewportAwareTouchTarget } from '../../lib/interaction-utils.mjs';
import { runRule } from '../../lib/rule-registry.mjs';
import { tokens } from '../../lib/design-tokens.mjs';

test('viewport-aware touch target thresholds follow the device class', async () => {
    expect(getViewportAwareTouchTarget(tokens, { width: 390, height: 844 })).toBe(44);
    expect(getViewportAwareTouchTarget(tokens, { width: 834, height: 1194 })).toBe(40);
    expect(getViewportAwareTouchTarget(tokens, { width: 1440, height: 1100 })).toBe(32);
});

test('click target rule groups compact peer actions and flags occluded controls', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.setContent(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <style>
    body {
      margin: 0;
      padding: 16px;
      font-family: sans-serif;
    }

    .toolbar {
      position: relative;
      display: flex;
      gap: 4px;
      align-items: center;
    }

    .toolbar button {
      width: 28px;
      height: 28px;
      padding: 0;
      border: 1px solid #6b7280;
      border-radius: 8px;
      background: #fff;
    }

    .toolbar .overlay {
      position: absolute;
      left: 0;
      top: 0;
      width: 28px;
      height: 28px;
      background: rgba(255, 0, 0, 0.15);
      pointer-events: auto;
    }
  </style>
</head>
<body>
  <main class="main-content">
    <div class="toolbar" data-ui-component="peer-actions" data-ui-density="compact">
      <button type="button" data-action="show-qr" data-peer-id="42" data-ui-importance="secondary" aria-label="Show QR code">Q</button>
      <button type="button" data-action="download-config" data-peer-id="42" data-ui-importance="secondary" aria-label="Download config">D</button>
      <div class="overlay" aria-hidden="true"></div>
    </div>
  </main>
</body>
</html>`);

    const snapshot = await collectDOMSnapshot(page);
    const findings = await runRule('click-targets', {
        page,
        snapshot,
        tokens,
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('error');
    expect(findings[0].details.component).toBe('peer-actions');
    expect(findings[0].details.count).toBe(2);
    expect(findings[0].details.viewport).toBe('mobile');
    expect(findings[0].details.items.some((item) => item.occluded)).toBeTruthy();
    expect(findings[0].details.items.every((item) => item.component === 'peer-actions')).toBeTruthy();
    expect(findings[0].details.items.every((item) => item.required === 37)).toBeTruthy();
});


test('each id-less control is inspected separately instead of collapsing onto the first match', async ({ page }) => {
    // Regression: the rule used to read dataAction/dataUiComponent/disabled flat off
    // the snapshot node, where they live under semantic.* / accessibility.*. Every
    // read returned undefined, so buildInteractionSelector fell back to the bare tag
    // and inspectInteractionTargets re-measured document.querySelector('button') for
    // every target. Here only the *second* button is occluded, so a collapsed
    // selector cannot report an occlusion at all.
    await page.setViewportSize({ width: 390, height: 844 });
    await page.setContent(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <style>
    body { margin: 0; padding: 16px; font-family: sans-serif; }
    .toolbar { position: relative; display: flex; gap: 4px; align-items: center; }
    .toolbar button { width: 28px; height: 28px; padding: 0; border: 1px solid #6b7280; background: #fff; }
    .cover { position: absolute; left: 32px; top: 0; width: 28px; height: 28px; background: rgba(255, 0, 0, 0.15); pointer-events: auto; }
  </style>
</head>
<body>
  <main class="main-content">
    <div class="toolbar" data-ui-component="peer-actions" data-ui-density="compact">
      <button type="button" data-action="show-qr" data-peer-id="42" data-ui-importance="secondary" aria-label="Show QR code">Q</button>
      <button type="button" data-action="download-config" data-peer-id="42" data-ui-importance="secondary" aria-label="Download config">D</button>
      <div class="cover" aria-hidden="true"></div>
      <button type="button" disabled data-action="delete-peer" data-peer-id="42" aria-label="Delete peer">X</button>
    </div>
  </main>
</body>
</html>`);

    const snapshot = await collectDOMSnapshot(page);
    const findings = await runRule('click-targets', { page, snapshot, tokens });

    expect(findings).toHaveLength(1);
    const items = findings[0].details.items;

    // The disabled control is skipped via accessibility.disabled.
    expect(items).toHaveLength(2);
    expect(items.some((item) => /delete-peer/.test(String(item.selector)))).toBeFalsy();

    // Distinct selectors, so each button is measured as itself.
    expect(new Set(items.map((item) => item.selector)).size).toBe(2);
    expect(items.every((item) => item.exists !== false)).toBeTruthy();

    // Only the download button sits under the overlay.
    const occluded = items.filter((item) => item.occluded);
    expect(occluded).toHaveLength(1);
    expect(occluded[0].selector).toContain('download-config');
});
