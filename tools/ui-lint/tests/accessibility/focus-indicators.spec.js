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


test('a box-shadow-only focus ring clears the area gate the rule applies', async () => {
    // Regression: the geometry derived its area from outlineWidth/outlineOffset only,
    // so a Bootstrap-style `box-shadow: 0 0 0 .25rem` ring scored area 0 and always
    // failed focus-indicators' `focusArea < minArea` check. Asserted against that
    // exact formula rather than against "no findings", which would also pass when
    // the rule never evaluates the control at all.
    const { isFocusVisibleEnough } = await import('../../lib/focus-visibility.mjs');

    const before = {
        outlineStyle: 'none', outlineWidth: '0px', outlineColor: 'rgb(33, 37, 41)', outlineOffset: '0px',
        boxShadow: 'none', boxShadowColor: '', borderColor: 'rgb(206, 212, 218)',
        backgroundColor: 'rgb(255, 255, 255)', color: 'rgb(33, 37, 41)',
    };
    const after = { ...before, boxShadow: 'rgb(10, 88, 202) 0px 0px 0px 4px', boxShadowColor: 'rgb(10, 88, 202)' };
    const elementRect = { width: 120, height: 38 };

    const result = isFocusVisibleEnough({ before, after, elementRect, focusRect: { width: 128, height: 46 } });
    const minArea = Math.max(16, Math.round(elementRect.width + elementRect.height));

    expect(result.visible).toBe(true);
    expect(result.focusRingArea).toBeGreaterThanOrEqual(minArea);
    // Contrast must come from the shadow colour, not from the reported outlineColor.
    expect(result.contrastRatio).toBeLessThan(10);
    expect(result.sufficientContrast).toBe(true);
});

test('focus geometry derives the ring width from the box-shadow spread', async () => {
    const { getFocusIndicatorGeometry } = await import('../../lib/focus-visibility.mjs');

    const shadowOnly = getFocusIndicatorGeometry({
        outlineWidth: '0px',
        outlineOffset: '0px',
        boxShadow: 'rgb(10, 88, 202) 0px 0px 0px 4px',
    });
    expect(shadowOnly.shadowSpread).toBe(4);
    expect(shadowOnly.ringWidth).toBe(4);
    expect(shadowOnly.area).toBeGreaterThan(0);

    // Blur alone is a glow, not a ring.
    expect(getFocusIndicatorGeometry({ boxShadow: 'rgb(10, 88, 202) 0px 0px 3px' }).ringWidth).toBe(0);

    // An outline still wins when it is the thicker ring.
    expect(getFocusIndicatorGeometry({ outlineWidth: '6px', boxShadow: 'rgb(0, 0, 0) 0px 0px 0px 2px' }).ringWidth).toBe(6);
});

test('focus geometry ignores drop and inset shadows and takes the widest ring in a list', async () => {
    const { getFocusIndicatorGeometry } = await import('../../lib/focus-visibility.mjs');

    // A soft drop shadow with an offset is not a focus ring.
    expect(getFocusIndicatorGeometry({ boxShadow: 'rgba(0, 0, 0, 0.2) 0px 2px 8px 0px' }).ringWidth).toBe(0);

    // A leading inset shadow must not hide or replace the real ring.
    const mixed = 'rgb(0, 0, 0) 0px 0px 0px 9px inset, rgb(10, 88, 202) 0px 0px 0px 3px, rgba(0, 0, 0, 0.2) 0px 4px 12px 0px';
    expect(getFocusIndicatorGeometry({ boxShadow: mixed }).ringWidth).toBe(3);
});
