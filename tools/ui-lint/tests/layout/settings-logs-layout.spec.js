//
// tools/ui-lint/tests/layout/settings-logs-layout.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import settingsLogsLayoutRule from '../../rules/layout/settings-logs-layout.mjs';

function buildLogsFixture(css) {
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <style>
    body {
      margin: 0;
      padding: 16px;
      font-family: sans-serif;
    }

    #logs-pane .logs-metrics-row {
      display: flex;
      flex-wrap: nowrap;
      align-items: baseline;
      gap: 12px;
    }

    #logs-pane .logs-metric-item {
      flex: 1 1 0;
      min-width: 0;
      white-space: nowrap;
    }

    #logs-pane .metrics-delete hr {
      margin: 4px 0 4px;
    }

    #logs-pane .metrics-delete-inner {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      padding-top: 10px;
    }

    ${css}
  </style>
</head>
<body>
  <main id="logs-pane">
    <section class="card-body">
      <div class="logs-metrics-row">
        <div class="logs-metric-item">Size: 12 MB</div>
        <div class="logs-metric-item">Peers: 7</div>
        <div class="logs-metric-item">Files: 25</div>
      </div>
      <div class="metrics-delete">
        <hr>
        <div class="metrics-delete-inner">
          <div class="metrics-delete-copy">Delete all Traffic Metrics</div>
          <button type="button">Purge</button>
        </div>
      </div>
    </section>
  </main>
</body>
</html>`;
}

test('settings logs layout rule stays quiet on the expected layout contract', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.setContent(buildLogsFixture(''));

    const findings = await settingsLogsLayoutRule.run({
        page,
        browser: 'chromium',
        scope: 'settings',
    });

    expect(findings).toEqual([]);
});

test('settings logs layout rule flags wrapped metrics rows on desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.setContent(buildLogsFixture(`
      #logs-pane .logs-metrics-row {
        flex-wrap: wrap;
      }

      #logs-pane .logs-metric-item {
        flex: 0 0 100%;
      }
    `));

    const findings = await settingsLogsLayoutRule.run({
        page,
        browser: 'chromium',
        scope: 'settings',
    });

    expect(findings.some((finding) => finding.kind === 'settings-logs-metrics-row-wrap')).toBeTruthy();
    expect(findings.some((finding) => finding.kind === 'settings-logs-metrics-row-stacked')).toBeTruthy();
});

test('settings logs layout rule flags too-tight delete-section spacing', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.setContent(buildLogsFixture(`
      #logs-pane .metrics-delete hr {
        margin-bottom: 0;
      }

      #logs-pane .metrics-delete-inner {
        padding-top: 2px;
      }
    `));

    const findings = await settingsLogsLayoutRule.run({
        page,
        browser: 'chromium',
        scope: 'settings',
    });

    expect(findings.some((finding) => finding.kind === 'settings-logs-delete-hairline-gap')).toBeTruthy();
    expect(findings.some((finding) => finding.kind === 'settings-logs-delete-padding-top')).toBeTruthy();
});
