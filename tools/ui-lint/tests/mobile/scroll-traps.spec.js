//
// tools/ui-lint/tests/mobile/scroll-traps.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import scrollTrapsRule from '../../rules/mobile/scroll-traps.mjs';
import { collectDOMSnapshot } from '../../lib/dom-snapshot.mjs';
import { mountContractPage } from '../support/contract-fixtures.mjs';

test('intentional scrollers stay quiet when they are isolated local panels', async ({ page }) => {
    await mountContractPage(page, {
        width: 390,
        height: 844,
        stylesheetPaths: ['app/static/css/core/tokens.css'],
        body: `
<section class="card">
    <div
        class="activity-feed"
        data-ui-scroll-container="intentional"
        style="height: 180px; overflow-y: auto; overscroll-behavior: contain;"
    >
        <div style="height: 620px; padding: 12px;">
            ${'feed entry '.repeat(80)}
        </div>
    </div>
</section>
`,
    });

    const snapshot = await collectDOMSnapshot(page);
    const findings = await scrollTrapsRule.run({ page, snapshot, browser: 'chromium', scope: 'dashboard' });

    expect(findings).toEqual([]);
});

test('computed-style nested scroll containers are classified as a modal scroll jail', async ({ page }) => {
    await mountContractPage(page, {
        width: 390,
        height: 844,
        stylesheetPaths: ['app/static/css/core/tokens.css'],
        body: `
<style>
    body {
        margin: 0;
        height: 100vh;
        overflow: hidden;
    }

    .modal-shell {
        display: flex;
        flex-direction: column;
        height: 100vh;
        padding: 12px;
        gap: 12px;
    }

    .modal-body {
        flex: 1 1 auto;
        min-height: 0;
        overflow-y: auto;
        overscroll-behavior: contain;
        border: 1px solid #d1d5db;
        border-radius: 12px;
    }

    .timeline {
        height: 180px;
        overflow-y: auto;
        background: #f9fafb;
        border-top: 1px solid #d1d5db;
    }

    .timeline > div {
        height: 640px;
        padding: 12px;
    }
</style>
<section class="modal modal-shell show" data-ui-component="notifications-modal" role="dialog" aria-modal="true">
    <header style="position: sticky; top: 0; background: #fff; z-index: 1;">
        <button type="button" data-ui-importance="primary">Confirm</button>
    </header>
    <div class="modal-body" data-ui-component="notifications-modal">
        <div style="height: 920px; padding: 12px; display: flex; flex-direction: column; gap: 12px;">
            <p>${'modal content '.repeat(60)}</p>
            <div class="timeline" data-ui-component="activity-timeline">
                <div>${'timeline item '.repeat(70)}</div>
            </div>
        </div>
    </div>
</section>
`,
    });

    const snapshot = await collectDOMSnapshot(page);
    const findings = await scrollTrapsRule.run({ page, snapshot, browser: 'webkit', scope: 'dashboard' });

    expect(findings.some((finding) => finding.kind === 'modal-scroll-jail')).toBeTruthy();
    expect(findings.some((finding) => finding.kind === 'webkit-scroll-momentum')).toBeTruthy();

    const modalFinding = findings.find((finding) => finding.kind === 'modal-scroll-jail');
    expect(modalFinding?.severity).toBe('error');
    expect(modalFinding?.details.component).toBe('activity-timeline');
    expect(modalFinding?.details.axis).toBe('vertical');
    expect(modalFinding?.details.nestingDepth).toBeGreaterThanOrEqual(1);
    expect(modalFinding?.details.bodyLocked).toBeTruthy();
    expect(modalFinding?.details.scrollAncestors.length).toBeGreaterThanOrEqual(1);
});