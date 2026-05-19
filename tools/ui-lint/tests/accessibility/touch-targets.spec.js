//
// tools/ui-lint/tests/accessibility/touch-targets.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import { tokens } from '../../lib/design-tokens.mjs';
import { mountContractPage } from '../support/contract-fixtures.mjs';

const peerMarkup = `
<div class="peer-card-list" id="peer-card-list">
    <article class="peer-card" data-peer-id="42">
        <div class="peer-card-actions">
            <button type="button" class="btn btn-sm btn-outline-secondary peer-card-action-btn" aria-label="Show QR">
                <span class="material-icons" aria-hidden="true">Q</span>
            </button>
            <button type="button" class="btn btn-sm btn-outline-secondary peer-card-action-btn" aria-label="Download config">
                <span class="material-icons" aria-hidden="true">D</span>
            </button>
            <div class="dropdown peer-card-more-actions">
                <button type="button" class="btn btn-sm btn-outline-secondary peer-card-action-btn" aria-label="More actions">
                    <span class="material-icons" aria-hidden="true">M</span>
                </button>
            </div>
        </div>
    </article>
</div>
`;

const nodeMarkup = `
<div class="table-responsive">
    <table class="nodes-table">
        <tbody>
            <tr>
                <td data-label="Actions" class="node-actions-cell">
                    <div class="d-flex">
                        <button type="button" class="btn btn-sm btn-outline-secondary node-action-btn" aria-label="Edit node">
                            <span class="material-icons" aria-hidden="true">E</span>
                        </button>
                        <button type="button" class="btn btn-sm btn-outline-secondary node-action-btn" aria-label="Copy config">
                            <span class="material-icons" aria-hidden="true">C</span>
                        </button>
                        <button type="button" class="btn btn-sm btn-outline-secondary node-action-btn node-actions-more" aria-label="More actions">
                            <span class="material-icons" aria-hidden="true">M</span>
                        </button>
                    </div>
                </td>
            </tr>
        </tbody>
    </table>
</div>
`;

async function expectTargetsToRespectMinimum(page, selector) {
    const boxes = await page.locator(selector).evaluateAll((elements) =>
        elements.map((element) => {
            const rect = element.getBoundingClientRect();
            return {
                left: rect.left,
                top: rect.top,
                right: rect.right,
                bottom: rect.bottom,
                width: rect.width,
                height: rect.height,
            };
        })
    );

    expect(boxes).not.toHaveLength(0);

    for (const box of boxes) {
        expect(box.width).toBeGreaterThanOrEqual(tokens.interaction.touchTargetMin);
        expect(box.height).toBeGreaterThanOrEqual(tokens.interaction.touchTargetMin);
    }

    for (let index = 0; index < boxes.length; index += 1) {
        for (let other = index + 1; other < boxes.length; other += 1) {
            const horizontalOverlap = Math.min(boxes[index].right, boxes[other].right) - Math.max(boxes[index].left, boxes[other].left);
            const verticalOverlap = Math.min(boxes[index].bottom, boxes[other].bottom) - Math.max(boxes[index].top, boxes[other].top);
            expect(horizontalOverlap <= 0 || verticalOverlap <= 0).toBeTruthy();
        }
    }
}

test('peer mobile actions meet the touch target minimum', async ({ page }) => {
    await mountContractPage(page, {
        width: 390,
        height: 844,
        stylesheetPaths: [
            'app/static/css/core/tokens.css',
            'app/static/css/peers.css',
        ],
        body: peerMarkup,
    });

    await expectTargetsToRespectMinimum(page, '.peer-card-action-btn');
});

test('node mobile actions meet the touch target minimum', async ({ page }) => {
    await mountContractPage(page, {
        width: 390,
        height: 844,
        stylesheetPaths: [
            'app/static/css/core/tokens.css',
            'app/static/css/pages/nodes.css',
        ],
        body: nodeMarkup,
    });

    await expectTargetsToRespectMinimum(page, '.node-action-btn');
});