//
// tools/ui-lint/tests/entity-layout/mobile-entities.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import { mountContractPage } from '../support/contract-fixtures.mjs';

const peerMarkup = `
<section class="peers-list-toolbar"></section>
<div class="peers-table-wrapper" id="peers-table-wrapper">
    <table class="peers-table"><tbody><tr><td>table shell</td></tr></tbody></table>
</div>
<div class="peer-card-list" id="peer-card-list">
    <article class="peer-card" data-peer-id="42">
        <div class="peer-card-header">
            <div class="peer-card-identity">
                <div class="peer-card-title">peer-with-a-very-long-identity-that-still-needs-to-wrap-cleanly</div>
                <div class="peer-card-subline">
                    <span>10.0.0.42</span>
                    <span class="peer-card-last-seen">Last seen 2 minutes ago</span>
                </div>
            </div>
            <div class="peer-card-status">
                <span class="badge bg-success peer-card-online-badge" role="status">Online</span>
                <span class="badge bg-success peer-card-enabled-badge" role="status">Enabled</span>
            </div>
        </div>
        <div class="peer-card-meta">
            <div class="peer-card-routing">Allowed IPs: 10.0.0.42/32, fd00::42/128</div>
            <div class="peer-card-addresses">
                <code>10.0.0.42/32</code>
                <code>fd00:abcd:1234:5678:9abc:def0:1234:5678/128</code>
            </div>
        </div>
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
            <tr data-node-id="7">
                <td data-label="Name">node-7</td>
                <td data-label="Status"><span class="badge node-status-badge bg-success">Online</span></td>
                <td data-label="FQDN">
                    <div class="node-fqdn-stack">
                        <div class="node-fqdn-main">
                            <span class="node-country-flag"></span>
                            <code>node-7.super-long-hostname-that-must-wrap-cleanly.example.internal</code>
                        </div>
                        <div class="node-fqdn-meta">
                            <span class="node-meta-city">Berlin</span>
                            <span class="node-meta-separator">·</span>
                            <span class="node-meta-provider">Very Long Provider Name That Still Fits</span>
                        </div>
                    </div>
                    <div class="node-mobile-summary">
                        <span class="node-mobile-summary-version">v1.2.3</span>
                        <span class="node-mobile-summary-port">51820</span>
                    </div>
                </td>
                <td data-label="Port">51820</td>
                <td data-label="Version">v1.2.3</td>
                <td data-label="Peers">19</td>
                <td data-label="Last Seen">2 minutes ago</td>
                <td data-label="Speedtest">125 Mbps</td>
                <td data-label="Actions" class="node-actions-cell">
                    <div class="d-flex">
                        <button type="button" class="btn btn-sm btn-outline-secondary node-action-btn" aria-label="Edit node">
                            <span class="material-icons" aria-hidden="true">E</span>
                        </button>
                        <button type="button" class="btn btn-sm btn-outline-secondary node-action-btn" aria-label="Copy config">
                            <span class="material-icons" aria-hidden="true">C</span>
                        </button>
                        <button type="button" class="btn btn-sm btn-outline-secondary node-action-btn node-action-secondary" aria-label="Delete node">
                            <span class="material-icons" aria-hidden="true">X</span>
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

test('mobile entity layouts keep peers and nodes in the card contract', async ({ page }) => {
    await mountContractPage(page, {
        width: 390,
        height: 844,
        stylesheetPaths: [
            'app/static/css/core/tokens.css',
            'app/static/css/peers.css',
            'app/static/css/pages/nodes.css',
        ],
        body: `${peerMarkup}${nodeMarkup}`,
    });

    await expect(page.locator('#peers-table-wrapper')).toBeHidden();
    await expect(page.locator('#peer-card-list')).toBeVisible();
    await expect(page.locator('.peer-card-status')).toBeVisible();
    await expect(page.locator('.peer-card-subline')).toBeVisible();
    await expect(page.locator('.node-mobile-summary')).toBeVisible();
    await expect(page.locator('.nodes-table td[data-label="Port"]')).toBeHidden();
    await expect(page.locator('.nodes-table td[data-label="Version"]')).toBeHidden();
    await expect(page.locator('.node-action-secondary')).toBeHidden();

    const nodeSummaryDisplay = await page.locator('.node-mobile-summary').evaluate((el) => getComputedStyle(el).display);
    expect(nodeSummaryDisplay).toBe('flex');

    const peerTableDisplay = await page.locator('#peers-table-wrapper').evaluate((el) => getComputedStyle(el).display);
    expect(peerTableDisplay).toBe('none');
});