//
// tools/ui-lint/tests/overflow/mobile-overflow.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import overflowRule from '../../rules/layout/overflow.mjs';
import { mountContractPage } from '../support/contract-fixtures.mjs';

const peerMarkup = `
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

const dashboardMarkup = `
<section class="dashboard-page">
    <div class="dashboard-header">
        <div class="map-kpis">
            <span class="map-kpi"><span class="material-icons">A</span> Active</span>
            <span class="map-kpi"><span class="material-icons">B</span> Busy</span>
        </div>
    </div>
    <div class="dashboard-main-grid">
        <div class="dashboard-map-col card">
            <div class="card-body">
                <div id="peer-map"></div>
            </div>
        </div>
        <div class="dashboard-speedtest-col card">
            <div class="card-body">
                <div class="speedtest-chart-wrap"></div>
            </div>
        </div>
        <div class="dashboard-recent-peers-col card">
            <div class="card-body">
                <div class="recent-peers-card overflow-auto" style="max-height: 180px;">
                    <div style="height: 420px;"></div>
                </div>
            </div>
        </div>
    </div>
</section>
`;

test('mobile peers cards stay inside the viewport', async ({ page }) => {
    await mountContractPage(page, {
        width: 390,
        height: 844,
        stylesheetPaths: [
            'app/static/css/core/tokens.css',
            'app/static/css/peers.css',
        ],
        body: peerMarkup,
    });

    const findings = await overflowRule.run({ page });
    expect(findings).toEqual([]);

    const metrics = await page.evaluate(() => ({
        scrollWidth: document.documentElement.scrollWidth,
        innerWidth: window.innerWidth,
    }));

    expect(metrics.scrollWidth).toBeLessThanOrEqual(metrics.innerWidth);
});

test('mobile nodes keep the entity row within the viewport', async ({ page }) => {
    await mountContractPage(page, {
        width: 390,
        height: 844,
        stylesheetPaths: [
            'app/static/css/core/tokens.css',
            'app/static/css/pages/nodes.css',
        ],
        body: nodeMarkup,
    });

    const findings = await overflowRule.run({ page });
    expect(findings).toEqual([]);

    const metrics = await page.evaluate(() => ({
        scrollWidth: document.documentElement.scrollWidth,
        innerWidth: window.innerWidth,
    }));

    expect(metrics.scrollWidth).toBeLessThanOrEqual(metrics.innerWidth);
});

test('mobile dashboard layout does not create horizontal overflow', async ({ page }) => {
    await mountContractPage(page, {
        width: 390,
        height: 844,
        stylesheetPaths: [
            'app/static/css/core/tokens.css',
            'app/static/css/dashboard.css',
        ],
        body: dashboardMarkup,
    });

    const findings = await overflowRule.run({ page });
    expect(findings).toEqual([]);

    const metrics = await page.evaluate(() => ({
        scrollWidth: document.documentElement.scrollWidth,
        innerWidth: window.innerWidth,
    }));

    expect(metrics.scrollWidth).toBeLessThanOrEqual(metrics.innerWidth);
});

test('local scroll containers are treated as acceptable overflow', async ({ page }) => {
    await mountContractPage(page, {
        width: 390,
        height: 844,
        stylesheetPaths: [
            'app/static/css/core/tokens.css',
        ],
        body: `
<section class="card" data-ui-component="code-sample">
    <div class="snippet-scroll" style="max-width: 100%; overflow-x: auto; overflow-y: hidden;">
        <pre style="width: 920px; margin: 0;">${'wide_code_line '.repeat(40)}</pre>
    </div>
</section>
`,
    });

    const findings = await overflowRule.run({ page, browser: 'chromium', scope: 'settings' });

    expect(findings).toEqual([]);
    const metrics = await page.evaluate(() => ({
        scrollWidth: document.documentElement.scrollWidth,
        bodyScrollWidth: document.body.scrollWidth,
        innerWidth: window.innerWidth,
    }));

    expect(metrics.scrollWidth).toBeLessThanOrEqual(metrics.innerWidth);
    expect(metrics.bodyScrollWidth).toBeLessThanOrEqual(metrics.innerWidth);
});

test('flex nowrap overflow reports a root cause and page scroll width', async ({ page }) => {
    await mountContractPage(page, {
        width: 390,
        height: 844,
        stylesheetPaths: [
            'app/static/css/core/tokens.css',
        ],
        body: `
<section class="peer-card" data-ui-component="peer-actions" data-ui-importance="primary">
    <div class="peer-actions-shell" style="display: flex; flex-wrap: nowrap; gap: 12px; min-width: 0;">
        <button type="button" class="btn btn-sm btn-outline-secondary" aria-label="Primary action">Primary action</button>
        <div class="peer-actions-label" style="white-space: nowrap; min-width: 360px;">peer-actions-have-a-very-long-unbroken-label</div>
    </div>
</section>
`,
    });

    const findings = await overflowRule.run({ page, browser: 'webkit', scope: 'peers' });

    expect(findings).toHaveLength(1);
    expect(findings[0].kind).toBe('clipped-action');
    expect(findings[0].details.component).toBe('peer-actions');
    expect(findings[0].details.browser).toBe('webkit');
    expect(findings[0].details.pageScrollWidth).toBeGreaterThan(findings[0].details.viewportWidth);
    expect(findings[0].details.rootCause?.reason).toBe('flex-nowrap');
    expect(findings[0].details.rootCause?.selector).toBe('.peer-actions-shell');
});