//
// tools/ui-lint/tests/runtime/dashboard-grid.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import { mountContractPage, readRepoFile } from '../support/contract-fixtures.mjs';

const markup = `
<button id="wb-dashboard-edit-toggle" type="button">Edit dashboard</button>
<button id="wb-dashboard-add-widget" class="d-none" type="button">Edit widgets</button>
<button id="wb-dashboard-reset-layout" class="d-none" type="button">Reset layout</button>
<button id="wb-dashboard-edit-done" class="d-none" type="button">Done</button>
<ul id="wb-add-widget-list"></ul>
<div class="grid-stack wb-dashboard-grid wb-dashboard-grid--loading" id="wb-dashboard-grid">
    <div class="grid-stack-item" gs-id="kpi-nodes" gs-x="0" gs-y="0" gs-w="3" gs-h="2" gs-min-w="2" data-widget-id="kpi-nodes">
        <div class="grid-stack-item-content">
            <div class="dashboard-widget-header d-none"><span class="dashboard-drag-handle">Drag</span></div>
            <div class="card dashboard-kpi-card h-100"><div class="card-body">Nodes</div></div>
        </div>
    </div>
    <div class="grid-stack-item" gs-id="kpi-connections" gs-x="3" gs-y="0" gs-w="3" gs-h="2" gs-min-w="2" data-widget-id="kpi-connections">
        <div class="grid-stack-item-content">
            <div class="dashboard-widget-header d-none"><span class="dashboard-drag-handle">Drag</span></div>
            <div class="card dashboard-kpi-card h-100"><div class="card-body">Connections</div></div>
        </div>
    </div>
</div>`;

async function mountDashboard(page, width, savedLayout = null) {
    await mountContractPage(page, {
        width,
        height: 800,
        stylesheetPaths: [
            'app/static/vendor/bootstrap.min.css',
            'app/static/vendor/gridstack.min.css',
            'app/static/css/dashboard.css',
            'app/static/css/pages/dashboard.css',
        ],
        body: markup,
    });
    await page.evaluate((layout) => {
        window.savedLayout = layout;
        window.layoutWrites = [];
        window.apiCall = async (method, url, body) => {
            if (url !== '/api/dashboard/layout') throw new Error(`Unexpected API path: ${url}`);
            if (method === 'GET') return { layout: window.savedLayout };
            if (method === 'PUT') {
                window.savedLayout = body;
                window.layoutWrites.push(body);
                return { layout: body };
            }
            throw new Error(`Unexpected method: ${method}`);
        };
        window.wbToast = () => {};
    }, savedLayout);
    for (const file of [
        'app/static/vendor/gridstack-all.js',
        'app/static/js/dashboard_widgets.js',
        'app/static/js/dashboard_grid.js',
    ]) {
        await page.addScriptTag({ content: readRepoFile(file) });
    }
    await page.evaluate(() => document.dispatchEvent(new Event('wb:dashboard-data-ready')));
    await expect(page.locator('#wb-dashboard-grid')).not.toHaveClass(/wb-dashboard-grid--loading/);
}

test('hero KPI resizes to half width and survives saving while mobile stays stacked', async ({ page }) => {
    await mountDashboard(page, 1200);
    const grid = page.locator('#wb-dashboard-grid');
    const nodes = page.locator('[data-widget-id="kpi-nodes"]');
    const grip = nodes.locator('.ui-resizable-se');

    await expect(grip).toBeHidden();
    await page.getByRole('button', { name: 'Edit dashboard' }).click();
    await expect(grip).toBeVisible();
    const guides = await grid.evaluate((el) => {
        const style = getComputedStyle(el);
        return { image: style.backgroundImage, size: style.backgroundSize };
    });
    expect(guides.image).toContain('linear-gradient');
    expect(guides.size).toContain('72px');

    const handle = await grip.boundingBox();
    const gridBox = await grid.boundingBox();
    expect(handle.width).toBeGreaterThanOrEqual(24);
    await page.mouse.move(handle.x + handle.width / 2, handle.y + handle.height / 2);
    await page.mouse.down();
    await page.mouse.move(handle.x + handle.width / 2 + gridBox.width / 4, handle.y + handle.height / 2, { steps: 12 });
    await page.mouse.up();
    await expect.poll(() => nodes.evaluate((el) => el.gridstackNode?.w)).toBe(6);

    await page.getByRole('button', { name: 'Done' }).click();
    await expect.poll(() => page.evaluate(() => window.layoutWrites.length)).toBe(1);
    const stored = await page.evaluate(() => window.layoutWrites[0]);
    expect(stored.widgets.find((widget) => widget.id === 'kpi-nodes').w).toBe(6);
    await expect(grip).toBeHidden();

    const reloaded = await page.context().newPage();
    try {
        await mountDashboard(reloaded, 1200, stored);
        const dimensions = await reloaded.evaluate(() => {
            const root = document.querySelector('#wb-dashboard-grid').getBoundingClientRect();
            const tile = document.querySelector('[data-widget-id="kpi-nodes"]').getBoundingClientRect();
            return { ratio: tile.width / root.width };
        });
        expect(dimensions.ratio).toBeCloseTo(0.5, 1);

        await reloaded.getByRole('button', { name: 'Edit dashboard' }).click();
        for (const [width, columns] of [[790, 4], [390, 2]]) {
            await reloaded.setViewportSize({ width, height: 800 });
            await expect(reloaded.locator('#wb-dashboard-grid')).not.toHaveClass(/wb-dashboard-editing/);
            await expect(reloaded.getByRole('button', { name: 'Edit dashboard' })).toBeHidden();
            const mobile = await reloaded.evaluate(() => ({
                columns: getComputedStyle(document.querySelector('#wb-dashboard-grid')).gridTemplateColumns,
                overflow: document.documentElement.scrollWidth > window.innerWidth,
            }));
            expect(mobile.columns.split(' ')).toHaveLength(columns);
            expect(mobile.overflow).toBe(false);
        }
    } finally {
        await reloaded.close();
    }
});
