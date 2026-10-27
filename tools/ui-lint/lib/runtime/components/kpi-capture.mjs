//
// tools/ui-lint/lib/runtime/components/kpi-capture.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { registerCaptureComponent } from './component-registry.mjs';

registerCaptureComponent({ selector: '.wb-kpi-card, .dashboard-kpi-card', type: 'kpi' });

export async function captureKpiCards(page, viewName, screenshotDir, { selector = '.wb-kpi-card, .dashboard-kpi-card' } = {}) {
    const cards = await page.$$(selector);
    const paths = [];

    for (const card of cards) {
        if (!(await card.isVisible())) continue;
        const pathOut = `${screenshotDir}/${viewName.replace(/[^a-z0-9-_]+/gi, '_').toLowerCase()}-kpi-${paths.length}.png`;
        await card.screenshot({ path: pathOut });
        paths.push(pathOut);
    }

    return paths;
}
