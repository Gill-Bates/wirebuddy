//
// tools/ui-lint/lib/runtime/components/kpi-capture.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { registerCaptureComponent } from './component-registry.mjs';

registerCaptureComponent({ selector: '.wb-kpi-card', type: 'kpi' });

export async function captureKpiCards(page, viewName, screenshotDir, { selector = '.wb-kpi-card' } = {}) {
    const cards = await page.$$(selector);
    const paths = [];

    for (let i = 0; i < cards.length; i += 1) {
        const card = cards[i];
        const pathOut = `${screenshotDir}/${viewName.replace(/[^a-z0-9-_]+/gi, '_').toLowerCase()}-kpi-${i}.png`;
        await card.screenshot({ path: pathOut });
        paths.push(pathOut);
    }

    return paths;
}
