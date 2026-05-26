//
// tools/ui-lint/lib/runtime/screenshots/capture-stable.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { disableMotion } from '../motion/disable-motion.mjs';
import { waitForVisualStability } from '../browser/navigation.mjs';
import { sanitize } from './screenshot-normalizer.mjs';

export async function captureScreenshot(page, { path, fullPage = true, animations = 'disabled' } = {}) {
    await page.screenshot({ path, fullPage, animations });
    return { path, fullPage, animations, timestamp: Date.now() };
}

export async function prepareStableViewport(page, { motionResetCss, viewName = 'unknown', settleMs = 800 } = {}) {
    if (motionResetCss) {
        await disableMotion(page, motionResetCss, viewName);
    }
    await waitForVisualStability(page, { settleMs });
}

export async function captureStablePair(page, {
    motionResetCss,
    name,
    screenshotDir,
    screenshotSettleMs,
}) {
    await prepareStableViewport(page, {
        motionResetCss,
        viewName: name,
        settleMs: screenshotSettleMs,
    });

    const safeName = sanitize(name);
    const shotA = `${screenshotDir}/${safeName}-a.png`;
    const shotB = `${screenshotDir}/${safeName}-b.png`;

    await captureScreenshot(page, { path: shotA, fullPage: true, animations: 'disabled' });
    await waitForVisualStability(page, { settleMs: screenshotSettleMs, requireNetworkIdle: false });
    await captureScreenshot(page, { path: shotB, fullPage: true, animations: 'disabled' });

    return { shotA, shotB };
}
