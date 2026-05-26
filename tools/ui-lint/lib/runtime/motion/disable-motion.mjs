//
// tools/ui-lint/lib/runtime/motion/disable-motion.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { createHash } from 'node:crypto';

const MOTION_RESET_ROUTE_PREFIX = '/__ui_lint__/motion-reset';
const MOTION_ROUTE_STATE = Symbol.for('uiLint.motionResetRoutes');
const MOTION_SCOPE_ATTRIBUTE = 'data-ui-lint-motion';

function buildMotionResetRoutePath(cssText) {
    const hash = createHash('sha256').update(cssText).digest('hex').slice(0, 16);
    return `${MOTION_RESET_ROUTE_PREFIX}-${hash}.css`;
}

async function installMotionResetStylesheet(page, cssText, viewName, label) {
    const routePath = buildMotionResetRoutePath(cssText);
    const state = page[MOTION_ROUTE_STATE] || (page[MOTION_ROUTE_STATE] = { routes: new Set() });

    if (!state.routes.has(routePath)) {
        await page.route(`**${routePath}`, async (route) => {
            await route.fulfill({
                contentType: 'text/css; charset=utf-8',
                body: cssText,
            });
        }).catch((err) => console.warn(`[${viewName}] Failed to register ${label} stylesheet route: ${err.message}`));
        state.routes.add(routePath);
    }

    await page.evaluate((attributeName) => {
        document.documentElement.setAttribute(attributeName, 'true');
    }, MOTION_SCOPE_ATTRIBUTE).catch((err) => console.warn(`[${viewName}] Failed to set ${label} scope attribute: ${err.message}`));

    await page.addStyleTag({ url: routePath })
        .catch((err) => console.warn(`[${viewName}] Failed to inject ${label} stylesheet: ${err.message}`));
}

export async function disableMotion(page, motionResetCss, viewName = 'unknown') {
    await installMotionResetStylesheet(page, motionResetCss, viewName, 'motion reset');
}

export async function forceReducedMotion(page, viewName = 'unknown') {
    await installMotionResetStylesheet(page, `
            *,
            *::before,
            *::after {
                animation-duration: 0.01ms !important;
                animation-delay: 0ms !important;
                transition-duration: 0.01ms !important;
                scroll-behavior: auto !important;
            }
        `, viewName, 'reduced motion');
}
