//
// tools/ui-lint/lib/runtime/browser/navigation.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export async function waitForNavigationSettled(page, { timeout = 30000 } = {}) {
    await page.waitForLoadState('networkidle', { timeout })
        .catch(() => {});
}

export async function waitForVisualStability(page, {
    settleMs = 800,
    requireNetworkIdle = true,
    timeout = 30000,
} = {}) {
    if (requireNetworkIdle) {
        await waitForNavigationSettled(page, { timeout });
    }

    await page.waitForTimeout(settleMs);
}
