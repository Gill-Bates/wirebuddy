//
// tools/ui-lint/lib/runtime/motion/transition-stability.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { detectActiveAnimations } from './animation-detector.mjs';

export async function verifyNoLayoutAnimation(page, { settleMs = 250 } = {}) {
    const before = await detectActiveAnimations(page);
    await page.waitForTimeout(settleMs);
    const after = await detectActiveAnimations(page);

    return {
        before,
        after,
        stable: after.active === 0 && after.count === before.count,
    };
}
