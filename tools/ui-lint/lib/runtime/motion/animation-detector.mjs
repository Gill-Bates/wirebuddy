//
// tools/ui-lint/lib/runtime/motion/animation-detector.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export async function detectActiveAnimations(page) {
    return page.evaluate(() => {
        const animations = typeof document.getAnimations === 'function' ? document.getAnimations() : [];
        return {
            count: animations.length,
            active: animations.filter((animation) => animation.playState === 'running').length,
        };
    });
}
