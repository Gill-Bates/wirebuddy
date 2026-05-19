//
// tools/ui-lint/lib/runtime/motion/disable-motion.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export async function disableMotion(page, motionResetCss, viewName = 'unknown') {
    await page.addStyleTag({ content: motionResetCss })
        .catch((err) => console.warn(`[${viewName}] Failed to inject motion reset CSS: ${err.message}`));
}

export async function forceReducedMotion(page, viewName = 'unknown') {
    await page.addStyleTag({
        content: `
            *,
            *::before,
            *::after {
                animation-duration: 0.01ms !important;
                animation-delay: 0ms !important;
                transition-duration: 0.01ms !important;
                scroll-behavior: auto !important;
            }
        `,
    }).catch((err) => console.warn(`[${viewName}] Failed to force reduced motion: ${err.message}`));
}
