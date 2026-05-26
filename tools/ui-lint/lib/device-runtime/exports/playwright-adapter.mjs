//
// tools/ui-lint/lib/device-runtime/exports/playwright-adapter.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function toPlaywrightOptions(runtime) {
    const snapshot = runtime.snapshot();
    return {
        viewport: snapshot.viewport.layout,
        deviceScaleFactor: snapshot.dpr.devicePixelRatio,
        isMobile: Boolean(snapshot.descriptor.isMobile),
        hasTouch: Boolean(snapshot.descriptor.hasTouch),
        userAgent: snapshot.descriptor.userAgent,
    };
}