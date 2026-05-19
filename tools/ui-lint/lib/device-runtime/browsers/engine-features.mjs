//
// tools/ui-lint/lib/device-runtime/browsers/engine-features.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const BROWSER_PROFILES = Object.freeze({
    chromium: Object.freeze({
        name: 'chromium',
        supports: Object.freeze({ inert: true, backdropFilter: true, dynamicViewportUnits: true, scrollTimeline: true, webkitTouchCallout: false }),
        fontSmoothing: 'subpixel-antialiased',
        overlayScrollbars: false,
        compositing: 'gpu',
    }),
    webkit: Object.freeze({
        name: 'webkit',
        supports: Object.freeze({ inert: true, backdropFilter: true, dynamicViewportUnits: true, scrollTimeline: false, webkitTouchCallout: true }),
        fontSmoothing: 'subpixel-antialiased',
        overlayScrollbars: true,
        compositing: 'gpu',
    }),
    firefox: Object.freeze({
        name: 'firefox',
        supports: Object.freeze({ inert: true, backdropFilter: true, dynamicViewportUnits: true, scrollTimeline: false, webkitTouchCallout: false }),
        fontSmoothing: 'grayscale',
        overlayScrollbars: false,
        compositing: 'gpu',
    }),
});

export function getBrowserProfile(browserName) {
    return BROWSER_PROFILES[browserName] || BROWSER_PROFILES.chromium;
}