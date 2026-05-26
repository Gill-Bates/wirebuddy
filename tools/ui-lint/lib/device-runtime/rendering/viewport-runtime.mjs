//
// tools/ui-lint/lib/device-runtime/rendering/viewport-runtime.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildViewportRuntime(descriptor) {
    const viewport = descriptor.viewport || { width: 1440, height: 1100 };
    const browserChromeInsets = descriptor.browserChromeInsets || { top: 0, right: 0, bottom: 0, left: 0 };

    return {
        layout: { ...viewport },
        visual: {
            width: Math.max(0, viewport.width - browserChromeInsets.left - browserChromeInsets.right),
            height: Math.max(0, viewport.height - browserChromeInsets.top - browserChromeInsets.bottom),
        },
        browserChromeInsets,
    };
}