//
// tools/ui-lint/lib/device-runtime/rendering/dpr-runtime.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildDprRuntime(descriptor) {
    const devicePixelRatio = descriptor.deviceScaleFactor || 1;
    return {
        devicePixelRatio,
        subpixelGrid: 1 / devicePixelRatio,
    };
}