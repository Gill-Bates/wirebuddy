//
// tools/ui-lint/lib/device-runtime/rendering/visual-viewport.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildVisualViewportRuntime(descriptor, viewportRuntime) {
    const dynamicViewport = Boolean(descriptor.capabilities?.dynamicViewport);
    return {
        layout: { ...viewportRuntime.layout },
        visual: { ...viewportRuntime.visual },
        dynamicViewport,
        supportsKeyboardResize: Boolean(descriptor.capabilities?.virtualKeyboard),
    };
}