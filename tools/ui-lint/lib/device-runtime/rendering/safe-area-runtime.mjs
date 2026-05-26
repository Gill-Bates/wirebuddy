//
// tools/ui-lint/lib/device-runtime/rendering/safe-area-runtime.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildSafeAreaRuntime(descriptor) {
    const supportsSafeArea = Boolean(descriptor.capabilities?.safeAreaInsets);
    const chromeInsets = descriptor.browserChromeInsets || { top: 0, right: 0, bottom: 0, left: 0 };

    return {
        supported: supportsSafeArea,
        env: supportsSafeArea ? {
            'safe-area-inset-top': chromeInsets.top,
            'safe-area-inset-right': chromeInsets.right,
            'safe-area-inset-bottom': chromeInsets.bottom,
            'safe-area-inset-left': chromeInsets.left,
        } : {
            'safe-area-inset-top': 0,
            'safe-area-inset-right': 0,
            'safe-area-inset-bottom': 0,
            'safe-area-inset-left': 0,
        },
    };
}