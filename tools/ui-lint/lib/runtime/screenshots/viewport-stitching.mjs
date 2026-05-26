//
// tools/ui-lint/lib/runtime/screenshots/viewport-stitching.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function stitchViewportFrames(frames = []) {
    return {
        frameCount: frames.length,
        frames,
    };
}
