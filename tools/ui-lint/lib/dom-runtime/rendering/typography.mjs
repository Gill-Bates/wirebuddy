//
// tools/ui-lint/lib/dom-runtime/rendering/typography.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildTypographySnapshot(style) {
    return {
        lineHeight: style.lineHeight || 'normal',
        letterSpacing: style.letterSpacing || 'normal',
        fontSmoothing: style.webkitFontSmoothing || style.fontSmoothing || 'auto',
        textRendering: style.textRendering || 'auto',
    };
}
