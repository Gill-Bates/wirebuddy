//
// tools/ui-lint/lib/dom-runtime/rendering/colors.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

function parseRgb(colorValue) {
    const match = /rgba?\(([^)]+)\)/.exec(colorValue || '');
    if (!match) return null;
    const parts = match[1].split(',').map((part) => Number.parseFloat(part.trim()) || 0);
    return {
        r: parts[0] || 0,
        g: parts[1] || 0,
        b: parts[2] || 0,
        a: parts.length > 3 ? parts[3] : 1,
    };
}

function channelToLinear(channel) {
    const normalized = channel / 255;
    return normalized <= 0.03928 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
}

function luminance(rgb) {
    return 0.2126 * channelToLinear(rgb.r) + 0.7152 * channelToLinear(rgb.g) + 0.0722 * channelToLinear(rgb.b);
}

export function buildColorSnapshot(style) {
    const rgb = parseRgb(style.color);
    const backgroundRgb = parseRgb(style.backgroundColor);
    const light = rgb ? luminance(rgb) : 0;
    const dark = backgroundRgb ? luminance(backgroundRgb) : 0;
    const contrast = light > dark ? (light + 0.05) / (dark + 0.05) : (dark + 0.05) / (light + 0.05);

    return {
        colors: {
            rgb,
            rgba: rgb,
            luminance: rgb ? luminance(rgb) : null,
            contrast,
        },
    };
}
