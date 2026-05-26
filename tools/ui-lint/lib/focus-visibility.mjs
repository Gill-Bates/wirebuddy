//
// tools/ui-lint/lib/focus-visibility.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

function parseRgb(color) {
    const match = String(color || '').match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/i);
    if (!match) return null;
    return {
        r: Number(match[1]),
        g: Number(match[2]),
        b: Number(match[3]),
    };
}

function relativeLuminance({ r, g, b }) {
    const channel = (value) => {
        const scaled = value / 255;
        return scaled <= 0.03928 ? scaled / 12.92 : ((scaled + 0.055) / 1.055) ** 2.4;
    };

    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

export function computeContrastRatio(foreground, background) {
    const fg = parseRgb(foreground);
    const bg = parseRgb(background);
    if (!fg || !bg) return null;

    const a = relativeLuminance(fg);
    const b = relativeLuminance(bg);
    const lighter = Math.max(a, b);
    const darker = Math.min(a, b);
    return (lighter + 0.05) / (darker + 0.05);
}

export function getFocusIndicatorGeometry(style = {}) {
    const outlineWidth = Number.parseFloat(style.outlineWidth || '0') || 0;
    const offset = Number.parseFloat(style.outlineOffset || '0') || 0;
    const boxShadow = String(style.boxShadow || '').trim();
    return {
        outlineWidth,
        outlineOffset: offset,
        hasBoxShadow: boxShadow !== '' && boxShadow !== 'none',
        boxShadow,
        area: Math.max(0, outlineWidth * 2 + Math.abs(offset) * 2),
    };
}

export function isFocusVisibleEnough({ before, after, tokens, elementRect, focusRect }) {
    const minContrast = tokens?.wcag?.contrastAALarge || 3;
    const geometry = getFocusIndicatorGeometry(after);
    const borderDelta = before.borderColor !== after.borderColor;
    const backgroundDelta = before.backgroundColor !== after.backgroundColor;
    const outlineVisible = after.outlineStyle !== 'none' && geometry.outlineWidth > 0;
    const boxShadowVisible = geometry.hasBoxShadow && after.boxShadow !== 'none';
    const styleChanged =
        before.outlineStyle !== after.outlineStyle ||
        Math.abs(before.outlineWidth - geometry.outlineWidth) > 0.1 ||
        before.outlineColor !== after.outlineColor ||
        before.boxShadow !== after.boxShadow ||
        borderDelta ||
        backgroundDelta;

    const width = focusRect?.width || elementRect?.width || 0;
    const height = focusRect?.height || elementRect?.height || 0;
    const perimeter = Math.max(0, 2 * (width + height));
    const focusRingArea = perimeter * Math.max(geometry.outlineWidth, 0) + Math.abs(geometry.outlineOffset) * perimeter;
    const focusColor = after.outlineColor || after.borderColor || after.boxShadowColor || after.color || '';
    const surroundingColor = after.backgroundColor || before.backgroundColor || '';
    const contrastRatio = computeContrastRatio(focusColor, surroundingColor);

    return {
        visible: Boolean(styleChanged && (outlineVisible || boxShadowVisible || borderDelta || backgroundDelta)),
        sufficientContrast: contrastRatio == null ? null : contrastRatio >= minContrast,
        contrastRatio,
        focusRingArea,
        geometry,
    };
}