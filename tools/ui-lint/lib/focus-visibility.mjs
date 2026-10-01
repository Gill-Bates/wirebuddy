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
    const hasBoxShadow = boxShadow !== '' && boxShadow !== 'none';
    // A box-shadow ring (Bootstrap's `0 0 0 .25rem`) carries its thickness in the
    // spread, so deriving the area from outlineWidth alone returned 0 and the
    // caller's `focusArea < minArea` gate rejected every shadow-only ring.
    const shadowSpread = hasBoxShadow ? parseShadowRingWidth(boxShadow) : 0;
    const ringWidth = Math.max(outlineWidth, shadowSpread);
    return {
        outlineWidth,
        outlineOffset: offset,
        hasBoxShadow,
        boxShadow,
        shadowSpread,
        ringWidth,
        area: Math.max(0, ringWidth * 2 + Math.abs(offset) * 2),
    };
}

function splitTopLevel(list) {
    const parts = [];
    let depth = 0;
    let start = 0;
    for (let i = 0; i < list.length; i += 1) {
        const ch = list[i];
        if (ch === '(') depth += 1;
        else if (ch === ')') depth = Math.max(0, depth - 1);
        else if (ch === ',' && depth === 0) {
            parts.push(list.slice(start, i));
            start = i + 1;
        }
    }
    parts.push(list.slice(start));
    return parts;
}

function parseShadowRingWidth(boxShadow) {
    // Only offset-free outer shadows form a ring; a drop shadow or inset shadow
    // would otherwise be scored as focus thickness. Take the widest spread.
    let widest = 0;
    for (const shadow of splitTopLevel(String(boxShadow))) {
        const tokens = shadow.replace(/\([^)]*\)/g, ' ').trim().split(/\s+/).filter(Boolean);
        if (tokens.includes('inset')) continue;
        const lengths = tokens.filter((token) => /^-?[\d.]+(px)?$/.test(token)).map(Number.parseFloat);
        if (lengths.length < 2 || lengths[0] !== 0 || lengths[1] !== 0) continue;
        widest = Math.max(widest, lengths[3] ?? 0);
    }
    return widest;
}

export function isFocusVisibleEnough({ before, after, tokens, elementRect, focusRect, minContrast: minContrastOverride }) {
    const minContrast = minContrastOverride ?? (tokens?.wcag?.contrastAALarge || 3);
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
    const focusRingArea = perimeter * Math.max(geometry.ringWidth, 0) + Math.abs(geometry.outlineOffset) * perimeter;
    // Score the colour of the ring that is actually painted. outlineColor stays
    // populated even when outlineStyle is 'none', so preferring it unconditionally
    // measured a box-shadow ring against the wrong colour.
    const focusColor = (outlineVisible ? after.outlineColor : '')
        || (boxShadowVisible ? after.boxShadowColor : '')
        || after.outlineColor
        || after.borderColor
        || after.boxShadowColor
        || after.color
        || '';
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