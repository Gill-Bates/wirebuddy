//
// tools/ui-lint/lib/fonts/icon-diagnostics.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { normalizeFontFamilyName, splitFontFamilyList } from './fout-detection.mjs';

export const MAX_ICON_CHECKS = 50;
export const MIN_VISIBLE_GLYPH_WIDTH = 8;
export const ICON_SELECTOR = '.material-icons, .material-icons-outlined, [class*="material-symbols"]';

const MATERIAL_ICON_FONT_FAMILIES = new Set([
    'material icons',
    'material icons outlined',
    'material symbols outlined',
    'material symbols rounded',
    'material symbols sharp',
]);

function isMaterialIconFamily(fontFamily) {
    return MATERIAL_ICON_FONT_FAMILIES.has(normalizeFontFamilyName(fontFamily));
}

function createGlyphSampler(document) {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');

    return (fontFamily, text = 'Q') => {
        if (!context) return 0;

        context.font = `24px ${fontFamily}`;
        return context.measureText(text).width;
    };
}

function getLoadedFontFamilies(loadedFonts = []) {
    return new Set(
        loadedFonts
            .map((font) => normalizeFontFamilyName(font?.family))
            .filter(Boolean)
    );
}

export function analyzeIconFontIssues({ iconSamples = [], loadedFonts = [] } = {}) {
    const loadedFontFamilies = getLoadedFontFamilies(loadedFonts);
    const result = [];
    const seen = new Set();

    for (const sample of iconSamples) {
        const fontFamily = String(sample?.fontFamily || '');
        const fontFamilies = splitFontFamilyList(fontFamily);
        const fontLoaded = fontFamilies.some((family) => loadedFontFamilies.has(family) || isMaterialIconFamily(family));
        const width = Math.round(Number(sample?.width || 0));
        const height = Math.round(Number(sample?.height || 0));
        const glyphWidth = Math.round(Number(sample?.glyphWidth || 0) * 10) / 10;
        const text = String(sample?.text || '').trim();

        if ((width === 0 || height === 0) || (text.length > 0 && glyphWidth < MIN_VISIBLE_GLYPH_WIDTH && !fontLoaded)) {
            const fingerprint = `${fontFamily}|${text.slice(0, 30)}|${width}|${height}`;
            if (seen.has(fingerprint)) {
                continue;
            }

            seen.add(fingerprint);
            result.push({
                text: text.slice(0, 30) || '<empty>',
                width,
                height,
                fontFamily,
                glyphWidth,
                severity: width === 0 || height === 0 ? 'high' : 'medium',
            });
        }
    }

    return result;
}

export function collectIconFontSamples(document, { maxIcons = MAX_ICON_CHECKS } = {}) {
    if (!document || typeof document.querySelectorAll !== 'function' || typeof document.createElement !== 'function') {
        return [];
    }

    const view = document.defaultView;
    if (!view || typeof view.getComputedStyle !== 'function') {
        return [];
    }

    const sampleWidth = createGlyphSampler(document);
    const icons = Array.from(document.querySelectorAll(ICON_SELECTOR)).slice(0, maxIcons);
    const samples = [];

    for (const icon of icons) {
        const style = view.getComputedStyle(icon);
        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
            continue;
        }

        const rect = icon.getBoundingClientRect();
        const text = String(icon.textContent || '').trim();
        const fontFamily = String(style.fontFamily || '');
        const glyphWidth = fontFamily ? sampleWidth(fontFamily, text || 'Q') : 0;

        samples.push({
            text,
            width: rect.width,
            height: rect.height,
            fontFamily,
            glyphWidth,
        });
    }

    return samples;
}

export function detectIconFontIssues(document, loadedFonts = []) {
    return analyzeIconFontIssues({
        iconSamples: collectIconFontSamples(document),
        loadedFonts,
    });
}
