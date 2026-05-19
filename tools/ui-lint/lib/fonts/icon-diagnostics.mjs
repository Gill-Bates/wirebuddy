//
// tools/ui-lint/lib/fonts/icon-diagnostics.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

function sampleGlyphWidth(document, fontFamily, text = 'Q') {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    if (!context) return 0;

    context.font = `24px ${fontFamily}`;
    return context.measureText(text).width;
}

export function detectIconFontIssues(document, loadedFonts = []) {
    const result = [];
    const icons = Array.from(document.querySelectorAll('.material-icons, .material-icons-outlined, [class*="material-symbols"]'));

    for (const icon of icons.slice(0, 50)) {
        const style = window.getComputedStyle(icon);
        const rect = icon.getBoundingClientRect();
        const text = (icon.textContent || '').trim();
        const fontFamily = style.fontFamily || '';
        const fontLoaded = loadedFonts.some((font) => font.family.toLowerCase().includes('material') || font.family.toLowerCase().includes('icons'));
        const glyphWidth = sampleGlyphWidth(document, fontFamily || 'sans-serif', text || 'Q');

        if ((rect.width === 0 || rect.height === 0) || (text.length > 0 && glyphWidth < 8 && !fontLoaded)) {
            result.push({
                text: text.slice(0, 30) || '<empty>',
                width: Math.round(rect.width),
                height: Math.round(rect.height),
                fontFamily,
                glyphWidth: Math.round(glyphWidth * 10) / 10,
            });
        }
    }

    return result;
}
