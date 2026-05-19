//
// tools/ui-lint/lib/fonts/fout-detection.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function detectFoutRisk(document, loadedFonts = []) {
    const textElements = Array.from(document.querySelectorAll('body *'))
        .filter((element) => element.textContent?.trim() && element.children.length === 0)
        .slice(0, 100);

    for (const element of textElements) {
        const fontFamily = window.getComputedStyle(element).fontFamily || '';
        const fallbackFamily = fontFamily.split(',').pop()?.trim() || '';
        if (/serif|sans-serif|monospace$/i.test(fallbackFamily)) {
            const primaryFont = fontFamily.split(',')[0]?.replace(/["']/g, '').trim();
            const isLoaded = loadedFonts.some((font) => font.family.replace(/["']/g, '').toLowerCase() === primaryFont.toLowerCase());
            if (!isLoaded && primaryFont && !/serif|sans-serif|monospace/i.test(primaryFont)) {
                return true;
            }
        }
    }

    return false;
}
