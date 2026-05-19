//
// tools/ui-lint/lib/fonts/font-loading.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export async function checkFontLoading(page) {
    return page.evaluate(async () => {
        const result = {
            fontsReady: false,
            loadedFonts: [],
            failedFonts: [],
            materialIconsLoaded: false,
            iconMissing: [],
            foutRisk: false,
        };

        try {
            await document.fonts.ready;
            result.fontsReady = true;
        } catch {
            result.fontsReady = false;
        }

        if (document.fonts && typeof document.fonts.forEach === 'function') {
            document.fonts.forEach((font) => {
                if (font.status === 'loaded') {
                    result.loadedFonts.push({ family: font.family, weight: font.weight, style: font.style });
                } else if (font.status === 'error') {
                    result.failedFonts.push({ family: font.family, weight: font.weight, style: font.style });
                }
            });
        }

        result.materialIconsLoaded = result.loadedFonts.some((font) =>
            font.family.toLowerCase().includes('material') || font.family.toLowerCase().includes('icons')
        );

        const sampleGlyphWidth = (fontFamily, text = 'Q') => {
            const canvas = document.createElement('canvas');
            const context = canvas.getContext('2d');
            if (!context) return 0;

            context.font = `24px ${fontFamily}`;
            return context.measureText(text).width;
        };

        const icons = Array.from(document.querySelectorAll('.material-icons, .material-icons-outlined, [class*="material-symbols"]'));
        for (const icon of icons.slice(0, 50)) {
            const style = window.getComputedStyle(icon);
            const rect = icon.getBoundingClientRect();
            const text = (icon.textContent || '').trim();
            const fontFamily = style.fontFamily || '';
            const fontLoaded = result.loadedFonts.some((font) => font.family.toLowerCase().includes('material') || font.family.toLowerCase().includes('icons'));
            const glyphWidth = sampleGlyphWidth(fontFamily || 'sans-serif', text || 'Q');

            if ((rect.width === 0 || rect.height === 0) || (text.length > 0 && glyphWidth < 8 && !fontLoaded)) {
                result.iconMissing.push({
                    text: text.slice(0, 30) || '<empty>',
                    width: Math.round(rect.width),
                    height: Math.round(rect.height),
                    fontFamily,
                    glyphWidth: Math.round(glyphWidth * 10) / 10,
                });
            }
        }

        const textElements = Array.from(document.querySelectorAll('body *'))
            .filter((element) => element.textContent?.trim() && element.children.length === 0)
            .slice(0, 100);

        for (const element of textElements) {
            const fontFamily = window.getComputedStyle(element).fontFamily || '';
            const fallbackFamily = fontFamily.split(',').pop()?.trim() || '';
            if (/serif|sans-serif|monospace$/i.test(fallbackFamily)) {
                const primaryFont = fontFamily.split(',')[0]?.replace(/["']/g, '').trim();
                const isLoaded = result.loadedFonts.some((font) => font.family.replace(/["']/g, '').toLowerCase() === primaryFont.toLowerCase());
                if (!isLoaded && primaryFont && !/serif|sans-serif|monospace/i.test(primaryFont)) {
                    result.foutRisk = true;
                    break;
                }
            }
        }

        return result;
    });
}
