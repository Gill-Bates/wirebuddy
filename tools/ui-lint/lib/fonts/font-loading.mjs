//
// tools/ui-lint/lib/fonts/font-loading.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { analyzeFoutRisk, normalizeFontFamilyName } from './fout-detection.mjs';
import { analyzeIconFontIssues, ICON_SELECTOR, MAX_ICON_CHECKS } from './icon-diagnostics.mjs';

export async function checkFontLoading(page) {
    const result = await page.evaluate(async ({ iconSelector, maxIconChecks }) => {
        const FONT_READY_TIMEOUT_MS = 5000;
        const MAX_TEXT_CHECKS = 100;
        const MATERIAL_FONT_FAMILY_RE = /^(material icons|material icons outlined|material symbols outlined|material symbols rounded|material symbols sharp)$/i;

        const diagnostics = {
            fontsReady: false,
            loadedFonts: [],
            failedFonts: [],
            materialIconsLoaded: false,
            iconMissing: [],
            foutRisk: false,
            unsupported: false,
            fontReadyTimedOut: false,
            foutCandidates: [],
            textSamples: [],
            iconSamples: [],
        };

        const fontFaceSet = document.fonts;
        if (!fontFaceSet || typeof fontFaceSet.ready?.then !== 'function') {
            diagnostics.unsupported = true;
            return diagnostics;
        }

        const normalizeFontString = (value) => String(value || '').replace(/["']/g, '').trim();
        const isMaterialIconFamily = (family) => MATERIAL_FONT_FAMILY_RE.test(normalizeFontString(family).toLowerCase());

        const loadedFontNames = new Set();
        const failedFontNames = new Set();

        try {
            await Promise.race([
                fontFaceSet.ready.then(() => 'ready'),
                new Promise((resolve) => window.setTimeout(() => resolve('timeout'), FONT_READY_TIMEOUT_MS)),
            ]).then((state) => {
                diagnostics.fontReadyTimedOut = state === 'timeout';
            });
            diagnostics.fontsReady = true;
        } catch {
            diagnostics.fontsReady = false;
        }

        const fontEntries = typeof fontFaceSet.values === 'function' ? Array.from(fontFaceSet.values()) : [];
        for (const font of fontEntries) {
            const family = normalizeFontString(font.family);
            const payload = {
                family,
                weight: String(font.weight || ''),
                style: String(font.style || ''),
            };

            if (font.status === 'loaded') {
                diagnostics.loadedFonts.push(payload);
                if (family) {
                    loadedFontNames.add(family.toLowerCase());
                }
            } else if (font.status === 'error') {
                diagnostics.failedFonts.push(payload);
                if (family) {
                    failedFontNames.add(family.toLowerCase());
                }
            }
        }

        diagnostics.materialIconsLoaded = diagnostics.loadedFonts.some((font) => isMaterialIconFamily(font.family));

        const sampleGlyphWidth = (() => {
            const canvas = document.createElement('canvas');
            const canvasContext = canvas.getContext('2d');

            return (fontFamily, text = 'Q') => {
                if (!canvasContext) return 0;

                canvasContext.font = `24px ${fontFamily}`;
                return canvasContext.measureText(text).width;
            };
        })();

        const icons = Array.from(document.querySelectorAll(iconSelector));
        for (const icon of icons.slice(0, maxIconChecks)) {
            const style = window.getComputedStyle(icon);
            if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
                continue;
            }

            const rect = icon.getBoundingClientRect();
            const text = (icon.textContent || '').trim();
            const fontFamily = String(style.fontFamily || '');
            const glyphWidth = fontFamily ? sampleGlyphWidth(fontFamily, text || 'Q') : 0;

            diagnostics.iconSamples.push({
                text,
                width: rect.width,
                height: rect.height,
                fontFamily,
                glyphWidth,
            });
        }

        const textElements = [];
        if (document.body && typeof document.createTreeWalker === 'function') {
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT, {
                acceptNode(element) {
                    if (!(element instanceof Element)) {
                        return NodeFilter.FILTER_SKIP;
                    }

                    if (textElements.length >= MAX_TEXT_CHECKS) {
                        return NodeFilter.FILTER_REJECT;
                    }

                    const hasDirectText = Array.from(element.childNodes).some((node) =>
                        node.nodeType === Node.TEXT_NODE && node.textContent?.trim()
                    );

                    return hasDirectText ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
                },
            });

            while (textElements.length < MAX_TEXT_CHECKS) {
                const nextNode = walker.nextNode();
                if (!nextNode) {
                    break;
                }
                textElements.push(nextNode);
            }
        }

        for (const element of textElements) {
            const style = window.getComputedStyle(element);
            if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
                continue;
            }

            diagnostics.textSamples.push({
                text: (element.textContent || '').trim().slice(0, 60),
                fontFamily: String(style.fontFamily || ''),
            });
        }

        return diagnostics;
    }, {
        iconSelector: ICON_SELECTOR,
        maxIconChecks: MAX_ICON_CHECKS,
    });

    const foutAnalysis = analyzeFoutRisk({
        textSamples: result.textSamples,
        loadedFonts: result.loadedFonts.map((font) => ({ ...font, family: normalizeFontFamilyName(font.family) })),
        failedFonts: result.failedFonts.map((font) => ({ ...font, family: normalizeFontFamilyName(font.family) })),
    });

    result.foutRisk = foutAnalysis.detected;
    result.foutCandidates = foutAnalysis.candidates;
    result.iconMissing = analyzeIconFontIssues({
        iconSamples: result.iconSamples,
        loadedFonts: result.loadedFonts.map((font) => ({ ...font, family: normalizeFontFamilyName(font.family) })),
    });
    delete result.textSamples;
    delete result.iconSamples;

    return result;
}
