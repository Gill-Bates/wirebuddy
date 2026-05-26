//
// tools/ui-lint/lib/fonts/fout-detection.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const MAX_TEXT_ELEMENTS = 100;
export const GENERIC_FONT_FAMILY_RE = /^(serif|sans-serif|monospace|cursive|fantasy|system-ui|ui-serif|ui-sans-serif|ui-monospace|emoji|math|fangsong)$/i;

export function normalizeFontFamilyName(value) {
    return String(value || '').replace(/["']/g, '').trim().toLowerCase();
}

export function splitFontFamilyList(fontFamily) {
    const families = [];
    let current = '';
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let escaped = false;

    for (const character of String(fontFamily || '')) {
        if (escaped) {
            current += character;
            escaped = false;
            continue;
        }

        if (character === '\\') {
            current += character;
            escaped = true;
            continue;
        }

        if (character === "'" && !inDoubleQuote) {
            inSingleQuote = !inSingleQuote;
            current += character;
            continue;
        }

        if (character === '"' && !inSingleQuote) {
            inDoubleQuote = !inDoubleQuote;
            current += character;
            continue;
        }

        if (character === ',' && !inSingleQuote && !inDoubleQuote) {
            const normalized = normalizeFontFamilyName(current);
            if (normalized) {
                families.push(normalized);
            }
            current = '';
            continue;
        }

        current += character;
    }

    const normalized = normalizeFontFamilyName(current);
    if (normalized) {
        families.push(normalized);
    }

    return families;
}

export function analyzeFoutRisk({ textSamples = [], loadedFonts = [], failedFonts = [] } = {}) {
    const loadedFontFamilies = new Set(
        loadedFonts
            .map((font) => normalizeFontFamilyName(font?.family))
            .filter(Boolean)
    );
    const failedFontFamilies = new Set(
        failedFonts
            .map((font) => normalizeFontFamilyName(font?.family))
            .filter(Boolean)
    );
    const candidates = [];

    for (const sample of textSamples) {
        const fontFamilies = splitFontFamilyList(sample?.fontFamily);
        if (fontFamilies.length < 2) {
            continue;
        }

        const fallbackFamily = fontFamilies.at(-1) || '';
        if (!GENERIC_FONT_FAMILY_RE.test(fallbackFamily)) {
            continue;
        }

        const primaryFont = fontFamilies[0] || '';
        if (!primaryFont || GENERIC_FONT_FAMILY_RE.test(primaryFont)) {
            continue;
        }

        if (loadedFontFamilies.has(primaryFont) || failedFontFamilies.has(primaryFont)) {
            continue;
        }

        candidates.push({
            text: String(sample?.text || '').trim().slice(0, 60),
            primaryFont,
            fallbackFamily,
        });
    }

    return {
        detected: candidates.length > 0,
        candidates,
    };
}

export function collectFoutTextSamples(document, { maxElements = MAX_TEXT_ELEMENTS } = {}) {
    if (!document || typeof document.createTreeWalker !== 'function' || !document.body) {
        return [];
    }

    const view = document.defaultView;
    if (!view || typeof view.getComputedStyle !== 'function') {
        return [];
    }

    const samples = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT, {
        acceptNode(element) {
            if (!(element instanceof Element)) {
                return NodeFilter.FILTER_SKIP;
            }

            if (samples.length >= maxElements) {
                return NodeFilter.FILTER_REJECT;
            }

            const hasDirectText = Array.from(element.childNodes).some((node) =>
                node.nodeType === Node.TEXT_NODE && node.textContent?.trim()
            );
            if (!hasDirectText) {
                return NodeFilter.FILTER_SKIP;
            }

            const style = view.getComputedStyle(element);
            if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
                return NodeFilter.FILTER_SKIP;
            }

            return NodeFilter.FILTER_ACCEPT;
        },
    });

    while (samples.length < maxElements) {
        const nextNode = walker.nextNode();
        if (!nextNode) {
            break;
        }

        const style = view.getComputedStyle(nextNode);
        samples.push({
            text: String(nextNode.textContent || '').trim().slice(0, 60),
            fontFamily: String(style.fontFamily || ''),
        });
    }

    return samples;
}

export function detectFoutRisk(document, loadedFonts = []) {
    return analyzeFoutRisk({
        textSamples: collectFoutTextSamples(document),
        loadedFonts,
    }).detected;
}
