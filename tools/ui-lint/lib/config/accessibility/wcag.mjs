//
// tools/ui-lint/lib/config/accessibility/wcag.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { resolveOptionalToken } from '../tokens/resolver.mjs';

export const WCAG_CONTRAST = Object.freeze({
    NORMAL_AA: resolveOptionalToken('wcag.contrastAA', 4.5, { category: 'accessibility' }),
    LARGE_AA: resolveOptionalToken('wcag.contrastAALarge', 3.0, { category: 'accessibility' }),
    LARGE_TEXT_SIZE_PX: 24,
    LARGE_TEXT_SIZE_BOLD_PX: 18.66,
    BOLD_WEIGHT: 700,
});

export const WCAG_CONTRAST_POLICY = Object.freeze({
    normal: { minRatio: WCAG_CONTRAST.NORMAL_AA },
    large: { minRatio: WCAG_CONTRAST.LARGE_AA },
    largeTextSizePx: WCAG_CONTRAST.LARGE_TEXT_SIZE_PX,
    boldWeight: WCAG_CONTRAST.BOLD_WEIGHT,
});

export function isLargeText(fontSize, fontWeight) {
    return fontSize >= WCAG_CONTRAST.LARGE_TEXT_SIZE_PX || (
        fontSize >= WCAG_CONTRAST.LARGE_TEXT_SIZE_BOLD_PX && fontWeight >= WCAG_CONTRAST.BOLD_WEIGHT
    );
}

export function evaluateContrast({ fontSize, fontWeight, contrastRatio, browser = 'chromium' } = {}) {
    const largeText = isLargeText(Number(fontSize) || 0, Number(fontWeight) || 0);
    const threshold = largeText ? WCAG_CONTRAST.LARGE_AA : WCAG_CONTRAST.NORMAL_AA;
    const browserTolerance = browser === 'webkit' ? 0.05 : 0;
    const ratio = Number(contrastRatio);

    // The AA threshold is exact: W3C states 4.499 must not be rounded up to 4.5,
    // so the tolerance must not decide `passes`. It stays reported so a
    // borderline WebKit rounding difference is still diagnosable.
    const passes = ratio >= threshold;

    return {
        largeText,
        threshold,
        browserTolerance,
        passes,
        withinBrowserTolerance: !passes && browserTolerance > 0 && ratio + browserTolerance >= threshold,
    };
}