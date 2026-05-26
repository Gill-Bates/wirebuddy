//
// tools/ui-lint/tests/config/config-platform.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import {
    buildEvaluationPayload,
    buildMotionResetCSS,
    buildSerializableConstants,
    evaluateContrast,
    getScreenshotSettleTime,
    resolveToken,
    UI_EVAL_CONSTANTS,
    THEMES,
    THEME_REGISTRY,
    validateTokenPath,
} from '../../lib/config/index.mjs';

test('token resolver returns metadata and validates paths', () => {
    const resolution = resolveToken('card.radius', { fallback: 12, category: 'components' });

    expect(validateTokenPath('card.radius')).toBe('card.radius');
    expect(resolution.sourceToken).toBe('card.radius');
    expect(resolution.category).toBe('components');
    expect(typeof resolution.value).toBe('number');
    expect(resolution.fallbackUsed).toBe(false);
});

test('wcag evaluation adapts to text size', () => {
    expect(evaluateContrast({ fontSize: 16, fontWeight: 400, contrastRatio: 4.6 }).passes).toBe(true);
    expect(evaluateContrast({ fontSize: 18.66, fontWeight: 700, contrastRatio: 3.1 }).largeText).toBe(true);
});

test('runtime timing and payload builders stay category-aware', () => {
    const desktopSettle = getScreenshotSettleTime({ browser: 'chromium', deviceClass: 'desktop', animationCount: 0, cpuProfile: 'default' });
    const mobileSettle = getScreenshotSettleTime({ browser: 'webkit', deviceClass: 'mobile', animationCount: 12, cpuProfile: 'ci' });

    expect(mobileSettle).toBeGreaterThan(desktopSettle);

    const payload = buildEvaluationPayload({ categories: ['layout', 'accessibility', 'motion'] });
    expect(payload).toHaveProperty('layout');
    expect(payload).toHaveProperty('accessibility');
    expect(payload).toHaveProperty('motion');
    expect(payload).not.toHaveProperty('runtime');

    const serializable = buildSerializableConstants({ categories: ['legacy'] });
    expect(serializable).toHaveProperty('CLICK_TARGET_MIN_SIZE_PX');
    expect(serializable).toHaveProperty('WCAG_NORMAL_AA');
    expect(serializable).toHaveProperty('ABOUT_APPLICATION_DETAILS_REQUIRED_ROWS');
    expect(UI_EVAL_CONSTANTS).toHaveProperty('WCAG_NORMAL_AA');
});

test('motion profiles and theme registry remain extensible', () => {
    const css = buildMotionResetCSS({ disableLeaflet: true, disableCharts: true, disablePulseMarkers: true });

    expect(css).toContain('.leaflet-pane');
    expect(css).toContain('.pulse-marker');
    expect(THEMES).toContain('highContrast');
    expect(THEME_REGISTRY.highContrast.label).toBe('High Contrast');
});
