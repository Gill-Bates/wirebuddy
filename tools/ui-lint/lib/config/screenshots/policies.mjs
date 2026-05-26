//
// tools/ui-lint/lib/config/screenshots/policies.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { LAYOUT_STABILITY_POLICY } from '../layout/policies.mjs';

function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) {
        return value;
    }

    Object.freeze(value);
    for (const nested of Object.values(value)) {
        deepFreeze(nested);
    }
    return value;
}

function assertNonNegativeFiniteNumber(value, name) {
    if (!Number.isFinite(value) || value < 0) {
        throw new TypeError(`${name} must be a non-negative finite number, got ${value}`);
    }
}

function validateNumericPolicy(policyName, policy) {
    for (const [key, value] of Object.entries(policy)) {
        assertNonNegativeFiniteNumber(value, `${policyName}.${key}`);
    }
    return policy;
}

function clampLowerBound(value, minValue) {
    return value < minValue ? minValue : value;
}

export const SCREENSHOT_BROWSERS = deepFreeze({
    CHROMIUM: 'chromium',
    WEBKIT: 'webkit',
    FIREFOX: 'firefox',
});

export const SCREENSHOT_DEVICE_CLASSES = deepFreeze({
    DESKTOP: 'desktop',
    TABLET: 'tablet',
    MOBILE: 'mobile',
});

export const SCREENSHOT_CPU_PROFILES = deepFreeze({
    DEFAULT: 'default',
    CI: 'ci',
    SLOW: 'slow',
});

export const DEVICE_SETTLE_MODIFIERS_MS = deepFreeze({
    [SCREENSHOT_DEVICE_CLASSES.DESKTOP]: 0,
    [SCREENSHOT_DEVICE_CLASSES.TABLET]: 60,
    [SCREENSHOT_DEVICE_CLASSES.MOBILE]: 120,
});

export const BROWSER_SETTLE_MODIFIERS_MS = deepFreeze({
    [SCREENSHOT_BROWSERS.CHROMIUM]: 0,
    [SCREENSHOT_BROWSERS.FIREFOX]: 40,
    [SCREENSHOT_BROWSERS.WEBKIT]: 80,
});

export const CPU_SETTLE_MODIFIERS_MS = deepFreeze({
    [SCREENSHOT_CPU_PROFILES.DEFAULT]: 0,
    [SCREENSHOT_CPU_PROFILES.CI]: 120,
    [SCREENSHOT_CPU_PROFILES.SLOW]: 120,
});

export const SETTLE_TIME_POLICY = deepFreeze(validateNumericPolicy('SETTLE_TIME_POLICY', {
    minSettleMs: 200,
    animationStepMs: 8,
    animationMaxExtraMs: 120,
    reducedMotionFactor: 0.9,
}));

if (SETTLE_TIME_POLICY.reducedMotionFactor <= 0 || SETTLE_TIME_POLICY.reducedMotionFactor > 1) {
    throw new TypeError('SETTLE_TIME_POLICY.reducedMotionFactor must be > 0 and <= 1');
}

const AUTH_LOCKOUT_DURATION_MS = 30000;
const LOCKOUT_SAFETY_BUFFER_MS = 1000;

export const SCREENSHOT_TIMING_POLICY = deepFreeze(validateNumericPolicy('SCREENSHOT_TIMING_POLICY', {
    settleMs: 800,
    tabSwitchSettleMs: 700,
    detailsExpandSettleMs: 300,
    componentLayoutShiftSettleMs: 800,
    loginErrorSettleMs: 120,
    // The app's auth lockout starts at 30s after repeated failed logins.
    // UI-lint must wait longer than that before retrying or switching browsers.
    loginLockoutResetMs: AUTH_LOCKOUT_DURATION_MS + LOCKOUT_SAFETY_BUFFER_MS,
    loginTestStaggerMs: 13000,
}));

function assertKnownEnumValue(value, allowedValues, name) {
    if (!allowedValues.includes(value)) {
        throw new TypeError(`${name} must be one of ${allowedValues.join(', ')}, got ${value}`);
    }
}

export function calculateScreenshotSettleTime({
    browser = SCREENSHOT_BROWSERS.CHROMIUM,
    deviceClass = SCREENSHOT_DEVICE_CLASSES.DESKTOP,
    animationCount = 0,
    cpuProfile = SCREENSHOT_CPU_PROFILES.DEFAULT,
    reducedMotion = false,
} = {}) {
    assertKnownEnumValue(browser, Object.values(SCREENSHOT_BROWSERS), 'browser');
    assertKnownEnumValue(deviceClass, Object.values(SCREENSHOT_DEVICE_CLASSES), 'deviceClass');
    assertKnownEnumValue(cpuProfile, Object.values(SCREENSHOT_CPU_PROFILES), 'cpuProfile');
    assertNonNegativeFiniteNumber(animationCount, 'animationCount');

    let settleMs = SCREENSHOT_TIMING_POLICY.settleMs;

    settleMs += DEVICE_SETTLE_MODIFIERS_MS[deviceClass] ?? 0;
    settleMs += BROWSER_SETTLE_MODIFIERS_MS[browser] ?? 0;
    settleMs += CPU_SETTLE_MODIFIERS_MS[cpuProfile] ?? 0;
    settleMs += Math.min(animationCount * SETTLE_TIME_POLICY.animationStepMs, SETTLE_TIME_POLICY.animationMaxExtraMs);
    if (reducedMotion) {
        settleMs *= SETTLE_TIME_POLICY.reducedMotionFactor;
    }

    return Math.round(clampLowerBound(settleMs, SETTLE_TIME_POLICY.minSettleMs));
}

export function getScreenshotSettleTime(options = {}) {
    return calculateScreenshotSettleTime(options);
}

export const SCREENSHOT_SETTLE_MS = SCREENSHOT_TIMING_POLICY.settleMs;
export const TAB_SWITCH_SETTLE_MS = SCREENSHOT_TIMING_POLICY.tabSwitchSettleMs;
export const DETAILS_EXPAND_SETTLE_MS = SCREENSHOT_TIMING_POLICY.detailsExpandSettleMs;
export const COMPONENT_LAYOUT_SHIFT_SETTLE_MS = SCREENSHOT_TIMING_POLICY.componentLayoutShiftSettleMs;
export const LOGIN_ERROR_SETTLE_MS = SCREENSHOT_TIMING_POLICY.loginErrorSettleMs;
export const LOGIN_LOCKOUT_RESET_MS = SCREENSHOT_TIMING_POLICY.loginLockoutResetMs;
export const LOGIN_TEST_STAGGER_MS = SCREENSHOT_TIMING_POLICY.loginTestStaggerMs;

export const DIFF_THRESHOLD_POLICY = deepFreeze(validateNumericPolicy('DIFF_THRESHOLD_POLICY', {
    visualDrift: LAYOUT_STABILITY_POLICY.visualDriftThreshold,
    componentVisualDrift: 0.01,
}));