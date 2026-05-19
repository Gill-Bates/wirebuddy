//
// tools/ui-lint/lib/config/screenshots/policies.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const SCREENSHOT_TIMING_POLICY = Object.freeze({
    settleMs: 800,
    tabSwitchSettleMs: 700,
    detailsExpandSettleMs: 300,
    componentLayoutShiftSettleMs: 800,
    loginErrorSettleMs: 120,
    loginLockoutResetMs: 16000,
    loginTestStaggerMs: 13000,
});

export function getScreenshotSettleTime({ browser = 'chromium', deviceClass = 'desktop', animationCount = 0, cpuProfile = 'default', reducedMotion = false } = {}) {
    let settleMs = SCREENSHOT_TIMING_POLICY.settleMs;

    if (deviceClass === 'tablet') settleMs += 60;
    if (deviceClass === 'mobile') settleMs += 120;
    if (browser === 'webkit') settleMs += 80;
    if (browser === 'firefox') settleMs += 40;
    if (animationCount > 8) settleMs += 80;
    if (cpuProfile === 'ci' || cpuProfile === 'slow') settleMs += 120;
    if (reducedMotion) settleMs -= 200;

    return Math.max(200, Math.round(settleMs));
}

export const SCREENSHOT_SETTLE_MS = SCREENSHOT_TIMING_POLICY.settleMs;
export const TAB_SWITCH_SETTLE_MS = SCREENSHOT_TIMING_POLICY.tabSwitchSettleMs;
export const DETAILS_EXPAND_SETTLE_MS = SCREENSHOT_TIMING_POLICY.detailsExpandSettleMs;
export const COMPONENT_LAYOUT_SHIFT_SETTLE_MS = SCREENSHOT_TIMING_POLICY.componentLayoutShiftSettleMs;
export const LOGIN_ERROR_SETTLE_MS = SCREENSHOT_TIMING_POLICY.loginErrorSettleMs;
export const LOGIN_LOCKOUT_RESET_MS = SCREENSHOT_TIMING_POLICY.loginLockoutResetMs;
export const LOGIN_TEST_STAGGER_MS = SCREENSHOT_TIMING_POLICY.loginTestStaggerMs;

export const DIFF_THRESHOLD_POLICY = Object.freeze({
    visualDrift: 0.0025,
    componentVisualDrift: 0.01,
});