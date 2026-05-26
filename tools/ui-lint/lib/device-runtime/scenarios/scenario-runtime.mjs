//
// tools/ui-lint/lib/device-runtime/scenarios/scenario-runtime.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const SCENARIOS = Object.freeze({
    'desktop-default': Object.freeze({ name: 'desktop-default', orientation: 'landscape', performanceTier: 'desktop' }),
    'one-handed-mobile': Object.freeze({ name: 'one-handed-mobile', orientation: 'portrait', performanceTier: 'mid-mobile' }),
    'responsive-drift': Object.freeze({ name: 'responsive-drift', orientation: 'portrait', performanceTier: 'mid-mobile' }),
    'low-end-mobile': Object.freeze({ name: 'low-end-mobile', orientation: 'portrait', performanceTier: 'low-end' }),
    'low-end-android': Object.freeze({ name: 'low-end-android', orientation: 'portrait', performanceTier: 'low-end' }),
    'landscape-tablet': Object.freeze({ name: 'landscape-tablet', orientation: 'landscape', performanceTier: 'tablet' }),
    'portrait-tablet': Object.freeze({ name: 'portrait-tablet', orientation: 'portrait', performanceTier: 'tablet' }),
    'foldable-open': Object.freeze({ name: 'foldable-open', orientation: 'portrait', performanceTier: 'foldable' }),
});

export function getScenario(name) {
    return SCENARIOS[name] || SCENARIOS['desktop-default'];
}