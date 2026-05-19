//
// tools/ui-lint/lib/design-tokens/runtime/policies.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { TOKEN_CATEGORIES } from '../schema/categories.mjs';
import { detectTokenDrift } from '../themes/theme-diffing.mjs';

export const BROWSER_CAPABILITIES = Object.freeze({
    chromium: Object.freeze({ supportsCLS: true, supportsINP: true, supportsLCP: true, supportsMemory: true }),
    webkit: Object.freeze({ supportsCLS: true, supportsINP: false, supportsLCP: true, supportsMemory: false }),
    firefox: Object.freeze({ supportsCLS: false, supportsINP: true, supportsLCP: true, supportsMemory: true }),
});

export const DEVICE_PROFILE_REGISTRY = Object.freeze({
    desktop: Object.freeze({ class: 'desktop', density: 'comfortable', viewportScale: 1 }),
    tablet: Object.freeze({ class: 'tablet', density: 'balanced', viewportScale: 0.85 }),
    mobile: Object.freeze({ class: 'mobile', density: 'compact', viewportScale: 0.72 }),
});

export const UI_LINT_PROFILES = Object.freeze({
    ci: Object.freeze({ settleMultiplier: 1.25, motionPolicy: 'full', payloadMode: 'minimal' }),
    local: Object.freeze({ settleMultiplier: 1, motionPolicy: 'selective', payloadMode: 'default' }),
    debug: Object.freeze({ settleMultiplier: 1, motionPolicy: 'none', payloadMode: 'verbose' }),
    visualRegression: Object.freeze({ settleMultiplier: 1.5, motionPolicy: 'full', payloadMode: 'default' }),
});

export const DEFAULT_EVALUATION_CATEGORIES = Object.freeze([...TOKEN_CATEGORIES]);

export function buildEvaluationPayload({ categories = DEFAULT_EVALUATION_CATEGORIES } = {}) {
    return {
        categories: [...categories],
        browserCapabilities: BROWSER_CAPABILITIES,
        deviceProfiles: DEVICE_PROFILE_REGISTRY,
        uiLintProfiles: UI_LINT_PROFILES,
    };
}

export function buildSerializableConstants({ categories = DEFAULT_EVALUATION_CATEGORIES } = {}) {
    return structuredClone(buildEvaluationPayload({ categories }));
}

export { detectTokenDrift };