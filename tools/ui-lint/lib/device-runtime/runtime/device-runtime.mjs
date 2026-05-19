//
// tools/ui-lint/lib/device-runtime/runtime/device-runtime.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { getBrowserProfile } from '../browsers/engine-features.mjs';
import { buildRuntimeDiagnostics } from './diagnostics.mjs';
import { buildViewportRuntime } from '../rendering/viewport-runtime.mjs';
import { buildDprRuntime } from '../rendering/dpr-runtime.mjs';
import { buildSafeAreaRuntime } from '../rendering/safe-area-runtime.mjs';
import { buildVisualViewportRuntime } from '../rendering/visual-viewport.mjs';
import { getScenario } from '../scenarios/scenario-runtime.mjs';

function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
    Object.freeze(value);
    for (const nested of Object.values(value)) {
        deepFreeze(nested);
    }
    return value;
}

export function createDeviceRuntime({ descriptor, browser = 'chromium', platform = descriptor?.platform || 'desktop', capabilities = {}, scenario = 'desktop-default' } = {}) {
    if (!descriptor) {
        throw new TypeError('descriptor is required');
    }

    const browserProfile = getBrowserProfile(browser);
    const scenarioProfile = getScenario(scenario);
    const mergedCapabilities = {
        ...(descriptor.capabilities || {}),
        ...capabilities,
        browser: browserProfile.name,
    };
    const viewportRuntime = buildViewportRuntime(descriptor);
    const dprRuntime = buildDprRuntime(descriptor);
    const safeAreaRuntime = buildSafeAreaRuntime(descriptor);
    const visualViewportRuntime = buildVisualViewportRuntime(descriptor, viewportRuntime);
    const foldable = descriptor.foldable || null;

    let orientation = scenarioProfile.orientation || (descriptor.viewport?.width > descriptor.viewport?.height ? 'landscape' : 'portrait');

    const runtime = {
        descriptor,
        browser: browserProfile.name,
        browserProfile,
        platform,
        capabilities: deepFreeze(mergedCapabilities),
        viewport: deepFreeze({ ...viewportRuntime, ...visualViewportRuntime }),
        dpr: deepFreeze(dprRuntime),
        safeArea: deepFreeze(safeAreaRuntime),
        foldable: foldable ? deepFreeze(foldable) : null,
        rendering: deepFreeze({ ...(descriptor.rendering || {}), ...browserProfile }),
        networkProfile: descriptor.networkProfile || 'online',
        performanceTier: scenarioProfile.performanceTier || descriptor.performanceTier || 'desktop',
        scenario: scenarioProfile.name,
        input: deepFreeze({
            touch: Boolean(mergedCapabilities.touch),
            mouse: !mergedCapabilities.touch,
            stylus: false,
            keyboard: true,
        }),
        rotate(nextOrientation) {
            if (!['portrait', 'landscape'].includes(nextOrientation)) {
                throw new Error(`Unsupported orientation: ${nextOrientation}`);
            }
            orientation = nextOrientation;
            return orientation;
        },
        snapshot() {
            return deepFreeze({
                descriptor,
                browser: browserProfile.name,
                platform,
                orientation,
                capabilities: mergedCapabilities,
                viewport: { ...viewportRuntime, ...visualViewportRuntime },
                dpr: dprRuntime,
                safeArea: safeAreaRuntime,
                foldable,
                rendering: { ...(descriptor.rendering || {}), ...browserProfile },
                networkProfile: descriptor.networkProfile || 'online',
                performanceTier: scenarioProfile.performanceTier || descriptor.performanceTier || 'desktop',
                scenario: scenarioProfile.name,
                input: { touch: Boolean(mergedCapabilities.touch), mouse: !mergedCapabilities.touch, stylus: false, keyboard: true },
            });
        },
        query(filters = {}) {
            const snapshot = this.snapshot();
            return Object.entries(filters).every(([key, expected]) => snapshot[key] === expected || snapshot.capabilities?.[key] === expected);
        },
        diagnostics() {
            const unsupportedCapabilities = Object.entries(browserProfile.supports)
                .filter(([, supported]) => !supported)
                .map(([name]) => name);
            return buildRuntimeDiagnostics({
                descriptor,
                browser: browserProfile.name,
                capabilities: mergedCapabilities,
                viewport: viewportRuntime,
                foldable,
                unsupportedCapabilities,
                conflictingConfigs: [],
                invalidViewportCombinations: [],
                missingBrowserEngines: [],
            });
        },
    };

    return deepFreeze(runtime);
}