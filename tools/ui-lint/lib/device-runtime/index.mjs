//
// tools/ui-lint/lib/device-runtime/index.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export { DEVICE_CATALOG, DEVICE_CATEGORIES, DEFAULT_MATRIX, EXTENDED_MATRIX, CUSTOM_VIEWPORTS } from './devices/descriptors.mjs';
export { BROWSER_PROFILES, getBrowserProfile } from './browsers/engine-features.mjs';
export { NETWORK_PROFILES, getNetworkProfile } from './network/profiles.mjs';
export { SCENARIOS, getScenario } from './scenarios/scenario-runtime.mjs';
export { createDeviceRuntime } from './runtime/device-runtime.mjs';
export { createMatrixRuntime } from './runtime/matrix-runtime.mjs';
export { buildRuntimeDiagnostics } from './runtime/diagnostics.mjs';
export { buildViewportRuntime } from './rendering/viewport-runtime.mjs';
export { buildDprRuntime } from './rendering/dpr-runtime.mjs';
export { buildSafeAreaRuntime } from './rendering/safe-area-runtime.mjs';
export { buildVisualViewportRuntime } from './rendering/visual-viewport.mjs';
export { toPlaywrightOptions } from './exports/playwright-adapter.mjs';
export { buildMatrixHash } from './exports/matrix-hashes.mjs';
export { buildSerializableRuntime } from './exports/serializable-runtime.mjs';
