//
// tools/ui-lint/lib/browser-utils.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Compatibility facade for the modular browser runtime.

export { sanitize, ensureDir } from './runtime/screenshots/screenshot-normalizer.mjs';
export { disableMotion, forceReducedMotion } from './runtime/motion/disable-motion.mjs';
export { installLayoutShiftObserver, resetLayoutShiftMetric, collectCLSMetrics } from './runtime/observers/cls-observer.mjs';
export { login, performLogin } from './runtime/auth/login-flow.mjs';
export { applyTheme, bootstrapAuthenticatedSession } from './runtime/auth/auth-state.mjs';
export { collectConsoleAndNetwork, createTelemetrySession } from './runtime/telemetry/network.mjs';
export { captureStablePair, captureScreenshot, prepareStableViewport } from './runtime/screenshots/capture-stable.mjs';
export { diffScreenshots, writeDiffArtifact } from './runtime/visual-diff/diff-artifacts.mjs';
export { captureKpiCards } from './runtime/components/kpi-capture.mjs';
export { diffKpiSets } from './runtime/components/card-diffing.mjs';
export { BrowserAdapters, getBrowserLauncher } from './runtime/browser/launcher.mjs';
export { createBrowserContextOptions } from './runtime/browser/context.mjs';
export { createBrowserSession } from './runtime/browser/session.mjs';
export { waitForNavigationSettled, waitForVisualStability } from './runtime/browser/navigation.mjs';
export { createCleanupBucket } from './runtime/runtime/cleanup.mjs';
export { createRuntime } from './runtime/runtime/lifecycle.mjs';
export { buildRuntimeDiagnostics } from './runtime/runtime/diagnostics.mjs';
