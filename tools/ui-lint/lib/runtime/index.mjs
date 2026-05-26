//
// tools/ui-lint/lib/runtime/index.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export { sanitize, ensureDir } from './screenshots/screenshot-normalizer.mjs';

export {
    BrowserAdapters,
    getBrowserLauncher,
} from './browser/launcher.mjs';
export { createBrowserContextOptions } from './browser/context.mjs';
export { createBrowserSession } from './browser/session.mjs';
export { waitForNavigationSettled, waitForVisualStability } from './browser/navigation.mjs';

export {
    disableMotion,
    forceReducedMotion,
    detectActiveAnimations,
    verifyNoLayoutAnimation,
} from './motion/index.mjs';

export {
    captureScreenshot,
    captureStablePair,
    prepareStableViewport,
} from './screenshots/screenshot-pipeline.mjs';
export { stitchViewportFrames } from './screenshots/viewport-stitching.mjs';

export {
    loadImageBuffer,
    normalizeDimensions,
    computePixelDiff,
} from './visual-diff/pixelmatch.mjs';
export { computeSSIM } from './visual-diff/ssim.mjs';
export { classifyDiffSeverity } from './visual-diff/diff-classification.mjs';
export { writeDiffArtifact, diffScreenshots } from './visual-diff/diff-artifacts.mjs';

export {
    collectConsoleAndNetwork,
    createTelemetrySession,
} from './telemetry/network.mjs';
export { createConsoleBuffer } from './telemetry/console.mjs';
export { createPageErrorBuffer } from './telemetry/page-errors.mjs';
export { createRequestTimeline } from './telemetry/requests.mjs';

export {
    installCLSObserver,
    installLayoutShiftObserver,
    collectCLSMetrics,
    resetLayoutShiftMetric,
} from './observers/cls-observer.mjs';
export { installLCPObserver } from './observers/lcp-observer.mjs';
export { installINPObserver } from './observers/inp-observer.mjs';
export {
    installDOMStabilityObserver,
    collectDOMStabilityMetrics,
} from './observers/mutation-observer.mjs';

export {
    registerCaptureComponent,
    getCaptureComponent,
    getCaptureComponents,
} from './components/component-registry.mjs';
export { captureKpiCards } from './components/kpi-capture.mjs';
export { diffKpiSets } from './components/card-diffing.mjs';

export { createRuntime } from './runtime/runtime/lifecycle.mjs';
export { createCleanupBucket } from './runtime/runtime/cleanup.mjs';
export { buildRuntimeDiagnostics } from './runtime/runtime/diagnostics.mjs';

export { login, performLogin, detectLoginFailure } from './auth/login-flow.mjs';
export { applyTheme, bootstrapAuthenticatedSession } from './auth/auth-state.mjs';
