//
// tools/ui-lint/lib/audit-helpers.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Compatibility facade for the modular audit runtime.

export {
    BROWSER_CONFIGS,
    BrowserAdapters,
    checkFontLoading,
    collectDOMStabilityMetrics,
    collectMemoryMetrics,
    collectNavigationPerformanceMetrics,
    collectPerformanceMetrics,
    collectScrollPerformanceMetrics,
    collectWebVitalsMetrics,
    computeSSIM,
    CONSOLE_ALLOWLIST,
    CONSOLE_SEVERITY,
    createAuditTelemetry,
    detectFoutRisk,
    detectIconFontIssues,
    filterConsoleEntries,
    finalizeAuditTelemetry,
    getBrowserCapabilityProfile,
    getBrowserLauncher,
    installDOMStabilityObserver,
    installPerformanceObservers,
    normalizeAccessibilityFinding,
    runAxeAudit,
    runExtendedAudits,
    scoreConsoleSeverity,
    supportsINP,
    supportsLCP,
    supportsMemoryAPI,
    supportsVisualViewport,
} from './orchestration/audit-runner.mjs';
