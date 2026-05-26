//
// tools/ui-lint/lib/orchestration/audit-runner.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export { CONSOLE_ALLOWLIST } from '../console/allowlist.mjs';
export { filterConsoleEntries } from '../console/filters.mjs';
export { CONSOLE_SEVERITY, scoreConsoleSeverity } from '../console/severity.mjs';

export { runAxeAudit } from '../accessibility/axe-runner.mjs';
export { normalizeAccessibilityFinding } from '../accessibility/violation-normalizer.mjs';

export { collectPerformanceMetrics, collectNavigationPerformanceMetrics } from '../performance/metrics.mjs';
export { installPerformanceObservers } from '../performance/observers.mjs';
export { collectMemoryMetrics, supportsMemoryAPI } from '../performance/memory.mjs';
export { collectWebVitalsMetrics } from '../performance/web-vitals.mjs';
export { collectScrollPerformanceMetrics } from '../performance/scroll-performance.mjs';

export { checkFontLoading } from '../fonts/font-loading.mjs';
export { detectFoutRisk } from '../fonts/fout-detection.mjs';
export { detectIconFontIssues } from '../fonts/icon-diagnostics.mjs';

export { computeSSIM } from '../visual/ssim.mjs';

export { collectDOMStabilityMetrics, installDOMStabilityObserver } from '../dom/mutation-observer.mjs';
export { classifyMutationSeverity } from '../dom/stability.mjs';

export { BrowserAdapters, getBrowserLauncher } from '../browsers/launcher.mjs';
export { BROWSER_CONFIGS, getBrowserCapabilityProfile } from '../browsers/matrix.mjs';
export { supportsINP, supportsLCP, supportsVisualViewport } from '../browsers/capabilities.mjs';

export { createAuditTelemetry, finalizeAuditTelemetry } from './telemetry.mjs';

import { runAxeAudit } from '../accessibility/axe-runner.mjs';
import { collectPerformanceMetrics } from '../performance/metrics.mjs';
import { checkFontLoading } from '../fonts/font-loading.mjs';

export async function runExtendedAudits(page, { browserName = null, includeAxe = true, includePerformance = true, includeFonts = true } = {}) {
    const audits = {};

    if (includeAxe) {
        audits.axe = await runAxeAudit(page);
    }

    if (includePerformance) {
        audits.performance = await collectPerformanceMetrics(page, { browserName });
    }

    if (includeFonts) {
        audits.fonts = await checkFontLoading(page);
    }

    return audits;
}
