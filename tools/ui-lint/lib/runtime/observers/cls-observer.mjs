//
// tools/ui-lint/lib/runtime/observers/cls-observer.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export async function installCLSObserver(context) {
    await context.addInitScript(() => {
        const RUNTIME_KEY = Symbol.for('uiLint.runtime');
        const runtime = window[RUNTIME_KEY] || {
            version: 1,
            performance: { webVitals: { lcp: 0, inp: 0, cls: 0 }, memory: null, scroll: { eventCount: 0, longFrames: 0, longTasks: 0, averageFrameTime: null } },
            dom: { mutationCount: 0, mutationBursts: 0, maxBurstSize: 0, reconnectCount: 0, pollingDetected: false, severity: 'diagnostic' },
            fonts: {},
            interactions: {},
            viewport: { width: window.innerWidth, height: window.innerHeight },
        };
        window[RUNTIME_KEY] = runtime;
        window[Symbol.for('uiLint.layoutShift')] = { value: 0, count: 0, entries: [] };

        if (!('PerformanceObserver' in window)) return;
        try {
            const observer = new PerformanceObserver((list) => {
                for (const entry of list.getEntries()) {
                    if (entry.hadRecentInput) continue;
                    runtime.performance.webVitals.cls += entry.value || 0;
                    const layoutShift = window[Symbol.for('uiLint.layoutShift')];
                    layoutShift.value += entry.value || 0;
                    layoutShift.count += 1;
                    layoutShift.entries.push({
                        value: entry.value || 0,
                        timestamp: entry.startTime || performance.now(),
                        sources: entry.sources || [],
                    });
                }
            });
            observer.observe({ type: 'layout-shift', buffered: true });
        } catch {
            // Ignore unsupported browsers.
        }
    });
}

export { installCLSObserver as installLayoutShiftObserver };

export async function resetLayoutShiftMetric(page) {
    await page.evaluate(() => {
        window[Symbol.for('uiLint.layoutShift')] = { value: 0, count: 0, entries: [] };
        const runtime = window[Symbol.for('uiLint.runtime')];
        if (runtime?.performance?.webVitals) {
            runtime.performance.webVitals.cls = 0;
        }
    }).catch(() => { });
}

export async function collectCLSMetrics(page) {
    return page.evaluate(() => window[Symbol.for('uiLint.layoutShift')] || { value: 0, count: 0, entries: [] });
}
