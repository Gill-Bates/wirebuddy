//
// tools/ui-lint/lib/runtime/observers/inp-observer.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export async function installINPObserver(context) {
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
        if (!('PerformanceObserver' in window)) return;
        try {
            const observer = new PerformanceObserver((list) => {
                for (const entry of list.getEntries()) {
                    if (entry.duration > runtime.performance.webVitals.inp) {
                        runtime.performance.webVitals.inp = entry.duration;
                    }
                }
            });
            observer.observe({ type: 'event', buffered: true, durationThreshold: 16 });
        } catch {
            // INP not supported.
        }
    });
}
