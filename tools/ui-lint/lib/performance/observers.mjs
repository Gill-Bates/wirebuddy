//
// tools/ui-lint/lib/performance/observers.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export async function installPerformanceObservers(context) {
    await context.addInitScript(() => {
        const runtimeKey = Symbol.for('uiLint.runtime');
        const runtime = window[runtimeKey] || {
            version: 1,
            performance: {
                webVitals: {
                    lcp: 0,
                    inp: 0,
                    cls: 0,
                },
                memory: null,
                scroll: {
                    eventCount: 0,
                    longFrames: 0,
                    longTasks: 0,
                    averageFrameTime: null,
                },
            },
            dom: {
                mutationCount: 0,
                mutationBursts: 0,
                maxBurstSize: 0,
                reconnectCount: 0,
                pollingDetected: false,
                severity: 'diagnostic',
            },
            fonts: {},
            interactions: {},
            viewport: {
                width: window.innerWidth,
                height: window.innerHeight,
            },
        };

        window[runtimeKey] = runtime;

        if (!('PerformanceObserver' in window)) return;

        try {
            const lcpObserver = new PerformanceObserver((list) => {
                const entries = list.getEntries();
                if (entries.length > 0) {
                    runtime.performance.webVitals.lcp = entries[entries.length - 1].startTime;
                }
            });
            lcpObserver.observe({ type: 'largest-contentful-paint', buffered: true });
        } catch {
            // LCP not supported.
        }

        try {
            const inpObserver = new PerformanceObserver((list) => {
                for (const entry of list.getEntries()) {
                    if (entry.duration > runtime.performance.webVitals.inp) {
                        runtime.performance.webVitals.inp = entry.duration;
                    }
                }
            });
            inpObserver.observe({ type: 'event', buffered: true, durationThreshold: 16 });
        } catch {
            // INP not supported.
        }
    });
}
