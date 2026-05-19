//
// tools/ui-lint/lib/runtime/observers/lcp-observer.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

const RUNTIME_KEY = Symbol.for('uiLint.runtime');

function ensureRuntime() {
    const runtime = window[RUNTIME_KEY] || {
        version: 1,
        performance: { webVitals: { lcp: 0, inp: 0, cls: 0 }, memory: null, scroll: { eventCount: 0, longFrames: 0, longTasks: 0, averageFrameTime: null } },
        dom: { mutationCount: 0, mutationBursts: 0, maxBurstSize: 0, reconnectCount: 0, pollingDetected: false, severity: 'diagnostic' },
        fonts: {},
        interactions: {},
        viewport: { width: window.innerWidth, height: window.innerHeight },
    };
    window[RUNTIME_KEY] = runtime;
    return runtime;
}

export async function installLCPObserver(context) {
    await context.addInitScript(() => {
        const runtime = ensureRuntime();
        if (!('PerformanceObserver' in window)) return;
        try {
            const observer = new PerformanceObserver((list) => {
                const entries = list.getEntries();
                if (entries.length > 0) {
                    runtime.performance.webVitals.lcp = entries[entries.length - 1].startTime;
                }
            });
            observer.observe({ type: 'largest-contentful-paint', buffered: true });
        } catch {
            // LCP not supported.
        }
    });
}
