//
// tools/ui-lint/lib/performance/web-vitals.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export async function collectWebVitalsMetrics(page) {
    return page.evaluate(() => {
        const runtime = window[Symbol.for('uiLint.runtime')] || {};
        const webVitals = runtime.performance?.webVitals || {};

        return {
            lcp: webVitals.lcp ?? window.__uiLintLCP ?? null,
            inp: webVitals.inp ?? window.__uiLintINP ?? null,
            cls: webVitals.cls ?? null,
        };
    });
}
