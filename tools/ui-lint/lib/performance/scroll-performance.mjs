//
// tools/ui-lint/lib/performance/scroll-performance.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export async function collectScrollPerformanceMetrics(page) {
    return page.evaluate(() => {
        const runtime = window[Symbol.for('uiLint.runtime')] || {};
        const scroll = runtime.performance?.scroll || {};

        return {
            eventCount: scroll.eventCount || 0,
            longFrames: scroll.longFrames || 0,
            longTasks: scroll.longTasks || 0,
            averageFrameTime: scroll.averageFrameTime || null,
        };
    });
}
