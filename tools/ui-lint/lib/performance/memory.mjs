//
// tools/ui-lint/lib/performance/memory.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { supportsMemoryAPI } from '../browsers/capabilities.mjs';

export { supportsMemoryAPI };

export async function collectMemoryMetrics(page, browserName = null) {
    if (browserName && !supportsMemoryAPI(browserName)) {
        return null;
    }

    return page.evaluate(() => {
        if (!performance.memory) return null;

        return {
            usedJSHeapSize: performance.memory.usedJSHeapSize,
            totalJSHeapSize: performance.memory.totalJSHeapSize,
            jsHeapSizeLimit: performance.memory.jsHeapSizeLimit,
            heapUtilization: performance.memory.usedJSHeapSize / performance.memory.jsHeapSizeLimit,
        };
    });
}
