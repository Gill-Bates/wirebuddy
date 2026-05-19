//
// tools/ui-lint/lib/performance/metrics.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { collectMemoryMetrics } from './memory.mjs';
import { collectScrollPerformanceMetrics } from './scroll-performance.mjs';
import { collectWebVitalsMetrics } from './web-vitals.mjs';

export async function collectNavigationPerformanceMetrics(page) {
    return page.evaluate(() => {
        const result = {
            navigation: null,
            paint: {},
            resourceCount: 0,
            totalTransferSize: 0,
        };

        const navEntries = performance.getEntriesByType('navigation');
        if (navEntries.length > 0) {
            const nav = navEntries[0];
            result.navigation = {
                domContentLoaded: Math.round(nav.domContentLoadedEventEnd - nav.startTime),
                domComplete: Math.round(nav.domComplete - nav.startTime),
                loadEventEnd: Math.round(nav.loadEventEnd - nav.startTime),
                ttfb: Math.round(nav.responseStart - nav.requestStart),
                redirectTime: Math.round(nav.redirectEnd - nav.redirectStart),
                dnsTime: Math.round(nav.domainLookupEnd - nav.domainLookupStart),
                connectTime: Math.round(nav.connectEnd - nav.connectStart),
                responseTime: Math.round(nav.responseEnd - nav.responseStart),
            };
        }

        const paintEntries = performance.getEntriesByType('paint');
        for (const entry of paintEntries) {
            if (entry.name === 'first-contentful-paint') {
                result.paint.fcp = Math.round(entry.startTime);
            } else if (entry.name === 'first-paint') {
                result.paint.fp = Math.round(entry.startTime);
            }
        }

        const resources = performance.getEntriesByType('resource');
        result.resourceCount = resources.length;
        result.totalTransferSize = resources.reduce((sum, resource) => sum + (resource.transferSize || 0), 0);

        return result;
    });
}

export async function collectPerformanceMetrics(page, { browserName = null } = {}) {
    const [navigation, webVitals, memory, scroll] = await Promise.all([
        collectNavigationPerformanceMetrics(page),
        collectWebVitalsMetrics(page),
        collectMemoryMetrics(page, browserName),
        collectScrollPerformanceMetrics(page),
    ]);

    return {
        ...navigation,
        ...webVitals,
        memory,
        scroll,
    };
}
