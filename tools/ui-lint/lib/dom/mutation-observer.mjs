//
// tools/ui-lint/lib/dom/mutation-observer.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { classifyMutationSeverity } from './stability.mjs';

export async function installDOMStabilityObserver(context) {
    await context.addInitScript(() => {
        const runtimeKey = Symbol.for('uiLint.runtime');
        const domStatsKey = Symbol.for('uiLint.domStats');
        const runtime = window[runtimeKey] || {
            version: 1,
            performance: {
                webVitals: { lcp: 0, inp: 0, cls: 0 },
                memory: null,
                scroll: { eventCount: 0, longFrames: 0, longTasks: 0, averageFrameTime: null },
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
            viewport: { width: window.innerWidth, height: window.innerHeight },
        };

        window[runtimeKey] = runtime;
        window[domStatsKey] = runtime.dom;

        if (!('MutationObserver' in window)) return;

        let burstCount = 0;
        let burstTimeout = null;

        const observer = new MutationObserver((mutations) => {
            runtime.dom.mutationCount += mutations.length;
            burstCount += mutations.length;

            if (burstTimeout) clearTimeout(burstTimeout);
            burstTimeout = setTimeout(() => {
                if (burstCount > 50) {
                    runtime.dom.mutationBursts += 1;
                    runtime.dom.maxBurstSize = Math.max(runtime.dom.maxBurstSize, burstCount);
                }
                runtime.dom.severity = classifyMutationSeverity(runtime.dom);
                burstCount = 0;
            }, 100);

            for (const mutation of mutations) {
                if (mutation.type === 'childList') {
                    for (const node of mutation.addedNodes) {
                        if (node.nodeType === 1 && !document.body.contains(node)) {
                            runtime.dom.reconnectCount += 1;
                        }
                    }
                }
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            characterData: true,
        });
    });
}

export async function collectDOMStabilityMetrics(page) {
    return page.evaluate(() => {
        const runtime = window[Symbol.for('uiLint.runtime')];
        return runtime?.dom || window[Symbol.for('uiLint.domStats')] || {
            mutationCount: 0,
            mutationBursts: 0,
            maxBurstSize: 0,
            reconnectCount: 0,
            pollingDetected: false,
            severity: 'diagnostic',
        };
    });
}
