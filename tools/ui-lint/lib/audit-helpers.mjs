//
// tools/ui-lint/lib/audit-helpers.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Extended audit capabilities: Axe, Performance, Fonts, SSIM, Console filtering
//

import fs from 'node:fs';
import path from 'node:path';
import { PNG } from 'pngjs';

// -----------------------------------------------------------------------------
// Console Allowlist / Severity Scoring
// -----------------------------------------------------------------------------

const CONSOLE_ALLOWLIST = [
    // Third-party noise
    /ResizeObserver loop/i,
    /Failed to load resource.*favicon/i,
    /DevTools failed to load/i,
    /Download the React DevTools/i,
    // Known framework warnings
    /React does not recognize/i,
    /Warning: Each child in a list/i,
    // Bootstrap deprecation notices (non-critical)
    /Bootstrap.*deprecated/i,
    // Leaflet map tiles (expected 404s in test environments)
    /tile.*404/i,
    /openstreetmap.*failed/i,
];

const CONSOLE_SEVERITY = {
    error: 3,
    warning: 2,
    info: 1,
    log: 0,
};

export function filterConsoleEntries(entries, { allowlist = CONSOLE_ALLOWLIST } = {}) {
    return entries.filter((entry) => {
        const text = String(entry.text || '');
        return !allowlist.some((pattern) => pattern.test(text));
    });
}

export function scoreConsoleSeverity(entries) {
    let score = 0;
    const critical = [];
    const serious = [];
    const minor = [];

    for (const entry of entries) {
        const severity = CONSOLE_SEVERITY[entry.type] || 0;
        score += severity;

        if (severity >= 3) {
            critical.push(entry);
        } else if (severity >= 2) {
            serious.push(entry);
        } else if (severity >= 1) {
            minor.push(entry);
        }
    }

    return { score, critical, serious, minor, total: entries.length };
}

// -----------------------------------------------------------------------------
// Axe Accessibility Integration
// -----------------------------------------------------------------------------

export async function runAxeAudit(page) {
    try {
        const { default: AxeBuilder } = await import('@axe-core/playwright');
        const axeResults = await new AxeBuilder({ page })
            .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'])
            .analyze();

        const violations = axeResults.violations || [];
        const critical = violations.filter((v) => v.impact === 'critical');
        const serious = violations.filter((v) => v.impact === 'serious');
        const moderate = violations.filter((v) => v.impact === 'moderate');
        const minor = violations.filter((v) => v.impact === 'minor');

        return {
            passed: axeResults.passes?.length || 0,
            violations: violations.length,
            critical: critical.map(summarizeViolation),
            serious: serious.map(summarizeViolation),
            moderate: moderate.map(summarizeViolation),
            minor: minor.map(summarizeViolation),
            incomplete: axeResults.incomplete?.length || 0,
        };
    } catch (err) {
        return {
            error: err.message,
            passed: 0,
            violations: 0,
            critical: [],
            serious: [],
            moderate: [],
            minor: [],
            incomplete: 0,
        };
    }
}

function summarizeViolation(violation) {
    return {
        id: violation.id,
        impact: violation.impact,
        description: violation.description,
        help: violation.help,
        helpUrl: violation.helpUrl,
        nodeCount: violation.nodes?.length || 0,
        nodes: (violation.nodes || []).slice(0, 5).map((node) => ({
            html: node.html?.slice(0, 200),
            target: node.target,
            failureSummary: node.failureSummary,
        })),
    };
}

// -----------------------------------------------------------------------------
// Performance Metrics (FCP, LCP, Navigation Timing)
// -----------------------------------------------------------------------------

export async function collectPerformanceMetrics(page) {
    return page.evaluate(() => {
        const result = {
            navigation: null,
            paint: {},
            lcp: null,
            memory: null,
            resourceCount: 0,
            totalTransferSize: 0,
        };

        // Navigation timing
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

        // Paint timing (FCP, FP)
        const paintEntries = performance.getEntriesByType('paint');
        for (const entry of paintEntries) {
            if (entry.name === 'first-contentful-paint') {
                result.paint.fcp = Math.round(entry.startTime);
            } else if (entry.name === 'first-paint') {
                result.paint.fp = Math.round(entry.startTime);
            }
        }

        // LCP (if available via PerformanceObserver buffer)
        if (window.__uiLintLCP !== undefined) {
            result.lcp = Math.round(window.__uiLintLCP);
        }

        // Memory (Chrome-only)
        if (performance.memory) {
            result.memory = {
                usedJSHeapSize: performance.memory.usedJSHeapSize,
                totalJSHeapSize: performance.memory.totalJSHeapSize,
                jsHeapSizeLimit: performance.memory.jsHeapSizeLimit,
                heapUtilization: performance.memory.usedJSHeapSize / performance.memory.jsHeapSizeLimit,
            };
        }

        // Resource summary
        const resources = performance.getEntriesByType('resource');
        result.resourceCount = resources.length;
        result.totalTransferSize = resources.reduce((sum, r) => sum + (r.transferSize || 0), 0);

        return result;
    });
}

export async function installPerformanceObservers(context) {
    await context.addInitScript(() => {
        window.__uiLintLCP = 0;
        window.__uiLintINP = 0;

        if (!('PerformanceObserver' in window)) return;

        // LCP observer
        try {
            const lcpObserver = new PerformanceObserver((list) => {
                const entries = list.getEntries();
                if (entries.length > 0) {
                    window.__uiLintLCP = entries[entries.length - 1].startTime;
                }
            });
            lcpObserver.observe({ type: 'largest-contentful-paint', buffered: true });
        } catch {
            // LCP not supported
        }

        // INP approximation (interaction timing)
        try {
            const inpObserver = new PerformanceObserver((list) => {
                for (const entry of list.getEntries()) {
                    if (entry.duration > window.__uiLintINP) {
                        window.__uiLintINP = entry.duration;
                    }
                }
            });
            inpObserver.observe({ type: 'event', buffered: true, durationThreshold: 16 });
        } catch {
            // INP not supported
        }
    });
}

// -----------------------------------------------------------------------------
// Font and Icon Loading Checks
// -----------------------------------------------------------------------------

export async function checkFontLoading(page) {
    return page.evaluate(async () => {
        const result = {
            fontsReady: false,
            loadedFonts: [],
            failedFonts: [],
            materialIconsLoaded: false,
            iconMissing: [],
            foutRisk: false,
        };

        // Wait for fonts
        try {
            await document.fonts.ready;
            result.fontsReady = true;
        } catch {
            result.fontsReady = false;
        }

        // Enumerate loaded fonts
        if (document.fonts && typeof document.fonts.forEach === 'function') {
            document.fonts.forEach((font) => {
                if (font.status === 'loaded') {
                    result.loadedFonts.push({
                        family: font.family,
                        weight: font.weight,
                        style: font.style,
                    });
                } else if (font.status === 'error') {
                    result.failedFonts.push({
                        family: font.family,
                        weight: font.weight,
                        style: font.style,
                    });
                }
            });
        }

        // Check Material Icons specifically
        const materialIcons = result.loadedFonts.some((f) =>
            f.family.toLowerCase().includes('material') ||
            f.family.toLowerCase().includes('icons')
        );
        result.materialIconsLoaded = materialIcons;

        // Find potentially broken icons (empty or showing ligature text)
        const icons = Array.from(document.querySelectorAll('.material-icons, .material-icons-outlined, [class*="material-symbols"]'));
        for (const icon of icons.slice(0, 50)) {
            const style = window.getComputedStyle(icon);
            const rect = icon.getBoundingClientRect();

            // Check for visible ligature text (font not loaded)
            if (rect.width > 50 && icon.textContent?.trim().length > 2) {
                result.iconMissing.push({
                    text: icon.textContent.trim().slice(0, 30),
                    width: Math.round(rect.width),
                    height: Math.round(rect.height),
                });
            }

            // Check for empty icons
            if (rect.width === 0 || rect.height === 0) {
                result.iconMissing.push({
                    text: icon.textContent?.trim().slice(0, 30) || '<empty>',
                    width: 0,
                    height: 0,
                });
            }
        }

        // FOUT risk: check if any text uses fallback serif/sans-serif
        const textElements = Array.from(document.querySelectorAll('body *'))
            .filter((el) => el.textContent?.trim() && el.children.length === 0)
            .slice(0, 100);

        for (const el of textElements) {
            const fontFamily = window.getComputedStyle(el).fontFamily || '';
            // If font stack ends with generic fallback and no loaded font matches
            if (/serif|sans-serif|monospace$/i.test(fontFamily.split(',').pop()?.trim() || '')) {
                const primaryFont = fontFamily.split(',')[0]?.replace(/["']/g, '').trim();
                const isLoaded = result.loadedFonts.some((f) =>
                    f.family.replace(/["']/g, '').toLowerCase() === primaryFont.toLowerCase()
                );
                if (!isLoaded && primaryFont && !/serif|sans-serif|monospace/i.test(primaryFont)) {
                    result.foutRisk = true;
                    break;
                }
            }
        }

        return result;
    });
}

// -----------------------------------------------------------------------------
// SSIM Perceptual Diff (complementary to pixelmatch)
// -----------------------------------------------------------------------------

export async function computeSSIM(imgPathA, imgPathB) {
    try {
        const { default: ssim } = await import('ssim.js');

        const imgA = PNG.sync.read(fs.readFileSync(imgPathA));
        const imgB = PNG.sync.read(fs.readFileSync(imgPathB));

        // SSIM requires same dimensions
        if (imgA.width !== imgB.width || imgA.height !== imgB.height) {
            return {
                ssim: null,
                mssim: null,
                error: 'dimension-mismatch',
                dimensions: {
                    a: { width: imgA.width, height: imgA.height },
                    b: { width: imgB.width, height: imgB.height },
                },
            };
        }

        // Convert PNG RGBA to ImageData-like format for ssim.js
        const dataA = {
            data: imgA.data,
            width: imgA.width,
            height: imgA.height,
        };
        const dataB = {
            data: imgB.data,
            width: imgB.width,
            height: imgB.height,
        };

        const result = ssim.ssim(dataA, dataB);

        return {
            ssim: result.ssim,
            mssim: result.mssim,
            error: null,
        };
    } catch (err) {
        return {
            ssim: null,
            mssim: null,
            error: err.message,
        };
    }
}

// -----------------------------------------------------------------------------
// DOM Stability Observer (detect render loops, excessive mutations)
// -----------------------------------------------------------------------------

export async function installDOMStabilityObserver(context) {
    await context.addInitScript(() => {
        window.__uiLintDOMStats = {
            mutationCount: 0,
            mutationBursts: 0,
            maxBurstSize: 0,
            lastBurstTime: 0,
            reconnectCount: 0,
            pollingDetected: false,
        };

        if (!('MutationObserver' in window)) return;

        let burstCount = 0;
        let burstTimeout = null;

        const observer = new MutationObserver((mutations) => {
            window.__uiLintDOMStats.mutationCount += mutations.length;
            burstCount += mutations.length;

            // Detect burst (many mutations in short time)
            if (burstTimeout) clearTimeout(burstTimeout);
            burstTimeout = setTimeout(() => {
                if (burstCount > 50) {
                    window.__uiLintDOMStats.mutationBursts += 1;
                    if (burstCount > window.__uiLintDOMStats.maxBurstSize) {
                        window.__uiLintDOMStats.maxBurstSize = burstCount;
                    }
                }
                burstCount = 0;
            }, 100);

            // Track reconnects (elements added then immediately removed)
            for (const mutation of mutations) {
                if (mutation.type === 'childList') {
                    for (const node of mutation.addedNodes) {
                        if (node.nodeType === 1 && !document.body.contains(node)) {
                            window.__uiLintDOMStats.reconnectCount += 1;
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
    return page.evaluate(() => window.__uiLintDOMStats || {
        mutationCount: 0,
        mutationBursts: 0,
        maxBurstSize: 0,
        reconnectCount: 0,
        pollingDetected: false,
    });
}

// -----------------------------------------------------------------------------
// Browser Matrix Helpers
// -----------------------------------------------------------------------------

export const BROWSER_CONFIGS = [
    { name: 'chromium', launcher: 'chromium' },
    { name: 'webkit', launcher: 'webkit' },
    { name: 'firefox', launcher: 'firefox' },
];

export function getBrowserLauncher(browserName) {
    return async (playwright) => {
        switch (browserName) {
            case 'webkit':
                return playwright.webkit.launch({ headless: true });
            case 'firefox':
                return playwright.firefox.launch({ headless: true });
            case 'chromium':
            default:
                return playwright.chromium.launch({ headless: true });
        }
    };
}

// -----------------------------------------------------------------------------
// Export combined audit runner
// -----------------------------------------------------------------------------

export async function runExtendedAudits(page, { includeAxe = true, includePerformance = true, includeFonts = true } = {}) {
    const audits = {};

    if (includeAxe) {
        audits.axe = await runAxeAudit(page);
    }

    if (includePerformance) {
        audits.performance = await collectPerformanceMetrics(page);
    }

    if (includeFonts) {
        audits.fonts = await checkFontLoading(page);
    }

    return audits;
}
