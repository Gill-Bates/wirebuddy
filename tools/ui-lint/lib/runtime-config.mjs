import path from 'node:path';

export function buildRunPaths({ scriptDir, sessionId, outputDir, screenshotDir = 'screenshots' }) {
    const resolvedOutputDir = path.resolve(outputDir || `/tmp/wirebuddy-ui-lint-${sessionId}`);

    if (path.isAbsolute(screenshotDir)) {
        throw new Error('UI_LINT_SCREENSHOT_DIR must be a relative path');
    }

    const resolvedScreenshotDir = path.resolve(resolvedOutputDir, screenshotDir);
    const relativeScreenshotDir = path.relative(resolvedOutputDir, resolvedScreenshotDir);
    if (relativeScreenshotDir.startsWith('..') || path.isAbsolute(relativeScreenshotDir)) {
        throw new Error('UI_LINT_SCREENSHOT_DIR must stay inside UI_LINT_OUTPUT_DIR');
    }

    return {
        outputDir: resolvedOutputDir,
        screenshotDir: resolvedScreenshotDir,
        summaryPath: path.join(resolvedOutputDir, 'ui-lint-summary.json'),
        latestSummaryPath: path.join(scriptDir, 'ui-lint-summary.latest.json'),
    };
}

export function getBaseContextOptions(device, availableDevices) {
    if (device === 'mobile') {
        return { ...availableDevices['iPhone 13'] };
    }
    if (device === 'tablet') {
        return { ...availableDevices['iPad Pro 11'] };
    }
    if (device === 'large-desktop') {
        return { viewport: { width: 1600, height: 1100 } };
    }
    return { viewport: { width: 1440, height: 1100 } };
}

export function getAuthenticatedContextOptions(device, availableDevices, storageState) {
    return {
        ...getBaseContextOptions(device, availableDevices),
        storageState,
    };
}

export function getLoginFailureContextOptions(device, availableDevices) {
    return getBaseContextOptions(device, availableDevices);
}