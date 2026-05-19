//
// tools/ui-lint/lib/device-matrix.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Device matrix configuration for mobile testing.
// Uses Playwright's built-in device descriptors.
//

import { devices } from 'playwright';

/**
 * Device categories for organized testing.
 */
export const DEVICE_CATEGORIES = {
    desktop: ['Desktop Chrome', 'Desktop Firefox', 'Desktop Safari'],
    mobile: ['iPhone 15', 'iPhone SE', 'Pixel 7'],
    tablet: ['iPad Pro 11', 'iPad Mini'],
    foldable: ['Galaxy Z Fold 5'],
};

/**
 * Default test matrix - covers common breakpoints.
 */
export const DEFAULT_MATRIX = [
    'Desktop Chrome',
    'iPhone 15',
    'iPad Pro 11',
];

/**
 * Extended test matrix - comprehensive coverage.
 */
export const EXTENDED_MATRIX = [
    'Desktop Chrome',
    'Desktop Safari',
    'iPhone 15',
    'iPhone SE',
    'Pixel 7',
    'iPad Pro 11',
    'iPad Mini',
];

/**
 * Custom viewport configurations (not in Playwright devices).
 */
export const CUSTOM_VIEWPORTS = {
    'Desktop 1080p': {
        viewport: { width: 1920, height: 1080 },
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        deviceScaleFactor: 1,
        isMobile: false,
        hasTouch: false,
    },
    'Desktop 768': {
        viewport: { width: 768, height: 1024 },
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        deviceScaleFactor: 1,
        isMobile: false,
        hasTouch: false,
    },
    'Desktop 576': {
        viewport: { width: 576, height: 900 },
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        deviceScaleFactor: 1,
        isMobile: false,
        hasTouch: false,
    },
};

/**
 * Get device configuration by name.
 * @param {string} name - Device name
 * @returns {Object|null}
 */
export function getDevice(name) {
    // Check custom viewports first
    if (CUSTOM_VIEWPORTS[name]) {
        return { name, ...CUSTOM_VIEWPORTS[name] };
    }

    // Check Playwright devices
    const device = devices[name];
    if (device) {
        return { name, ...device };
    }

    console.warn(`Unknown device: ${name}`);
    return null;
}

/**
 * Get all devices for a matrix.
 * @param {string[]} matrix - Device names
 * @returns {Object[]}
 */
export function getDevices(matrix) {
    return matrix.map(getDevice).filter(Boolean);
}

/**
 * Get devices by category.
 * @param {string} category - Category name
 * @returns {Object[]}
 */
export function getDevicesByCategory(category) {
    const names = DEVICE_CATEGORIES[category] || [];
    return getDevices(names);
}

/**
 * Resolve matrix from environment or default.
 * UI_LINT_DEVICE_MATRIX=iPhone 15,iPad Pro 11
 * @returns {Object[]}
 */
export function resolveDeviceMatrix() {
    const envMatrix = process.env.UI_LINT_DEVICE_MATRIX;

    if (envMatrix) {
        const names = envMatrix.split(',').map(s => s.trim());
        return getDevices(names);
    }

    // Check for extended mode
    if (process.env.UI_LINT_EXTENDED_MATRIX === 'true') {
        return getDevices(EXTENDED_MATRIX);
    }

    return getDevices(DEFAULT_MATRIX);
}

/**
 * Get breakpoint-specific viewports for responsive testing.
 * @returns {Object[]}
 */
export function getBreakpointViewports() {
    return [
        { name: 'base (320px)', viewport: { width: 320, height: 568 }, isMobile: true },
        { name: 'sm (576px)', viewport: { width: 576, height: 900 }, isMobile: false },
        { name: 'md (768px)', viewport: { width: 768, height: 1024 }, isMobile: false },
        { name: 'lg (992px)', viewport: { width: 992, height: 768 }, isMobile: false },
        { name: 'xl (1200px)', viewport: { width: 1200, height: 900 }, isMobile: false },
        { name: 'xxl (1400px)', viewport: { width: 1400, height: 900 }, isMobile: false },
    ];
}

/**
 * Check if a device is mobile.
 * @param {Object} device
 * @returns {boolean}
 */
export function isMobileDevice(device) {
    return device.isMobile === true;
}

/**
 * Check if a device is iOS.
 * @param {Object} device
 * @returns {boolean}
 */
export function isIOSDevice(device) {
    return device.name?.includes('iPhone') ||
        device.name?.includes('iPad') ||
        device.userAgent?.includes('iPhone') ||
        device.userAgent?.includes('iPad');
}

/**
 * Check if a device is a tablet.
 * @param {Object} device
 * @returns {boolean}
 */
export function isTablet(device) {
    return device.name?.includes('iPad') ||
        device.name?.includes('Galaxy Tab') ||
        (device.viewport?.width >= 768 && device.isMobile);
}
