//
// tools/ui-lint/lib/design-tokens.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Design tokens reader for the UI linter.
// Extracts tokens from the CSS source of truth.
//

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TOKENS_CSS_PATH = path.resolve(__dirname, '../../../app/static/css/core/tokens.css');

/**
 * Parse CSS custom property declarations from CSS content.
 * @param {string} css - CSS content
 * @returns {Map<string, string>}
 */
function parseCSSVariables(css) {
    const variables = new Map();
    // Match --variable: value; patterns
    const regex = /--([a-zA-Z0-9-]+):\s*([^;]+);/g;
    let match;
    while ((match = regex.exec(css)) !== null) {
        variables.set(`--${match[1]}`, match[2].trim());
    }
    return variables;
}

/**
 * Convert CSS value to pixels.
 * @param {string} value - CSS value
 * @param {number} [baseFontSize=16] - Base font size for rem/em conversion
 * @returns {number}
 */
function toPx(value, baseFontSize = 16) {
    if (!value) return 0;
    const trimmed = value.trim();
    if (trimmed.endsWith('px')) return parseFloat(trimmed);
    if (trimmed.endsWith('rem')) return parseFloat(trimmed) * baseFontSize;
    if (trimmed.endsWith('em')) return parseFloat(trimmed) * baseFontSize;
    return parseFloat(trimmed) || 0;
}

/**
 * Convert CSS time to milliseconds.
 * @param {string} value - CSS time value
 * @returns {number}
 */
function toMs(value) {
    if (!value) return 0;
    const trimmed = value.trim();
    if (trimmed.endsWith('ms')) return parseFloat(trimmed);
    if (trimmed.endsWith('s')) return parseFloat(trimmed) * 1000;
    return parseFloat(trimmed) || 0;
}

/**
 * Load and parse design tokens from CSS.
 * @returns {Object}
 */
export function loadDesignTokens() {
    let css;
    try {
        css = fs.readFileSync(TOKENS_CSS_PATH, 'utf-8');
    } catch (err) {
        console.warn(`Warning: Could not load design tokens from ${TOKENS_CSS_PATH}`);
        return getDefaultTokens();
    }

    const vars = parseCSSVariables(css);

    const get = (name) => vars.get(name) || '';
    const getPx = (name) => toPx(get(name));
    const getMs = (name) => toMs(get(name));
    const getFloat = (name) => parseFloat(get(name)) || 0;

    return {
        spacing: {
            xs: getPx('--wb-spacing-xs'),
            sm: getPx('--wb-spacing-sm'),
            md: getPx('--wb-spacing-md'),
            lg: getPx('--wb-spacing-lg'),
            xl: getPx('--wb-spacing-xl'),
        },
        radius: {
            none: 0,
            sm: getPx('--wb-radius-sm'),
            md: getPx('--wb-radius-md'),
            lg: getPx('--wb-radius-lg'),
            pill: 9999,
        },
        colors: {
            danger: get('--wb-danger'),
            warning: get('--wb-warning'),
            success: get('--wb-success'),
            info: get('--wb-info'),
        },
        interaction: {
            touchTargetMin: getPx('--wb-touch-target-min'),
            touchTargetComfortable: getPx('--wb-touch-target-comfortable'),
            focusRingWidth: getPx('--wb-focus-ring-width'),
        },
        animation: {
            fast: getMs('--wb-transition-fast'),
            base: getMs('--wb-transition-base'),
            slow: getMs('--wb-transition-slow'),
        },
        breakpoints: {
            sm: getPx('--wb-breakpoint-sm'),
            md: getPx('--wb-breakpoint-md'),
            lg: getPx('--wb-breakpoint-lg'),
            xl: getPx('--wb-breakpoint-xl'),
            xxl: getPx('--wb-breakpoint-xxl'),
        },
        badge: {
            paddingY: get('--wb-badge-padding-y'),
            paddingX: get('--wb-badge-padding-x'),
            radius: getPx('--wb-badge-radius'),
            fontSize: get('--wb-badge-font-size'),
            fontWeight: get('--wb-badge-font-weight'),
        },
        card: {
            padding: getPx('--wb-card-padding'),
            radius: getPx('--wb-card-radius'),
            borderWidth: getPx('--wb-card-border-width'),
        },
        modal: {
            backdropBlur: getPx('--wb-modal-backdrop-blur'),
            backdropOpacity: getFloat('--wb-modal-backdrop-opacity'),
            radius: getPx('--wb-modal-radius'),
            padding: getPx('--wb-modal-padding'),
        },
        form: {
            inputHeight: getPx('--wb-input-height'),
            inputRadius: getPx('--wb-input-radius'),
            switchHeight: getPx('--wb-switch-height'),
        },
        wcag: {
            contrastAA: getFloat('--wb-contrast-aa-normal') || 4.5,
            contrastAALarge: getFloat('--wb-contrast-aa-large') || 3,
            contrastAAA: getFloat('--wb-contrast-aaa-normal') || 7,
            contrastAAALarge: getFloat('--wb-contrast-aaa-large') || 4.5,
        },
    };
}

/**
 * Default tokens if CSS file cannot be loaded.
 * @returns {Object}
 */
function getDefaultTokens() {
    return {
        spacing: { xs: 4, sm: 8, md: 16, lg: 24, xl: 32 },
        radius: { none: 0, sm: 6, md: 12, lg: 16, pill: 9999 },
        colors: { danger: '#c53a2f', warning: '#b7791f', success: '#2f855a', info: '#3182ce' },
        interaction: { touchTargetMin: 44, touchTargetComfortable: 48, focusRingWidth: 3 },
        animation: { fast: 150, base: 200, slow: 300 },
        breakpoints: { sm: 576, md: 768, lg: 992, xl: 1200, xxl: 1400 },
        badge: { paddingY: '0.35em', paddingX: '0.65em', radius: 6, fontSize: '0.75em', fontWeight: '600' },
        card: { padding: 24, radius: 12, borderWidth: 1 },
        modal: { backdropBlur: 4, backdropOpacity: 0.5, radius: 16, padding: 24 },
        form: { inputHeight: 38, inputRadius: 6, switchHeight: 24 },
        wcag: { contrastAA: 4.5, contrastAALarge: 3, contrastAAA: 7, contrastAAALarge: 4.5 },
    };
}

// Export loaded tokens as a singleton
export const tokens = loadDesignTokens();
