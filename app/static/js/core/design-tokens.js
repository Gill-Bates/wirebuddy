//
// app/static/js/core/design-tokens.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//
// Design tokens runtime - reads CSS custom properties as the single source of truth.
// Both the frontend and UI linter use these values.
//

(function () {
    'use strict';

    /**
     * Get a CSS custom property value from :root.
     * @param {string} name - Property name with -- prefix
     * @returns {string}
     */
    function getCSSVar(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    }

    /**
     * Parse a CSS value to pixels.
     * @param {string} value - CSS value (e.g., '1rem', '16px')
     * @returns {number}
     */
    function toPx(value) {
        if (!value) return 0;
        if (value.endsWith('px')) return parseFloat(value);
        if (value.endsWith('rem')) {
            const rootFontSize = parseFloat(getComputedStyle(document.documentElement).fontSize);
            return parseFloat(value) * rootFontSize;
        }
        if (value.endsWith('em')) {
            // Assume 1em = 16px for design token purposes
            return parseFloat(value) * 16;
        }
        return parseFloat(value) || 0;
    }

    /**
     * Parse a CSS time value to milliseconds.
     * @param {string} value - CSS time value (e.g., '200ms', '0.2s')
     * @returns {number}
     */
    function toMs(value) {
        if (!value) return 0;
        if (value.endsWith('ms')) return parseFloat(value);
        if (value.endsWith('s')) return parseFloat(value) * 1000;
        return parseFloat(value) || 0;
    }

    /**
     * Design tokens object with lazy-loaded values from CSS.
     */
    const DesignTokens = {
        // Spacing
        get spacing() {
            return {
                xs: toPx(getCSSVar('--wb-spacing-xs')),
                sm: toPx(getCSSVar('--wb-spacing-sm')),
                md: toPx(getCSSVar('--wb-spacing-md')),
                lg: toPx(getCSSVar('--wb-spacing-lg')),
                xl: toPx(getCSSVar('--wb-spacing-xl')),
            };
        },

        // Radius
        get radius() {
            return {
                none: 0,
                sm: toPx(getCSSVar('--wb-radius-sm')),
                md: toPx(getCSSVar('--wb-radius-md')),
                lg: toPx(getCSSVar('--wb-radius-lg')),
                pill: 9999,
            };
        },

        // Colors
        get colors() {
            return {
                danger: getCSSVar('--wb-danger'),
                warning: getCSSVar('--wb-warning'),
                success: getCSSVar('--wb-success'),
                info: getCSSVar('--wb-info'),
            };
        },

        // Typography
        get typography() {
            return {
                fontSans: getCSSVar('--wb-font-sans'),
                fontMono: getCSSVar('--wb-font-mono'),
                sizeXs: toPx(getCSSVar('--wb-font-size-xs')),
                sizeSm: toPx(getCSSVar('--wb-font-size-sm')),
                sizeBase: toPx(getCSSVar('--wb-font-size-base')),
                sizeLg: toPx(getCSSVar('--wb-font-size-lg')),
                sizeXl: toPx(getCSSVar('--wb-font-size-xl')),
            };
        },

        // Interaction
        get interaction() {
            return {
                touchTargetMin: toPx(getCSSVar('--wb-touch-target-min')),
                touchTargetComfortable: toPx(getCSSVar('--wb-touch-target-comfortable')),
                focusRingWidth: toPx(getCSSVar('--wb-focus-ring-width')),
            };
        },

        // Animation
        get animation() {
            return {
                fast: toMs(getCSSVar('--wb-transition-fast')),
                base: toMs(getCSSVar('--wb-transition-base')),
                slow: toMs(getCSSVar('--wb-transition-slow')),
            };
        },

        // Breakpoints
        get breakpoints() {
            return {
                sm: toPx(getCSSVar('--wb-breakpoint-sm')),
                md: toPx(getCSSVar('--wb-breakpoint-md')),
                lg: toPx(getCSSVar('--wb-breakpoint-lg')),
                xl: toPx(getCSSVar('--wb-breakpoint-xl')),
                xxl: toPx(getCSSVar('--wb-breakpoint-xxl')),
            };
        },

        // Component: Badge
        get badge() {
            return {
                paddingY: getCSSVar('--wb-badge-padding-y'),
                paddingX: getCSSVar('--wb-badge-padding-x'),
                radius: toPx(getCSSVar('--wb-badge-radius')),
                fontSize: getCSSVar('--wb-badge-font-size'),
                fontWeight: getCSSVar('--wb-badge-font-weight'),
            };
        },

        // Component: Card
        get card() {
            return {
                padding: toPx(getCSSVar('--wb-card-padding')),
                radius: toPx(getCSSVar('--wb-card-radius')),
                borderWidth: toPx(getCSSVar('--wb-card-border-width')),
            };
        },

        // Component: Modal
        get modal() {
            return {
                backdropBlur: toPx(getCSSVar('--wb-modal-backdrop-blur')),
                backdropOpacity: parseFloat(getCSSVar('--wb-modal-backdrop-opacity')),
                radius: toPx(getCSSVar('--wb-modal-radius')),
                padding: toPx(getCSSVar('--wb-modal-padding')),
            };
        },

        // Component: Form Controls
        get form() {
            return {
                inputHeight: toPx(getCSSVar('--wb-input-height')),
                inputRadius: toPx(getCSSVar('--wb-input-radius')),
                switchHeight: toPx(getCSSVar('--wb-switch-height')),
            };
        },

        // WCAG Contrast
        get wcag() {
            return {
                contrastAA: parseFloat(getCSSVar('--wb-contrast-aa-normal')) || 4.5,
                contrastAALarge: parseFloat(getCSSVar('--wb-contrast-aa-large')) || 3,
                contrastAAA: parseFloat(getCSSVar('--wb-contrast-aaa-normal')) || 7,
                contrastAAALarge: parseFloat(getCSSVar('--wb-contrast-aaa-large')) || 4.5,
            };
        },

        /**
         * Get current breakpoint name based on viewport width.
         * @returns {'base'|'sm'|'md'|'lg'|'xl'|'xxl'}
         */
        getCurrentBreakpoint() {
            const width = window.innerWidth;
            const bp = this.breakpoints;
            if (width >= bp.xxl) return 'xxl';
            if (width >= bp.xl) return 'xl';
            if (width >= bp.lg) return 'lg';
            if (width >= bp.md) return 'md';
            if (width >= bp.sm) return 'sm';
            return 'base';
        },

        /**
         * Check if reduced motion is preferred.
         * @returns {boolean}
         */
        prefersReducedMotion() {
            return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        },

        /**
         * Get all tokens as a plain object (for serialization/debugging).
         * @returns {Object}
         */
        toJSON() {
            return {
                spacing: this.spacing,
                radius: this.radius,
                colors: this.colors,
                typography: this.typography,
                interaction: this.interaction,
                animation: this.animation,
                breakpoints: this.breakpoints,
                badge: this.badge,
                card: this.card,
                modal: this.modal,
                form: this.form,
                wcag: this.wcag,
            };
        },
    };

    // Expose globally
    window.DesignTokens = DesignTokens;
})();
