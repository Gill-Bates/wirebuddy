//
// app/static/js/components/retention-slider.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//
// Generic retention slider component.
// Replaces duplicated TSDB/DNS/Speedtest/Backup retention slider code.
//

(function () {
    'use strict';

    /**
     * Default retention values (days).
     * 0 = disabled/no logs
     */
    const DEFAULT_VALUES = [0, 7, 30, 90, 180, 365];

    /**
     * Default label formatter.
     * @param {number} days
     * @returns {string}
     */
    function defaultLabelFormatter(days) {
        const n = Number(days);
        if (n === 0) return 'No Logs';
        if (n === 365) return '1 Year';
        return `${n} Days`;
    }

    /**
     * Create a retention slider instance.
     *
     * @param {Object} config
     * @param {string} config.sliderId - Slider input element ID
     * @param {string} config.badgeId - Badge/label element ID
     * @param {number[]} [config.values] - Array of retention day values (default: [0, 7, 30, 90, 180, 365])
     * @param {Function} [config.labelFormatter] - Custom label formatter (days) => string
     * @param {number} [config.defaultIndex] - Default slider index if value not found
     * @param {number} [config.warningValue] - Value that triggers warning badge (default: 0)
     * @param {string} [config.warningClass] - Warning badge class (default: 'text-bg-danger')
     * @param {string} [config.normalClass] - Normal badge class (default: 'text-bg-secondary')
     * @param {Function} [config.onInput] - Callback on input (while dragging)
     * @param {Function} [config.onChange] - Callback on change (when released)
     * @param {Function} [config.onSave] - Async save callback (days) => Promise
     * @returns {Object} - Slider controller
     *
     * @example
     * const tsdbSlider = RetentionSlider({
     *     sliderId: 'tsdb-retention-slider',
     *     badgeId: 'tsdb-retention-value',
     *     defaultIndex: 5,
     *     onSave: async (days) => {
     *         await api('PUT', '/api/tsdb/retention', { retention_days: days });
     *     }
     * });
     * tsdbSlider.setValue(30);
     */
    function RetentionSlider(config) {
        const {
            sliderId,
            badgeId,
            values = DEFAULT_VALUES,
            labelFormatter = defaultLabelFormatter,
            defaultIndex = values.length - 1,
            warningValue = 0,
            warningClass = 'text-bg-danger',
            normalClass = 'text-bg-secondary',
            onInput,
            onChange,
            onSave
        } = config;

        const slider = document.getElementById(sliderId);
        const badge = document.getElementById(badgeId);

        if (!slider) {
            console.warn(`RetentionSlider: slider #${sliderId} not found`);
            return null;
        }

        // Configure slider range
        slider.min = '0';
        slider.max = String(values.length - 1);
        slider.step = '1';

        let isSaving = false;

        /**
         * Get index for a given days value.
         * @param {number} days
         * @returns {number}
         */
        function indexForDays(days) {
            const idx = values.indexOf(Number(days));
            return idx >= 0 ? idx : defaultIndex;
        }

        /**
         * Get days value from slider index.
         * @param {number|string} rawValue
         * @returns {number}
         */
        function daysFromIndex(rawValue) {
            const parsed = Number.parseInt(String(rawValue), 10);
            const idx = Number.isFinite(parsed)
                ? Math.max(0, Math.min(values.length - 1, parsed))
                : defaultIndex;
            return values[idx];
        }

        /**
         * Update badge display.
         * @param {number} days
         */
        function updateBadge(days) {
            if (!badge) return;

            badge.textContent = labelFormatter(days);

            // Apply warning/normal class
            badge.classList.remove(warningClass, normalClass);
            badge.classList.add(days === warningValue ? warningClass : normalClass);
        }

        /**
         * Handle input event (while dragging).
         * @param {Event} e
         */
        function handleInput(e) {
            const days = daysFromIndex(e.target.value);
            updateBadge(days);
            if (typeof onInput === 'function') {
                onInput(days, e);
            }
        }

        /**
         * Handle change event (when released).
         * @param {Event} e
         */
        async function handleChange(e) {
            const days = daysFromIndex(e.target.value);

            if (typeof onChange === 'function') {
                onChange(days, e);
            }

            if (typeof onSave === 'function' && !isSaving) {
                isSaving = true;
                slider.disabled = true;
                try {
                    await onSave(days);
                } catch (err) {
                    console.error(`RetentionSlider: save failed for ${sliderId}`, err);
                } finally {
                    slider.disabled = false;
                    isSaving = false;
                }
            }
        }

        // Bind events
        slider.addEventListener('input', handleInput);
        slider.addEventListener('change', handleChange);

        // Public API
        return {
            /**
             * Set slider value by days.
             * @param {number} days
             */
            setValue(days) {
                const idx = indexForDays(days);
                slider.value = String(idx);
                updateBadge(days);
            },

            /**
             * Get current days value.
             * @returns {number}
             */
            getValue() {
                return daysFromIndex(slider.value);
            },

            /**
             * Enable slider.
             */
            enable() {
                slider.disabled = false;
            },

            /**
             * Disable slider.
             */
            disable() {
                slider.disabled = true;
            },

            /**
             * Destroy instance and remove event listeners.
             */
            destroy() {
                slider.removeEventListener('input', handleInput);
                slider.removeEventListener('change', handleChange);
            },

            /**
             * Get the values array.
             * @returns {number[]}
             */
            getValues() {
                return [...values];
            }
        };
    }

    // Expose globally
    window.RetentionSlider = RetentionSlider;
})();
