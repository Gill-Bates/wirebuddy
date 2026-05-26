//
// app/static/js/components/retention-slider.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Generic retention slider component.
// Replaces duplicated TSDB/DNS/Speedtest/Backup retention slider code.
//

(function () {
    'use strict';

    const WB_DEBUG = window.WB_DEBUG === true;

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
    function RetentionSlider(config = {}) {
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

        if (!Array.isArray(values) || values.length === 0) {
            throw new Error('RetentionSlider: values must be a non-empty array');
        }

        const sliderValues = values.map((value) => {
            const normalized = Number(value);
            if (!Number.isFinite(normalized)) {
                throw new Error('RetentionSlider: values must contain only numeric entries');
            }
            return normalized;
        });

        for (let index = 1; index < sliderValues.length; index++) {
            if (sliderValues[index] < sliderValues[index - 1]) {
                throw new Error('RetentionSlider: values must be sorted in ascending order');
            }
        }

        const parsedDefaultIndex = Number.parseInt(String(defaultIndex), 10);
        const safeDefaultIndex = Number.isFinite(parsedDefaultIndex)
            ? Math.max(0, Math.min(sliderValues.length - 1, parsedDefaultIndex))
            : sliderValues.length - 1;

        const slider = document.getElementById(sliderId);
        const badge = document.getElementById(badgeId);

        if (!slider) {
            if (WB_DEBUG) {
                console.warn(`RetentionSlider: slider #${sliderId} not found`);
            }
            return null;
        }

        if (slider._wbRetentionSlider) {
            slider._wbRetentionSlider.destroy();
        }

        // Configure slider range
        slider.min = '0';
        slider.max = String(sliderValues.length - 1);
        slider.step = '1';

        let destroyed = false;
        let isSaving = false;
        let pendingDays = null;
        let committedDays = sliderValues[safeDefaultIndex];

        /**
         * Get index for a given days value.
         * @param {number} days
         * @returns {number}
         */
        function indexForDays(days) {
            const idx = sliderValues.indexOf(Number(days));
            return idx >= 0 ? idx : safeDefaultIndex;
        }

        /**
         * Get days value from slider index.
         * @param {number|string} rawValue
         * @returns {number}
         */
        function daysFromIndex(rawValue) {
            const parsed = Number.parseInt(String(rawValue), 10);
            const idx = Number.isFinite(parsed)
                ? Math.max(0, Math.min(sliderValues.length - 1, parsed))
                : safeDefaultIndex;
            return sliderValues[idx];
        }

        /**
         * Update badge display.
         * @param {number} days
         */
        function updateBadge(days) {
            const label = labelFormatter(days);
            slider.setAttribute('aria-valuetext', label);
            slider.setAttribute('aria-valuenow', String(days));

            if (!badge) return;

            badge.textContent = label;

            // Apply warning/normal class
            badge.classList.remove(warningClass, normalClass);
            badge.classList.add(days === warningValue ? warningClass : normalClass);
        }

        /**
         * Handle input event (while dragging).
         * @param {Event} e
         */
        function handleInput(e) {
            if (destroyed) return;
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
            if (destroyed) return;
            const days = daysFromIndex(e.target.value);

            if (typeof onChange === 'function') {
                onChange(days, e);
            }

            if (typeof onSave === 'function') {
                await persist(days);
            }
        }

        async function persist(days) {
            if (destroyed) return;

            if (isSaving) {
                pendingDays = days;
                return;
            }

            isSaving = true;
            const wasDisabled = slider.disabled;
            slider.disabled = true;

            try {
                await onSave(days);
                if (destroyed) return;
                committedDays = days;
                pendingDays = null;
            } catch (err) {
                if (WB_DEBUG) {
                    console.error(`RetentionSlider: save failed for ${sliderId}`, err);
                }
                if (!destroyed) {
                    setValue(committedDays);
                    pendingDays = null;
                }
            } finally {
                if (!destroyed) {
                    slider.disabled = wasDisabled;
                }
                isSaving = false;

                if (!destroyed && pendingDays !== null && pendingDays !== committedDays) {
                    const next = pendingDays;
                    pendingDays = null;
                    void persist(next);
                }
            }
        }

        // Bind events
        slider.addEventListener('input', handleInput, { passive: true });
        slider.addEventListener('change', handleChange);

        // Initialize current UI state.
        const initialDays = daysFromIndex(slider.value);
        slider.value = String(indexForDays(initialDays));
        committedDays = daysFromIndex(slider.value);
        updateBadge(committedDays);

        const controller = {
            /**
             * Set slider value by days.
             * @param {number} days
             */
            setValue(days) {
                if (destroyed) return;
                const idx = indexForDays(days);
                const normalizedDays = sliderValues[idx];
                slider.value = String(idx);
                committedDays = normalizedDays;
                pendingDays = null;
                updateBadge(normalizedDays);
            },

            /**
             * Get current days value.
             * @returns {number}
             */
            getValue() {
                return committedDays;
            },

            /**
             * Enable slider.
             */
            enable() {
                if (destroyed) return;
                slider.disabled = false;
            },

            /**
             * Disable slider.
             */
            disable() {
                if (destroyed) return;
                slider.disabled = true;
            },

            /**
             * Destroy instance and remove event listeners.
             */
            destroy() {
                if (destroyed) return;
                destroyed = true;
                pendingDays = null;
                slider.removeEventListener('input', handleInput);
                slider.removeEventListener('change', handleChange);
                if (slider._wbRetentionSlider === controller) {
                    slider._wbRetentionSlider = null;
                }
            },

            /**
             * Get the values array.
             * @returns {number[]}
             */
            getValues() {
                return [...sliderValues];
            }
        };

        slider._wbRetentionSlider = controller;
        return controller;
    }

    // Expose globally
    window.WB = window.WB || {};
    window.WB.RetentionSlider = RetentionSlider;
    window.RetentionSlider = RetentionSlider;
})();
