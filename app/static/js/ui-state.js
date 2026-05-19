//
// app/static/js/ui-state.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Central UI state management helpers.
// All DOM state changes should flow through these functions.
//

(function () {
    'use strict';

    /**
     * Show an element by removing .is-hidden and hidden attribute.
     * @param {Element|null} el
     */
    function showElement(el) {
        if (!el) return;
        el.classList.remove('is-hidden');
        el.hidden = false;
    }

    /**
     * Hide an element by adding .is-hidden and hidden attribute.
     * @param {Element|null} el
     */
    function hideElement(el) {
        if (!el) return;
        el.classList.add('is-hidden');
        el.hidden = true;
    }

    /**
     * Toggle loading state with aria-busy.
     * @param {Element|null} el
     * @param {boolean} state
     */
    function setLoading(el, state) {
        if (!el) return;
        el.classList.toggle('is-loading', !!state);
        if (state) {
            el.setAttribute('aria-busy', 'true');
            return;
        }
        el.removeAttribute('aria-busy');
    }

    /**
     * Enable an element (remove disabled attribute and .is-disabled class).
     * @param {Element|null} el
     */
    function enableElement(el) {
        if (!el) return;
        el.disabled = false;
        el.classList.remove('is-disabled');
        el.removeAttribute('aria-disabled');
    }

    /**
     * Disable an element (set disabled attribute and .is-disabled class).
     * @param {Element|null} el
     */
    function disableElement(el) {
        if (!el) return;
        el.disabled = true;
        el.classList.add('is-disabled');
        el.setAttribute('aria-disabled', 'true');
    }

    /**
     * Safely set text content of an element.
     * @param {Element|null} el
     * @param {string} text
     */
    function setText(el, text) {
        if (!el) return;
        el.textContent = text ?? '';
    }

    /**
     * Set element busy state with spinner icon swap.
     * @param {Element|null} el - Button or container element
     * @param {boolean} busy
     * @param {string} [busyText] - Optional text while busy
     */
    function setBusy(el, busy, busyText) {
        if (!el) return;
        setLoading(el, busy);
        disableElement(el);

        if (busy) {
            el.dataset.originalText = el.textContent || '';
            if (busyText) el.textContent = busyText;
        } else {
            enableElement(el);
            if (el.dataset.originalText) {
                el.textContent = el.dataset.originalText;
                delete el.dataset.originalText;
            }
        }
    }

    /**
     * Toggle visibility based on condition.
     * @param {Element|null} el
     * @param {boolean} visible
     */
    function toggleVisible(el, visible) {
        if (visible) {
            showElement(el);
        } else {
            hideElement(el);
        }
    }

    /**
     * Set badge class based on status (success/warning/danger).
     * @param {Element|null} el
     * @param {'success'|'warning'|'danger'|'secondary'} status
     */
    function setBadgeStatus(el, status) {
        if (!el) return;
        el.classList.remove('text-bg-success', 'text-bg-warning', 'text-bg-danger', 'text-bg-secondary');
        el.classList.add(`text-bg-${status}`);
    }

    // Expose globally
    window.showElement = showElement;
    window.hideElement = hideElement;
    window.setLoading = setLoading;
    window.enableElement = enableElement;
    window.disableElement = disableElement;
    window.setText = setText;
    window.setBusy = setBusy;
    window.toggleVisible = toggleVisible;
    window.setBadgeStatus = setBadgeStatus;
})();