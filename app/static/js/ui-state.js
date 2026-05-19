(function () {
    'use strict';

    function showElement(el) {
        if (!el) return;
        el.classList.remove('is-hidden');
        el.hidden = false;
    }

    function hideElement(el) {
        if (!el) return;
        el.classList.add('is-hidden');
        el.hidden = true;
    }

    function setLoading(el, state) {
        if (!el) return;
        el.classList.toggle('is-loading', !!state);
        if (state) {
            el.setAttribute('aria-busy', 'true');
            return;
        }
        el.removeAttribute('aria-busy');
    }

    window.showElement = showElement;
    window.hideElement = hideElement;
    window.setLoading = setLoading;
})();