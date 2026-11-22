//
// app/static/js/core/flags.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Country flag URLs. The server hands the directory URL of its locally served SVGs
// over in <body data-flag-base-url>; only a two-letter code is ever turned into a URL.
(function () {
    'use strict';

    const CODE_PATTERN = /^[a-z]{2}$/;

    function baseUrl() {
        const raw = String(document.body?.dataset.flagBaseUrl || '').trim().replace(/\/+$/, '');
        // Same-origin path or HTTPS URL only.
        return raw.startsWith('/') && !raw.startsWith('//') || raw.startsWith('https://') ? raw : '';
    }

    // Returns the flag image URL for a country code, or null for an invalid code.
    function url(countryCode) {
        const code = String(countryCode || '').trim().toLowerCase();
        const base = baseUrl();
        return CODE_PATTERN.test(code) && base ? `${base}/${code}.svg` : null;
    }

    window.WB = window.WB || {};
    window.WB.flags = Object.freeze({ url });
})();
