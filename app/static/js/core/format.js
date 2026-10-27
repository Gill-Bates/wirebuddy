//
// app/static/js/core/format.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Locale-aware display formatting. The server sends UTC (ISO-8601 with Z, or epoch);
// this module renders it in the browser's locale and time zone (locale argument
// undefined) and localises <time data-wb-format="date|time|datetime"> elements.

(function () {
    'use strict';

    if (window.WBFormat !== undefined) {
        return;
    }

    const PRESETS = {
        date: { year: 'numeric', month: 'short', day: 'numeric' },
        time: { hour: '2-digit', minute: '2-digit' },
        datetime: { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' },
    };

    function toDate(value) {
        if (value instanceof Date) return value;
        if (typeof value === 'number') return new Date(value < 1e12 ? value * 1000 : value);
        if (typeof value === 'string' && value !== '') {
            // A timestamp without offset is UTC by the storage contract, not browser-local.
            const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value);
            const looksLikeDateTime = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(value);
            return new Date(looksLikeDateTime && !hasZone ? value.replace(' ', 'T') + 'Z' : value);
        }
        return new Date(NaN);
    }

    /** Format a UTC value as 'date', 'time' or 'datetime' in the browser locale and zone. */
    function format(value, kind, options) {
        const date = toDate(value);
        if (Number.isNaN(date.getTime())) return '';
        const preset = PRESETS[kind] || PRESETS.datetime;
        return new Intl.DateTimeFormat(undefined, Object.assign({}, preset, options)).format(date);
    }

    /** Format a number in the browser locale. */
    function number(value, options) {
        const n = Number(value);
        return Number.isFinite(n) ? new Intl.NumberFormat(undefined, options).format(n) : '';
    }

    /** Localised relative time ("5 minutes ago") for a UTC value. */
    function relative(value, options) {
        const date = toDate(value);
        if (Number.isNaN(date.getTime())) return '';
        const diffSec = Math.round((date.getTime() - Date.now()) / 1000);
        const units = [['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]];
        const [unit, size] = units.find(([, s]) => Math.abs(diffSec) >= s) || units[units.length - 1];
        return new Intl.RelativeTimeFormat(undefined, Object.assign({ numeric: 'auto' }, options))
            .format(Math.trunc(diffSec / size), unit);
    }

    /** Replace the text of every <time data-wb-format> below root with its localised form. */
    function localizeTimes(root) {
        (root || document).querySelectorAll('time[data-wb-format]').forEach((node) => {
            const text = format(node.getAttribute('datetime'), node.dataset.wbFormat);
            if (text) {
                node.textContent = text;
                node.title = toDate(node.getAttribute('datetime')).toISOString();
            }
        });
    }

    window.WBFormat = Object.freeze({ format, number, relative, localizeTimes, toDate });

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => localizeTimes());
    } else {
        localizeTimes();
    }
})();
