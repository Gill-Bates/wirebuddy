//
// app/static/js/core/format.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Locale-aware display formatting. The server sends UTC (ISO-8601 with Z, or epoch)
// and raw numbers; this module renders them in the browser's locale and time zone
// (locale argument undefined, no time zone option) so decimal and grouping
// separators, date order and clock follow the user. It also localises
// <time data-wb-format="date|time|datetime|..."> and
// <span data-wb-number="bytes|bandwidth|..." data-wb-value="..."> elements.
(function () {
    'use strict';
    if (window.WBFormat !== undefined) {
        return;
    }
    const PRESETS = {
        date: { year: 'numeric', month: 'short', day: 'numeric' },
        time: { hour: '2-digit', minute: '2-digit' },
        datetime: { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' },
        'date-short': { month: 'short', day: 'numeric' },
        'datetime-short': { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' },
        'time-seconds': { hour: '2-digit', minute: '2-digit', second: '2-digit' },
        'datetime-seconds': {
            year: 'numeric', month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
        },
    };
    const SIZE_UNITS = Object.freeze(['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB']);
    const DURATION_UNITS = [['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]];
    const NUMBER_PLACEHOLDER = '\u2013';
    // Formatters are immutable and the browser locale does not change during a page life.
    const formatterCache = new Map();
    function formatter(kind, options) {
        const key = `${kind}|${JSON.stringify(options)}`;
        let instance = formatterCache.get(key);
        if (instance === undefined) {
            instance = kind === 'date'
                ? new Intl.DateTimeFormat(undefined, options)
                : new Intl.NumberFormat(undefined, options);
            formatterCache.set(key, instance);
        }
        return instance;
    }
    /** The browser's resolved locale and IANA time zone (for Chart.js `locale` and diagnostics). */
    function resolved() {
        const { locale, timeZone } = new Intl.DateTimeFormat().resolvedOptions();
        return { locale, timeZone };
    }
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
    /** Format a UTC value as a preset kind (see PRESETS) in the browser locale and zone. */
    function format(value, kind, options) {
        const date = toDate(value);
        if (Number.isNaN(date.getTime())) return '';
        const preset = PRESETS[kind] || PRESETS.datetime;
        return formatter('date', Object.assign({}, preset, options)).format(date);
    }
    // null, undefined and blank strings are missing values; 0 and "0" are real zeros.
    function isMissing(value) {
        return value == null || (typeof value === 'string' && value.trim() === '');
    }
    /** Format a number in the browser locale; a missing value gives the placeholder. */
    function number(value, options) {
        if (isMissing(value)) return NUMBER_PLACEHOLDER;
        const n = Number(value);
        return Number.isFinite(n) ? formatter('number', options || {}).format(n) : '';
    }
    /** Format with exactly `digits` fraction digits (the locale decides the separators). */
    function fixed(value, digits) {
        const d = Math.max(0, Math.trunc(Number(digits) || 0));
        return number(value, { minimumFractionDigits: d, maximumFractionDigits: d });
    }
    /** Format a value that is already a percentage (12.5 means 12.5 %) with a locale percent sign. */
    function percent(value, digits) {
        if (isMissing(value)) return NUMBER_PLACEHOLDER;
        const n = Number(value);
        if (!Number.isFinite(n)) return '';
        const d = Math.max(0, Math.trunc(Number(digits === undefined ? 1 : digits) || 0));
        return number(n / 100, { style: 'percent', minimumFractionDigits: d, maximumFractionDigits: d });
    }
    /** Short compact form (1.2K / 1,2 Mio.) in the browser locale. */
    function compact(value, options) {
        return number(value, Object.assign({ notation: 'compact' }, options));
    }
    /**
     * Binary size with automatic unit scaling. `startUnit` is the unit of `value`
     * (name such as 'MB' or index into B..EB). Non-finite and non-positive values give "0 B".
     */
    function bytes(value, startUnit) {
        const n = Number(value);
        if (!Number.isFinite(n) || n <= 0) return `${number(0)} B`;
        const named = typeof startUnit === 'string' ? SIZE_UNITS.indexOf(startUnit.toUpperCase()) : startUnit;
        let unitIndex = Math.max(0, Math.min(Number.isInteger(named) ? named : 0, SIZE_UNITS.length - 1));
        let scaled = n;
        while (unitIndex < SIZE_UNITS.length - 1 && scaled >= 1024) {
            scaled /= 1024;
            unitIndex += 1;
        }
        while (unitIndex > 0 && scaled > 0 && scaled < 1) {
            scaled *= 1024;
            unitIndex -= 1;
        }
        const decimals = unitIndex === 0 ? 0 : 1;
        // Rounding can reach 1024 (1023.96 KB): carry into the next unit instead of showing it.
        if (unitIndex < SIZE_UNITS.length - 1 && Math.round(scaled * 10 ** decimals) / 10 ** decimals >= 1024) {
            scaled /= 1024;
            unitIndex += 1;
        }
        return `${number(scaled, { maximumFractionDigits: decimals })} ${SIZE_UNITS[unitIndex]}`;
    }
    /** Bandwidth given in Mbit/s, shown as Mbit/s or Gbit/s from 1000 upwards. */
    function bandwidth(valueMbit, gbitDigits, mbitDigits) {
        if (isMissing(valueMbit)) return NUMBER_PLACEHOLDER;
        const n = Number(valueMbit);
        if (!Number.isFinite(n)) return NUMBER_PLACEHOLDER;
        const gbit = n >= 1000;
        const first = gbitDigits === undefined ? 1 : gbitDigits;
        const digits = gbit ? first : (mbitDigits === undefined ? first : mbitDigits);
        return `${fixed(gbit ? n / 1000 : n, digits)} ${gbit ? 'Gbit/s' : 'Mbit/s'}`;
    }
    /** Duration in seconds as up to `maxParts` units (d, h, min, s), localised unit labels. */
    function duration(seconds, maxParts) {
        if (isMissing(seconds)) return NUMBER_PLACEHOLDER;
        const total = Math.floor(Number(seconds));
        if (!Number.isFinite(total) || total < 0) return '';
        const limit = Math.max(1, Math.trunc(Number(maxParts) || 2));
        const unitText = (n, unit) => number(n, { style: 'unit', unit, unitDisplay: 'narrow' });
        let rest = total;
        const parts = [];
        for (const [unit, size] of DURATION_UNITS) {
            const n = Math.floor(rest / size);
            rest -= n * size;
            if (n > 0 && parts.length < limit) parts.push(unitText(n, unit));
        }
        return parts.length > 0 ? parts.join(' ') : unitText(0, 'second');
    }
    /** Localised relative time ("5 minutes ago") for a UTC value. */
    function relative(value, options) {
        const date = toDate(value);
        if (Number.isNaN(date.getTime())) return '';
        const diffSec = Math.round((date.getTime() - Date.now()) / 1000);
        const [unit, size] = DURATION_UNITS.find(([, s]) => Math.abs(diffSec) >= s) || DURATION_UNITS[DURATION_UNITS.length - 1];
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
    const NUMBER_KINDS = {
        number: (v) => number(v),
        fixed: (v, digits) => fixed(v, digits === undefined ? 2 : digits),
        percent: (v, digits) => percent(v, digits),
        compact: (v) => compact(v),
        bytes: (v) => bytes(v),
        bandwidth: (v, digits) => bandwidth(v, digits),
        duration: (v) => duration(v),
    };
    /** Localise every [data-wb-number=kind][data-wb-value=raw][data-wb-digits] below root. */
    function localizeNumbers(root) {
        (root || document).querySelectorAll('[data-wb-number]').forEach((node) => {
            const render = NUMBER_KINDS[node.dataset.wbNumber];
            const raw = node.dataset.wbValue;
            if (render === undefined || raw === undefined || raw === '') return;
            const digits = node.dataset.wbDigits === undefined ? undefined : Number(node.dataset.wbDigits);
            const text = render(Number(raw), digits);
            if (text) node.textContent = text;
        });
    }
    window.WBFormat = Object.freeze({
        resolved, toDate, format, number, fixed, percent, compact, bytes, bandwidth, duration,
        relative, localizeTimes, localizeNumbers, SIZE_UNITS,
    });
    function localizeAll() {
        localizeTimes();
        localizeNumbers();
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', localizeAll);
    } else {
        localizeAll();
    }
})();
