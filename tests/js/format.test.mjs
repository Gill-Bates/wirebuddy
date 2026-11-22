//
// tests/js/format.test.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Run: node --test "tests/js/*.test.mjs"
// The browser's locale and time zone are simulated by the process environment
// (LC_ALL, TZ): every case runs app/static/js/core/format.js in a child process.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const JS_DIR = join(ROOT, 'app', 'static', 'js');
const FORMAT_JS = join(JS_DIR, 'core', 'format.js');

// Evaluates format.js against a minimal DOM and prints the JSON result of `expr`.
const PROBE = `
const fs = require('fs');
const vm = require('vm');
const nodes = JSON.parse(process.env.WB_NODES || '[]').map((n) => ({
    ...n, textContent: '', title: '',
    getAttribute(name) { return name === 'datetime' ? this.datetime : null; },
}));
const window = {};
const document = {
    readyState: 'complete',
    addEventListener() {},
    querySelectorAll(sel) { return nodes.filter((n) => sel.startsWith('time') ? n.tag === 'time' : n.tag !== 'time'); },
};
vm.runInNewContext(fs.readFileSync(process.env.WB_FORMAT_JS, 'utf8'), { window, document, Intl, Date, Number, Math, JSON, Object });
const F = window.WBFormat;
const out = eval(process.env.WB_EXPR);
console.log(JSON.stringify(out));
`;

function run(expr, { locale, tz = 'UTC', nodes } = {}) {
    const env = {
        PATH: process.env.PATH,
        LC_ALL: locale,
        LANG: locale,
        TZ: tz,
        WB_FORMAT_JS: FORMAT_JS,
        WB_EXPR: expr,
        WB_NODES: JSON.stringify(nodes || []),
    };
    const result = spawnSync(process.execPath, ['-e', PROBE], { env, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
}

const DE = { locale: 'de_DE.UTF-8', tz: 'Europe/Berlin' };
const US = { locale: 'en_US.UTF-8', tz: 'America/New_York' };
const FR = { locale: 'fr_FR.UTF-8', tz: 'Europe/Paris' };

test('resolved() reports the browser locale and time zone', () => {
    assert.deepEqual(run('F.resolved()', DE), { locale: 'de-DE', timeZone: 'Europe/Berlin' });
    assert.deepEqual(run('F.resolved()', US), { locale: 'en-US', timeZone: 'America/New_York' });
});

test('the same UTC instant renders as different wall-clock time per time zone', () => {
    const expr = "F.format('2026-01-15T12:00:00Z', 'time')";
    const berlin = run(expr, DE);
    const newYork = run(expr, US);
    assert.match(berlin, /^13:00/);
    assert.match(newYork, /^07:00/);
});

test('a summer-time instant follows the zone offset of that date', () => {
    assert.match(run("F.format('2026-07-15T12:00:00Z', 'time')", DE), /^14:00/);
    assert.match(run("F.format('2026-07-15T12:00:00Z', 'time')", US), /^08:00/);
});

test('date order and month names follow the locale', () => {
    const expr = "F.format('2026-03-05T12:00:00Z', 'date')";
    assert.notEqual(run(expr, DE), run(expr, US));
    assert.match(run(expr, DE), /^5\. /);
    assert.match(run(expr, US), /^Mar 5, 2026$/);
});

test('zone-less timestamps are UTC, epoch seconds and Dates are accepted', () => {
    const expr = "[F.format('2026-01-15 12:00:00', 'time'), F.format(1768478400, 'time'), F.format(new Date(Date.UTC(2026, 0, 15, 12)), 'time'), F.format('nonsense', 'time')]";
    const [zoneless, epoch, date, invalid] = run(expr, DE);
    assert.match(zoneless, /^13:00/);
    assert.match(epoch, /^13:00/);
    assert.match(date, /^13:00/);
    assert.equal(invalid, '');
});

test('datetime presets cover short, seconds and caller options', () => {
    const [short, seconds, custom] = run(
        "[F.format('2026-01-15T12:34:56Z', 'datetime-short'), F.format('2026-01-15T12:34:56Z', 'time-seconds'), F.format('2026-01-15T12:34:56Z', 'date-short', { day: '2-digit' })]",
        US,
    );
    assert.match(short, /Jan 15/);
    assert.match(short, /07:34/);
    assert.match(seconds, /^07:34:56/);
    assert.match(custom, /Jan 15/);
});

test('decimal and grouping separators follow the locale', () => {
    const expr = '[F.number(1234567.891), F.fixed(1234.5, 2), F.fixed(0.5, 1)]';
    assert.deepEqual(run(expr, DE), ['1.234.567,891', '1.234,50', '0,5']);
    assert.deepEqual(run(expr, US), ['1,234,567.891', '1,234.50', '0.5']);
    const [grouped] = run(expr, FR);
    assert.match(grouped, /^1\s234\s567,891$/u);
});

test('non-finite numbers render as empty text', () => {
    assert.deepEqual(run("[F.number(NaN), F.fixed('x', 2), F.percent('x')]", DE), ['', '', '']);
});

test('missing values give the placeholder, a real zero stays a zero', () => {
    const missing = "[null, undefined, '', '  '].flatMap((v) => [F.number(v), F.fixed(v, 2), F.percent(v), F.compact(v), F.bandwidth(v), F.duration(v)])";
    assert.deepEqual(run(missing, US), Array(24).fill('\u2013'));
    assert.deepEqual(run('[F.number(0), F.number("0"), F.fixed(0, 2), F.fixed("0", 1), F.percent(0), F.percent("0")]', US),
        ['0', '0', '0.00', '0.0', '0.0%', '0.0%']);
    assert.deepEqual(run('[F.bandwidth(0, 1, 1), F.bandwidth("0", 1, 1), F.duration(0), F.duration("0"), F.bytes(0)]', US),
        ['0.0 Mbit/s', '0.0 Mbit/s', '0s', '0s', '0 B']);
});
test('percent uses the locale percent sign and separator', () => {
    assert.match(run('F.percent(12.5)', DE), /^12,5\s%$/u);
    assert.equal(run('F.percent(12.5)', US), '12.5%');
    assert.equal(run('F.percent(7, 0)', US), '7%');
});

test('compact numbers follow the locale', () => {
    assert.equal(run('F.compact(1234)', US), '1.2K');
    assert.match(run('F.compact(1500000)', DE), /^1,5\s?Mio\./u);
});

test('bytes scale in binary steps with locale separators', () => {
    assert.equal(run('F.bytes(1536)', DE), '1,5 KB');
    assert.equal(run('F.bytes(1536)', US), '1.5 KB');
    assert.equal(run('F.bytes(0)', US), '0 B');
    assert.equal(run('F.bytes(512)', US), '512 B');
    assert.equal(run("F.bytes(2048, 'MB')", US), '2 GB');
    assert.equal(run("F.bytes(0.5, 'GB')", US), '512 MB');
    assert.equal(run('F.bytes(1024 * 1024 * 1024 * 1.25)', DE), '1,3 GB');
});

test('bytes carry a rounding overflow into the next unit', () => {
    assert.equal(run('F.bytes(1024 * 1024 - 1)', US), '1 MB');
});

test('bandwidth switches to Gbit/s and keeps the requested digits', () => {
    assert.equal(run('F.bandwidth(123.456, 1, 2)', DE), '123,46 Mbit/s');
    assert.equal(run('F.bandwidth(2500)', DE), '2,5 Gbit/s');
    assert.equal(run('F.bandwidth(2500)', US), '2.5 Gbit/s');
    assert.equal(run("F.bandwidth('x')", US), '\u2013');
});

test('duration uses localised unit labels and the requested part count', () => {
    const [de, us] = [run('F.duration(93784)', DE), run('F.duration(93784)', US)];
    assert.match(de, /^1\s?T\s?2/u);
    assert.match(us, /^1d\s2h$/u);
    assert.match(run('F.duration(93784, 4)', US), /^1d\s2h\s3m\s4s$/u);
    assert.match(run('F.duration(0)', US), /^0s$/u);
    assert.equal(run('F.duration(-1)', US), '');
});

test('localizeTimes rewrites <time> elements and sets a UTC title', () => {
    const nodes = [{ tag: 'time', datetime: '2026-01-15T12:00:00Z', dataset: { wbFormat: 'time' } }];
    const expr = 'F.localizeTimes(), nodes.map((n) => [n.textContent, n.title])';
    const [[text, title]] = run(`(${expr})`, { ...DE, nodes });
    assert.match(text, /^13:00/);
    assert.equal(title, '2026-01-15T12:00:00.000Z');
});

test('localizeNumbers renders raw data-wb-value attributes per locale', () => {
    const nodes = [
        { tag: 'span', dataset: { wbNumber: 'bandwidth', wbValue: '1500', wbDigits: '2' } },
        { tag: 'span', dataset: { wbNumber: 'bytes', wbValue: '1536' } },
        { tag: 'span', dataset: { wbNumber: 'unknown', wbValue: '1' } },
    ];
    const expr = '(F.localizeNumbers(), nodes.map((n) => n.textContent))';
    assert.deepEqual(run(expr, { ...DE, nodes }), ['1,50 Gbit/s', '1,5 KB', '']);
    assert.deepEqual(run(expr, { ...US, nodes }), ['1.50 Gbit/s', '1.5 KB', '']);
});

// Static guard: nothing in first-party JS may pin a locale, a time zone or a separator.
function listJs(dir) {
    return readdirSync(dir).flatMap((name) => {
        const path = join(dir, name);
        return statSync(path).isDirectory() ? listJs(path) : (name.endsWith('.js') ? [path] : []);
    });
}

const SOURCES = listJs(JS_DIR).map((path) => [relative(JS_DIR, path), readFileSync(path, 'utf8')]);

test('no first-party JS pins a locale tag or a time zone', () => {
    const patterns = [
        [/['"`][a-z]{2,3}-[A-Z]{2}['"`]/, 'locale tag literal'],
        [/\btimeZone\s*:\s*['"`]/, 'time zone literal'],
        [/\b(?:Europe|America|Asia|Australia|Africa|Pacific)\/[A-Z][A-Za-z_]+/, 'IANA zone name'],
        [/\b(?:DateTimeFormat|NumberFormat|RelativeTimeFormat|PluralRules|ListFormat)\(\s*['"`]/, 'Intl locale argument'],
        [/\.toLocale\w*String\(\s*['"`]/, 'toLocale*String locale argument'],
    ];
    const hits = [];
    for (const [file, source] of SOURCES) {
        source.split('\n').forEach((line, index) => {
            for (const [pattern, label] of patterns) {
                if (pattern.test(line)) hits.push(`${file}:${index + 1} ${label}`);
            }
        });
    }
    assert.deepEqual(hits, []);
});

test('display numbers are formatted through WBFormat, not toFixed', () => {
    const hits = [];
    for (const [file, source] of SOURCES) {
        source.split('\n').forEach((line, index) => {
            if (line.includes('.toFixed(')) hits.push(`${file}:${index + 1}`);
        });
    }
    assert.deepEqual(hits, []);
    assert.ok(!readFileSync(FORMAT_JS, 'utf8').split('\n').some((l) => /\.toFixed\(\s*\)\s*\./.test(l)));
});
