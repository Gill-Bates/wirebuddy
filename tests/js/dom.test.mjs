//
// tests/js/dom.test.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Run: node --test "tests/js/*.test.mjs"
// Loads app/static/js/core/dom.js against a minimal DOM stub and checks the URL attribute guard of el().
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
const DOM_JS = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'app', 'static', 'js', 'core', 'dom.js');
function load() {
    const warnings = [];
    const window = {};
    const document = {
        createElement: () => ({
            attrs: {},
            classList: { add() {} },
            setAttribute(name, value) { this.attrs[name] = value; },
            removeAttribute(name) { delete this.attrs[name]; },
        }),
    };
    const console = { warn: (...args) => warnings.push(args.join(' ')) };
    vm.runInNewContext(readFileSync(DOM_JS, 'utf8'), { window, document, console });
    return { el: window.WBDom.el, warnings };
}
const UNSAFE = [
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    '  javascript:alert(1)',
    'java\tscript:alert(1)',
    'java\nscript:alert(1)',
    '\u0001javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    ' DATA:text/html;base64,AAAA',
    'vbscript:msgbox(1)',
    'VBScript:msgbox(1)',
];
const SAFE = ['http://example.com/a', 'HTTPS://example.com', 'mailto:a@example.com', '/relative/path', 'page.html?x=1:2', '#anchor', '//cdn.example.com/x', ''];
test('el() refuses unsafe URL schemes in every URL attribute', () => {
    const { el, warnings } = load();
    for (const attr of ['href', 'src', 'action', 'formaction', 'poster', 'xlink:href', 'HREF']) {
        for (const value of UNSAFE) {
            const node = el('a', { attrs: { [attr]: value } });
            assert.equal(Object.keys(node.attrs).length, 0, `${attr}=${JSON.stringify(value)}`);
        }
    }
    assert.ok(warnings.length > 0);
});
test('el() keeps http, https, mailto, relative and anchor URLs', () => {
    const { el } = load();
    for (const value of SAFE) {
        assert.equal(el('a', { attrs: { href: value } }).attrs.href, value);
    }
});
test('el() refuses srcdoc and keeps ordinary attributes working', () => {
    const { el } = load();
    assert.deepEqual(el('iframe', { attrs: { srcdoc: '<script>1</script>' } }).attrs, {});
    const node = el('input', { attrs: { type: 'checkbox', id: 'x', 'aria-label': 'javascript: is only text here', disabled: true } });
    assert.deepEqual(node.attrs, { type: 'checkbox', id: 'x', 'aria-label': 'javascript: is only text here', disabled: '' });
});
