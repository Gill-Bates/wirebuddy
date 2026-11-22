//
// app/static/js/core/dom.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Minimal DOM helpers: el() element builder, clearChildren() and fragment().
// Text goes through textContent, so no HTML string is ever parsed.

(function () {
    'use strict';

    const delegatedHandlers = new WeakMap();
    const delegatedEventTypes = new Set();

    function isNode(value) {
        return typeof Node !== 'undefined' && value instanceof Node;
    }

    // One capturing listener per event type; handlers live in a WeakMap keyed by node.
    // Handlers get the node as `this` and as second argument: event.currentTarget is
    // `document` here, unlike with element.addEventListener().
    function dispatchDelegatedEvent(event) {
        const path = typeof event.composedPath === 'function' ? event.composedPath() : [];
        const nodes = path.length ? path : buildEventPath(event.target);

        for (const node of nodes) {
            const handler = isNode(node) ? delegatedHandlers.get(node)?.get(event.type) : null;
            if (handler) {
                handler.call(node, event, node);
                if (event.cancelBubble) {
                    break;
                }
            }
        }
    }

    function buildEventPath(target) {
        const nodes = [];
        let current = target;

        while (current) {
            nodes.push(current);
            current = current.parentNode || current.host || null;
        }

        return nodes;
    }

    function registerDelegatedHandler(node, type, handler) {
        if (!isNode(node) || typeof handler !== 'function') {
            return;
        }

        let map = delegatedHandlers.get(node);
        if (!map) {
            map = new Map();
            delegatedHandlers.set(node, map);
        }
        map.set(type, handler);

        if (!delegatedEventTypes.has(type)) {
            document.addEventListener(type, dispatchDelegatedEvent, true);
            delegatedEventTypes.add(type);
        }
    }

    // Attributes whose value is a URL; srcdoc carries HTML and is refused outright.
    const URL_ATTRIBUTES = new Set([
        'href', 'src', 'action', 'formaction', 'poster', 'data', 'background', 'cite', 'ping', 'xlink:href',
    ]);
    const SAFE_URL_SCHEMES = new Set(['http', 'https', 'mailto']);
    // Browsers ignore control characters and spaces inside a scheme, so drop them before checking.
    function isSafeUrl(value) {
        const normalized = String(value).replace(/[\u0000-\u0020\u007f-\u009f]/g, '').toLowerCase();
        const match = /^([a-z][a-z0-9+.-]*):/.exec(normalized);
        return !match || SAFE_URL_SCHEMES.has(match[1]);
    }
    function setAttributes(element, attrs) {
        for (const [key, value] of Object.entries(attrs)) {
            // Inline handlers and style attributes violate the CSP; never set them via the builder.
            if (/^on/i.test(key) || key.toLowerCase() === 'style') {
                console.warn('dom.setAttributes: refusing attribute', key);
                continue;
            }
            const name = key.toLowerCase();
            if (name === 'srcdoc' || (URL_ATTRIBUTES.has(name) && value != null && typeof value !== 'boolean' && !isSafeUrl(value))) {
                console.warn('dom.setAttributes: refusing unsafe value for attribute', key);
                continue;
            }
            if (value === true) {
                element.setAttribute(key, '');
            } else if (value === false || value == null) {
                element.removeAttribute(key);
            } else {
                element.setAttribute(key, String(value));
            }
        }
    }

    function setDataAttributes(element, data) {
        for (const [key, value] of Object.entries(data)) {
            if (value == null || value === false) {
                delete element.dataset[key];
            } else {
                element.dataset[key] = String(value);
            }
        }
    }

    function clearChildren(element) {
        while (element.firstChild) {
            element.removeChild(element.firstChild);
        }
    }

    function fragment(elements) {
        const frag = document.createDocumentFragment();
        for (const elem of elements) {
            if (isNode(elem)) {
                frag.appendChild(elem);
            }
        }
        return frag;
    }

    function el(tag, options = {}) {
        const element = document.createElement(tag);

        if (options.class) {
            const classes = String(options.class).split(/\s+/).filter(Boolean);
            if (classes.length) {
                element.classList.add(...classes);
            }
        }

        if (options.id) {
            element.id = options.id;
        }

        if (options.text != null) {
            element.textContent = String(options.text);
        }

        if (options.attrs) {
            setAttributes(element, options.attrs);
        }

        if (options.data) {
            setDataAttributes(element, options.data);
        }

        if (options.children) {
            for (const child of options.children) {
                if (isNode(child)) {
                    element.appendChild(child);
                } else if (child != null) {
                    element.appendChild(document.createTextNode(String(child)));
                }
            }
        }

        if (options.on) {
            for (const [event, handler] of Object.entries(options.on)) {
                registerDelegatedHandler(element, event, handler);
            }
        }

        return element;
    }

    window.WBDom = { el, clearChildren, fragment };

    window.WB = window.WB || {};
    window.WB.dom = window.WBDom;

    window.el = el;
})();
