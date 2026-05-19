//
// app/static/js/core/dom.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// DOM builder utilities to replace innerHTML string concatenation.
// Provides XSS-safe element creation with declarative API.
//

(function () {
    'use strict';

    /**
     * Create a DOM element with options.
     *
     * @param {string} tag - HTML tag name
     * @param {Object} [options={}] - Element options
     * @param {string} [options.class] - CSS class(es)
     * @param {string} [options.id] - Element ID
     * @param {string} [options.text] - Text content (XSS-safe)
     * @param {string} [options.html] - Raw HTML (use sparingly, only for trusted content)
     * @param {Object} [options.attrs] - Additional attributes
     * @param {Object} [options.data] - Data attributes (data-*)
     * @param {Object} [options.style] - Inline styles
     * @param {Array<Element|string>} [options.children] - Child elements or text
     * @param {Object} [options.on] - Event listeners {event: handler}
     * @returns {HTMLElement}
     *
     * @example
     * const badge = el('span', {
     *     class: 'badge bg-success',
     *     text: 'Valid'
     * });
     *
     * @example
     * const card = el('div', {
     *     class: 'card',
     *     children: [
     *         el('h3', { text: 'Title' }),
     *         el('p', { text: 'Description' })
     *     ]
     * });
     */
    function el(tag, options = {}) {
        const element = document.createElement(tag);

        // CSS classes
        if (options.class) {
            const classes = options.class.split(/\s+/).filter(Boolean);
            if (classes.length) element.classList.add(...classes);
        }

        // ID
        if (options.id) {
            element.id = options.id;
        }

        // Text content (safe)
        if (options.text != null) {
            element.textContent = String(options.text);
        }

        // Raw HTML (use sparingly)
        if (options.html != null) {
            element.innerHTML = options.html;
        }

        // Attributes
        if (options.attrs) {
            for (const [key, value] of Object.entries(options.attrs)) {
                if (value === true) {
                    element.setAttribute(key, '');
                } else if (value !== false && value != null) {
                    element.setAttribute(key, String(value));
                }
            }
        }

        // Data attributes
        if (options.data) {
            for (const [key, value] of Object.entries(options.data)) {
                if (value != null) {
                    element.dataset[key] = String(value);
                }
            }
        }

        // Inline styles
        if (options.style) {
            for (const [prop, value] of Object.entries(options.style)) {
                if (value != null) {
                    element.style[prop] = value;
                }
            }
        }

        // Children
        if (options.children) {
            for (const child of options.children) {
                if (child instanceof Node) {
                    element.appendChild(child);
                } else if (child != null) {
                    element.appendChild(document.createTextNode(String(child)));
                }
            }
        }

        // Event listeners
        if (options.on) {
            for (const [event, handler] of Object.entries(options.on)) {
                if (typeof handler === 'function') {
                    element.addEventListener(event, handler);
                }
            }
        }

        return element;
    }

    /**
     * XSS-safe text escaping for HTML contexts.
     * @param {string} str - Input string
     * @returns {string} - Escaped string
     */
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str ?? '';
        return div.innerHTML;
    }

    /**
     * Generate a simple hash for stable DOM IDs.
     * @param {string} str - Input string
     * @returns {string} - Base36 hash
     */
    function hashId(str) {
        if (!str) return 'empty';
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash |= 0;
        }
        return Math.abs(hash).toString(36);
    }

    /**
     * Clear all children from an element.
     * @param {Element} element
     */
    function clearChildren(element) {
        while (element.firstChild) {
            element.removeChild(element.firstChild);
        }
    }

    /**
     * Replace element content with new children.
     * @param {Element} parent
     * @param {Array<Element>} children
     */
    function replaceContent(parent, children) {
        clearChildren(parent);
        for (const child of children) {
            if (child instanceof Node) {
                parent.appendChild(child);
            }
        }
    }

    /**
     * Create a document fragment from array of elements.
     * @param {Array<Element>} elements
     * @returns {DocumentFragment}
     */
    function fragment(elements) {
        const frag = document.createDocumentFragment();
        for (const elem of elements) {
            if (elem instanceof Node) {
                frag.appendChild(elem);
            }
        }
        return frag;
    }

    // Expose globally
    window.WBDom = {
        el,
        escapeHtml,
        hashId,
        clearChildren,
        replaceContent,
        fragment
    };

    window.WB = window.WB || {};
    window.WB.dom = window.WBDom;

    // Also expose el directly for convenience
    window.el = el;
})();
