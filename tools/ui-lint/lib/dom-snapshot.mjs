//
// tools/ui-lint/lib/dom-snapshot.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// DOM snapshot collector - collects all DOM data in a single pass.
// Avoids layout thrashing from repeated getBoundingClientRect/getComputedStyle calls.
//

/**
 * Collect a complete DOM snapshot from the page.
 * This runs inside page.evaluate() and collects all data at once.
 *
 * @param {Object} page - Playwright page
 * @param {Object} options - Collection options
 * @returns {Promise<DOMSnapshot>}
 */
export async function collectDOMSnapshot(page, options = {}) {
    return page.evaluate(({ options }) => {
        const round = (v) => Math.round(v * 10) / 10;

        // Selectors
        const interactiveSelector = 'button, [role="button"], a[href], input:not([type="hidden"]), select, textarea, summary, [tabindex]:not([tabindex="-1"])';
        const focusableSelector = 'a[href], button, input:not([type="hidden"]), select, textarea, summary, [tabindex]';

        // Content root
        const contentRoot = document.querySelector('main.main-content') || document.body;

        // Visibility helpers
        const isInsideInactivePane = (el) => {
            const pane = el.closest('.tab-pane');
            return Boolean(pane && !pane.classList.contains('active'));
        };

        const isIntentionallyHidden = (el) => Boolean(
            el.closest('.modal:not(.show)') ||
            el.closest('.collapse:not(.show)') ||
            el.closest('.navbar-collapse:not(.show)') ||
            el.closest('.hidden') ||
            el.closest('.d-none') ||
            el.closest('[hidden]') ||
            el.closest('[aria-hidden="true"]')
        );

        // Collect all elements once
        const allElements = Array.from(contentRoot.querySelectorAll('*'));

        // Pre-compute visibility and styles for all elements
        const elementData = new Map();

        for (const el of allElements) {
            if (!el.isConnected) continue;

            const style = window.getComputedStyle(el);
            const rect = el.getBoundingClientRect();
            const hidden = isInsideInactivePane(el) || isIntentionallyHidden(el);
            const visible = !hidden &&
                style.display !== 'none' &&
                style.visibility !== 'hidden' &&
                style.opacity !== '0' &&
                rect.width > 0 &&
                rect.height > 0;

            elementData.set(el, {
                tag: el.tagName,
                id: el.id || null,
                classList: Array.from(el.classList),
                className: typeof el.className === 'string' ? el.className : '',
                rect: {
                    left: round(rect.left),
                    right: round(rect.right),
                    top: round(rect.top),
                    bottom: round(rect.bottom),
                    width: round(rect.width),
                    height: round(rect.height),
                },
                style: {
                    display: style.display,
                    visibility: style.visibility,
                    opacity: style.opacity,
                    position: style.position,
                    overflow: style.overflow,
                    overflowX: style.overflowX,
                    overflowY: style.overflowY,
                    fontSize: style.fontSize,
                    fontFamily: style.fontFamily,
                    fontWeight: style.fontWeight,
                    color: style.color,
                    backgroundColor: style.backgroundColor,
                    borderRadius: style.borderRadius,
                    padding: style.padding,
                    margin: style.margin,
                    outline: style.outline,
                    outlineWidth: style.outlineWidth,
                    outlineColor: style.outlineColor,
                    boxShadow: style.boxShadow,
                },
                visible,
                hidden,
                disabled: el.disabled || el.getAttribute('aria-disabled') === 'true',
                role: el.getAttribute('role'),
                ariaLabel: el.getAttribute('aria-label'),
                ariaHidden: el.getAttribute('aria-hidden'),
                ariaDescribedby: el.getAttribute('aria-describedby'),
                inert: el.hasAttribute('inert'),
                tabIndex: el.tabIndex,
                text: el.textContent?.trim().slice(0, 100) || '',
                scrollHeight: el.scrollHeight,
                scrollWidth: el.scrollWidth,
                clientHeight: el.clientHeight,
                clientWidth: el.clientWidth,
            });
        }

        // Extract specific element collections
        const interactive = allElements.filter(el =>
            el.matches(interactiveSelector) && elementData.get(el)?.visible
        );

        const focusable = allElements.filter(el =>
            el.matches(focusableSelector) && elementData.get(el)?.visible
        );

        const badges = allElements.filter(el =>
            el.classList.contains('badge') && elementData.get(el)?.visible
        );

        const cards = allElements.filter(el =>
            (el.classList.contains('card') || el.matches('[data-ui="card"]')) &&
            elementData.get(el)?.visible
        );

        const buttons = allElements.filter(el =>
            (el.tagName === 'BUTTON' || el.classList.contains('btn')) &&
            elementData.get(el)?.visible
        );

        const modals = allElements.filter(el =>
            el.classList.contains('modal')
        );

        const scrollContainers = allElements.filter(el => {
            const data = elementData.get(el);
            if (!data) return false;
            const hasOverflow = ['auto', 'scroll'].includes(data.style.overflowY) ||
                ['auto', 'scroll'].includes(data.style.overflowX);
            const isScrollable = data.scrollHeight > data.clientHeight ||
                data.scrollWidth > data.clientWidth;
            return hasOverflow && isScrollable;
        });

        // Serialize element data for return
        const serializeElement = (el) => {
            const data = elementData.get(el);
            if (!data) return null;
            return {
                ...data,
                // Add semantic attributes
                dataUi: el.getAttribute('data-ui'),
                dataUiRole: el.getAttribute('data-ui-role'),
                dataUiComponent: el.getAttribute('data-ui-component'),
                dataUiDensity: el.getAttribute('data-ui-density'),
                dataUiImportance: el.getAttribute('data-ui-importance'),
                dataAction: el.getAttribute('data-action'),
                dataPeerId: el.getAttribute('data-peer-id'),
                dataNodeId: el.getAttribute('data-node-id'),
            };
        };

        return {
            viewport: {
                width: window.innerWidth,
                height: window.innerHeight,
                scrollX: window.scrollX,
                scrollY: window.scrollY,
            },
            breakpoint: (() => {
                const w = window.innerWidth;
                if (w >= 1400) return 'xxl';
                if (w >= 1200) return 'xl';
                if (w >= 992) return 'lg';
                if (w >= 768) return 'md';
                if (w >= 576) return 'sm';
                return 'base';
            })(),
            contentRoot: {
                tag: contentRoot.tagName,
                rect: (() => {
                    const r = contentRoot.getBoundingClientRect();
                    return { left: r.left, top: r.top, width: r.width, height: r.height };
                })(),
            },
            elementCount: allElements.length,
            collections: {
                interactive: interactive.map(serializeElement).filter(Boolean),
                focusable: focusable.map(serializeElement).filter(Boolean),
                badges: badges.map(serializeElement).filter(Boolean),
                cards: cards.map(serializeElement).filter(Boolean),
                buttons: buttons.map(serializeElement).filter(Boolean),
                modals: modals.map(serializeElement).filter(Boolean),
                scrollContainers: scrollContainers.map(serializeElement).filter(Boolean),
            },
            // Raw element data for custom queries
            elements: allElements
                .filter(el => elementData.get(el)?.visible)
                .slice(0, 1000) // Limit to prevent memory issues
                .map(serializeElement)
                .filter(Boolean),
        };
    }, { options });
}

/**
 * Query the snapshot for elements matching criteria.
 * @param {DOMSnapshot} snapshot
 * @param {Function} predicate - Filter function
 * @returns {Object[]}
 */
export function querySnapshot(snapshot, predicate) {
    return snapshot.elements.filter(predicate);
}

/**
 * Get elements by data-ui attribute.
 * @param {DOMSnapshot} snapshot
 * @param {string} uiName
 * @returns {Object[]}
 */
export function getByDataUi(snapshot, uiName) {
    return querySnapshot(snapshot, el => el.dataUi === uiName);
}

/**
 * Get elements by CSS class.
 * @param {DOMSnapshot} snapshot
 * @param {string} className
 * @returns {Object[]}
 */
export function getByClass(snapshot, className) {
    return querySnapshot(snapshot, el => el.classList?.includes(className));
}

/**
 * Get elements by tag name.
 * @param {DOMSnapshot} snapshot
 * @param {string} tagName
 * @returns {Object[]}
 */
export function getByTag(snapshot, tagName) {
    const upper = tagName.toUpperCase();
    return querySnapshot(snapshot, el => el.tag === upper);
}
