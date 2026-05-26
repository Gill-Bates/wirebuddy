//
// tools/ui-lint/lib/focus-flow.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function getFocusableSelector() {
    return [
        'a[href]',
        'button:not([disabled])',
        'input:not([type="hidden"]):not([disabled])',
        'select:not([disabled])',
        'textarea:not([disabled])',
        'summary',
        '[tabindex]:not([tabindex="-1"]):not([disabled])',
    ].join(', ');
}

export async function snapshotFocusState(page) {
    return page.evaluate(() => {
        const active = document.activeElement;
        if (!active) return null;

        const style = window.getComputedStyle(active);
        const rect = active.getBoundingClientRect();
        const parent = active.closest('[role="dialog"], .modal, .dropdown-menu, .offcanvas, [data-ui-component]');

        const beforeAfter = {
            outlineStyle: style.outlineStyle,
            outlineWidth: style.outlineWidth,
            outlineColor: style.outlineColor,
            outlineOffset: style.outlineOffset,
            boxShadow: style.boxShadow,
            borderColor: style.borderTopColor,
            backgroundColor: style.backgroundColor,
            color: style.color,
            visibility: style.visibility,
            display: style.display,
            opacity: style.opacity,
        };

        const role = active.getAttribute('role');
        const importance = active.getAttribute('data-ui-importance');
        const component = active.getAttribute('data-ui-component') || parent?.getAttribute('data-ui-component') || null;
        const density = active.getAttribute('data-ui-density') || parent?.getAttribute('data-ui-density') || null;

        const isHidden = Boolean(
            active.closest('[hidden], [aria-hidden="true"], .d-none, .invisible, .visually-hidden, [inert]') ||
            beforeAfter.visibility === 'hidden' ||
            beforeAfter.display === 'none' ||
            beforeAfter.opacity === '0'
        );

        return {
            id: active.id || null,
            tag: active.tagName,
            text: active.textContent?.trim().slice(0, 100) || '',
            role,
            component,
            density,
            importance,
            selector: active.id ? `#${active.id}` : null,
            rect: {
                left: Math.round(rect.left),
                top: Math.round(rect.top),
                right: Math.round(rect.right),
                bottom: Math.round(rect.bottom),
                width: Math.round(rect.width),
                height: Math.round(rect.height),
            },
            style: beforeAfter,
            hidden: isHidden,
            disabled: Boolean(active.disabled || active.getAttribute('aria-disabled') === 'true'),
            inert: Boolean(active.closest('[inert]') || active.hasAttribute('inert')),
            pointerEvents: style.pointerEvents,
            tabIndex: active.tabIndex,
            insideModal: Boolean(active.closest('.modal')),
            insideDropdown: Boolean(active.closest('.dropdown-menu')),
            insideOffcanvas: Boolean(active.closest('.offcanvas')),
            focusVisible: active.matches(':focus-visible'),
            focusWithin: active.matches(':focus-within'),
            computed: beforeAfter,
        };
    });
}

export async function simulateTabNavigation(page, steps) {
    const states = [];
    for (let index = 0; index < steps; index += 1) {
        await page.keyboard.press('Tab');
        states.push(await snapshotFocusState(page));
    }
    return states.filter(Boolean);
}