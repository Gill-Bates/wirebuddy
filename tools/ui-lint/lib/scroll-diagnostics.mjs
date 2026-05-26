//
// tools/ui-lint/lib/scroll-diagnostics.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

function selectorForElement(element) {
    if (!(element instanceof Element)) return null;
    if (element.id) return `#${element.id}`;

    const component = element.getAttribute('data-ui-component');
    if (component) return `[data-ui-component="${component}"]`;

    const action = element.getAttribute('data-action');
    if (action) return `[data-action="${action}"]`;

    const classes = Array.from(element.classList || []).slice(0, 2);
    if (classes.length > 0) return `.${classes.join('.')}`;

    return element.tagName.toLowerCase();
}

function isFocusableElement(element) {
    if (!(element instanceof HTMLElement)) return false;
    if (element.hasAttribute('disabled') || element.getAttribute('aria-disabled') === 'true') return false;
    return element.matches('a[href], button, input:not([type="hidden"]), select, textarea, summary, [tabindex]') && element.tabIndex !== -1;
}

function isIntentionalScrollContainer(element, allowedSelectors) {
    if (element.getAttribute('data-ui-scroll-container') === 'intentional') return true;

    for (const selector of allowedSelectors) {
        try {
            if (element.matches(selector)) return true;
        } catch {
            continue;
        }
    }

    return false;
}

function isCandidateScrollable(style, element, tolerance) {
    const overflowX = style.overflowX;
    const overflowY = style.overflowY;
    const overflow = style.overflow;
    const vertical = ['auto', 'scroll', 'overlay'].includes(overflowY) && element.scrollHeight > element.clientHeight + tolerance;
    const horizontal = ['auto', 'scroll', 'overlay'].includes(overflowX) && element.scrollWidth > element.clientWidth + tolerance;
    const clipped = ['hidden', 'clip'].includes(overflowX) || ['hidden', 'clip'].includes(overflowY) || ['hidden', 'clip'].includes(overflow)
        ? (element.scrollHeight > element.clientHeight + tolerance || element.scrollWidth > element.clientWidth + tolerance)
        : false;

    return {
        vertical,
        horizontal,
        clipped,
        candidate: vertical || horizontal || clipped,
    };
}

function elementScrollState(element, tolerance, allowedSelectors) {
    const style = window.getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    const visible = style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0' && rect.width > 0 && rect.height > 0;
    const scrollability = isCandidateScrollable(style, element, tolerance);
    const intentional = isIntentionalScrollContainer(element, allowedSelectors);

    return {
        selector: selectorForElement(element),
        tag: element.tagName.toLowerCase(),
        component: element.getAttribute('data-ui-component') || element.closest('[data-ui-component]')?.getAttribute('data-ui-component') || null,
        importance: element.getAttribute('data-ui-importance') || element.closest('[data-ui-importance]')?.getAttribute('data-ui-importance') || null,
        dataUiScrollContainer: element.getAttribute('data-ui-scroll-container') || null,
        visible,
        intentional,
        vertical: scrollability.vertical,
        horizontal: scrollability.horizontal,
        clipped: scrollability.clipped,
        candidate: visible && scrollability.candidate,
        overflowX: style.overflowX,
        overflowY: style.overflowY,
        overflow: style.overflow,
        position: style.position,
        overflowAnchor: style.overflowAnchor,
        touchAction: style.touchAction,
        overscrollBehavior: style.overscrollBehavior,
        overscrollBehaviorX: style.overscrollBehaviorX,
        overscrollBehaviorY: style.overscrollBehaviorY,
        webkitOverflowScrolling: style.webkitOverflowScrolling,
        scrollHeight: Math.round(element.scrollHeight),
        scrollWidth: Math.round(element.scrollWidth),
        clientHeight: Math.round(element.clientHeight),
        clientWidth: Math.round(element.clientWidth),
        rect: {
            left: Math.round(rect.left),
            top: Math.round(rect.top),
            right: Math.round(rect.right),
            bottom: Math.round(rect.bottom),
            width: Math.round(rect.width),
            height: Math.round(rect.height),
        },
        interactive: element.matches('button, a[href], input:not([type="hidden"]), select, textarea, summary, [role="button"]'),
        primaryAction: Boolean(element.getAttribute('data-ui-importance') === 'primary' || /\b(save|submit|confirm|apply|delete|primary)\b/i.test(`${element.getAttribute('aria-label') || ''} ${element.textContent || ''}`)),
        role: element.getAttribute('role') || null,
        fixedSticky: ['fixed', 'sticky'].includes(style.position),
    };
}

export async function collectScrollTrapDiagnostics(page, { allowedSelectors = [], tolerance = 2, browser = null, scope = null } = {}) {
    return page.evaluate(({ allowedSelectors, tolerance, browser, scope }) => {
        const selectorFor = (element) => {
            if (!(element instanceof Element)) return null;
            if (element.id) return `#${element.id}`;

            const component = element.getAttribute('data-ui-component');
            if (component) return `[data-ui-component="${component}"]`;

            const action = element.getAttribute('data-action');
            if (action) return `[data-action="${action}"]`;

            const classes = Array.from(element.classList || []).slice(0, 2);
            if (classes.length > 0) return `.${classes.join('.')}`;

            return element.tagName.toLowerCase();
        };

        const isFocusable = (element) => {
            if (!(element instanceof HTMLElement)) return false;
            if (element.hasAttribute('disabled') || element.getAttribute('aria-disabled') === 'true') return false;
            return element.matches('a[href], button, input:not([type="hidden"]), select, textarea, summary, [tabindex]') && element.tabIndex !== -1;
        };

        const isIntentional = (element) => {
            if (element.getAttribute('data-ui-scroll-container') === 'intentional') return true;

            for (const selector of allowedSelectors) {
                try {
                    if (element.matches(selector)) return true;
                } catch {
                    continue;
                }
            }

            return false;
        };

        const isCandidate = (style, element) => {
            const overflowX = style.overflowX;
            const overflowY = style.overflowY;
            const overflow = style.overflow;
            const vertical = ['auto', 'scroll', 'overlay'].includes(overflowY) && element.scrollHeight > element.clientHeight + tolerance;
            const horizontal = ['auto', 'scroll', 'overlay'].includes(overflowX) && element.scrollWidth > element.clientWidth + tolerance;
            const clipped = ['hidden', 'clip'].includes(overflowX) || ['hidden', 'clip'].includes(overflowY) || ['hidden', 'clip'].includes(overflow)
                ? (element.scrollHeight > element.clientHeight + tolerance || element.scrollWidth > element.clientWidth + tolerance)
                : false;

            return { vertical, horizontal, clipped, candidate: vertical || horizontal || clipped };
        };

        const scrollState = (element) => {
            const style = window.getComputedStyle(element);
            const rect = element.getBoundingClientRect();
            const visible = style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0' && rect.width > 0 && rect.height > 0;
            const scrollability = isCandidate(style, element);

            return {
                selector: selectorFor(element),
                tag: element.tagName.toLowerCase(),
                component: element.getAttribute('data-ui-component') || element.closest('[data-ui-component]')?.getAttribute('data-ui-component') || null,
                importance: element.getAttribute('data-ui-importance') || element.closest('[data-ui-importance]')?.getAttribute('data-ui-importance') || null,
                dataUiScrollContainer: element.getAttribute('data-ui-scroll-container') || null,
                visible,
                intentional: isIntentional(element),
                vertical: scrollability.vertical,
                horizontal: scrollability.horizontal,
                clipped: scrollability.clipped,
                candidate: visible && scrollability.candidate,
                overflowX: style.overflowX,
                overflowY: style.overflowY,
                overflow: style.overflow,
                position: style.position,
                overflowAnchor: style.overflowAnchor,
                touchAction: style.touchAction,
                overscrollBehavior: style.overscrollBehavior,
                overscrollBehaviorX: style.overscrollBehaviorX,
                overscrollBehaviorY: style.overscrollBehaviorY,
                webkitOverflowScrolling: style.webkitOverflowScrolling,
                scrollHeight: Math.round(element.scrollHeight),
                scrollWidth: Math.round(element.scrollWidth),
                clientHeight: Math.round(element.clientHeight),
                clientWidth: Math.round(element.clientWidth),
                rect: {
                    left: Math.round(rect.left),
                    top: Math.round(rect.top),
                    right: Math.round(rect.right),
                    bottom: Math.round(rect.bottom),
                    width: Math.round(rect.width),
                    height: Math.round(rect.height),
                },
                interactive: element.matches('button, a[href], input:not([type="hidden"]), select, textarea, summary, [role="button"]'),
                primaryAction: Boolean(element.getAttribute('data-ui-importance') === 'primary' || /\b(save|submit|confirm|apply|delete|primary)\b/i.test(`${element.getAttribute('aria-label') || ''} ${element.textContent || ''}`)),
                role: element.getAttribute('role') || null,
                fixedSticky: ['fixed', 'sticky'].includes(style.position),
            };
        };

        const contentRoot = document.querySelector('main.main-content') || document.body;
        const viewport = {
            width: window.innerWidth,
            height: window.innerHeight,
        };
        const visualViewport = window.visualViewport
            ? {
                width: Math.round(window.visualViewport.width),
                height: Math.round(window.visualViewport.height),
                offsetTop: Math.round(window.visualViewport.offsetTop),
                offsetLeft: Math.round(window.visualViewport.offsetLeft),
                scale: window.visualViewport.scale,
            }
            : null;

        const htmlStyle = window.getComputedStyle(document.documentElement);
        const body = document.body;
        const bodyStyle = window.getComputedStyle(body);
        const pageScrollHeight = Math.max(document.documentElement.scrollHeight || 0, body?.scrollHeight || 0);
        const pageScrollWidth = Math.max(document.documentElement.scrollWidth || 0, body?.scrollWidth || 0);
        const pageVerticalOverflow = Math.max(0, pageScrollHeight - viewport.height);
        const pageHorizontalOverflow = Math.max(0, pageScrollWidth - viewport.width);
        const bodyLocked = ['hidden', 'clip'].includes(htmlStyle.overflowY) || ['hidden', 'clip'].includes(bodyStyle.overflowY)
            || ['hidden', 'clip'].includes(htmlStyle.overflow) || ['hidden', 'clip'].includes(bodyStyle.overflow);

        const activeElement = document.activeElement;
        const activeRect = activeElement instanceof HTMLElement ? activeElement.getBoundingClientRect() : null;
        const activeScrollable = isFocusable(activeElement);
        const keyboardCompromised = Boolean(
            visualViewport
            && activeScrollable
            && activeRect
            && activeRect.bottom > visualViewport.height - tolerance
            && /^(input|textarea|select|button)$/i.test(activeElement.tagName)
        );

        const elements = Array.from(contentRoot.querySelectorAll('*'));
        const states = new Map();
        const issues = [];

        for (const element of elements) {
            if (!element.isConnected) continue;
            states.set(element, scrollState(element));
        }

        const collectAncestors = (element) => {
            const scrollAncestors = [];
            const fixedStickyAncestors = [];
            let depth = 0;
            let current = element.parentElement;

            while (current && current !== contentRoot.parentElement) {
                const ancestorState = states.get(current);
                if (ancestorState?.candidate) {
                    depth += 1;
                    if (scrollAncestors.length < 4) {
                        scrollAncestors.push({
                            selector: ancestorState.selector,
                            axis: ancestorState.vertical && ancestorState.horizontal ? 'both' : ancestorState.vertical ? 'vertical' : 'horizontal',
                            component: ancestorState.component,
                            intentional: ancestorState.intentional,
                        });
                    }
                }

                if (ancestorState?.fixedSticky && fixedStickyAncestors.length < 4) {
                    fixedStickyAncestors.push({
                        selector: ancestorState.selector,
                        position: ancestorState.position,
                        component: ancestorState.component,
                    });
                }

                current = current.parentElement;
            }

            return { depth, scrollAncestors, fixedStickyAncestors };
        };

        for (const [element, state] of states.entries()) {
            if (!state.candidate) continue;

            const ancestry = collectAncestors(element);
            const modalContext = Boolean(element.closest('.modal, dialog, .offcanvas, [role="dialog"], [aria-modal="true"]'));
            const dialogContext = Boolean(element.closest('dialog, [role="dialog"]'));
            const offcanvasContext = Boolean(element.closest('.offcanvas'));
            const pageLocked = bodyLocked && pageVerticalOverflow > tolerance;

            issues.push({
                ...state,
                axis: state.vertical && state.horizontal ? 'both' : state.vertical ? 'vertical' : 'horizontal',
                nestingDepth: ancestry.depth,
                scrollAncestors: ancestry.scrollAncestors,
                fixedStickyAncestors: ancestry.fixedStickyAncestors,
                modalContext,
                dialogContext,
                offcanvasContext,
                pageLocked,
                pageScrollHeight,
                pageScrollWidth,
                pageVerticalOverflow,
                pageHorizontalOverflow,
                bodyLocked,
                visualViewport,
                keyboardCompromised,
                browser,
                scope,
                activeElementTag: activeElement?.tagName?.toLowerCase?.() || null,
                activeElementSelector: activeElement instanceof HTMLElement ? selectorFor(activeElement) : null,
                activeElementRect: activeRect
                    ? {
                        left: Math.round(activeRect.left),
                        top: Math.round(activeRect.top),
                        right: Math.round(activeRect.right),
                        bottom: Math.round(activeRect.bottom),
                        width: Math.round(activeRect.width),
                        height: Math.round(activeRect.height),
                    }
                    : null,
            });

            if (issues.length >= 20) break;
        }

        return {
            viewport,
            visualViewport,
            pageScrollHeight,
            pageScrollWidth,
            pageVerticalOverflow,
            pageHorizontalOverflow,
            bodyLocked,
            browser,
            scope,
            issues,
        };
    }, { allowedSelectors, tolerance, browser, scope });
}

export function classifyScrollTrapIssue(issue, context = {}) {
    const browser = String(context.browser || issue.browser || '').toLowerCase();
    const viewport = context.viewport || issue.viewport || { width: issue.pageScrollWidth || 0, height: 0 };
    const tolerance = context.tolerance ?? 2;
    const hasVerticalTrap = issue.axis === 'vertical' || issue.axis === 'both';
    const hasHorizontalTrap = issue.axis === 'horizontal' || issue.axis === 'both';
    const pageOverflow = Number(issue.pageVerticalOverflow || 0);
    const bodyLocked = Boolean(issue.bodyLocked || context.bodyLocked);
    const intentional = Boolean(issue.intentional || issue.dataUiScrollContainer === 'intentional');
    const nested = Number(issue.nestingDepth || 0);
    const modalContext = Boolean(issue.modalContext || issue.dialogContext || issue.offcanvasContext);
    const keyboardCompromised = Boolean(issue.keyboardCompromised);
    const hasFixedStickyContext = Array.isArray(issue.fixedStickyAncestors) && issue.fixedStickyAncestors.length > 0;
    const interactive = Boolean(issue.interactive);
    const primaryAction = Boolean(issue.primaryAction || issue.importance === 'primary');
    const scrollDirection = hasVerticalTrap && hasHorizontalTrap ? 'both' : hasVerticalTrap ? 'vertical' : 'horizontal';

    if (!hasVerticalTrap && !keyboardCompromised) {
        return null;
    }

    if (intentional && nested === 0 && !keyboardCompromised) {
        return null;
    }

    let kind = 'nested-scroll-trap';
    let severity = 'warning';

    if (keyboardCompromised) {
        kind = 'keyboard-scroll-clip';
        severity = 'error';
    } else if (bodyLocked && pageOverflow > tolerance && hasVerticalTrap) {
        kind = 'scroll-jail-body-lock';
        severity = 'error';
    } else if (modalContext && hasVerticalTrap) {
        kind = 'modal-scroll-jail';
        severity = nested > 0 || primaryAction || hasFixedStickyContext ? 'error' : 'serious';
    } else if (nested > 0 && hasVerticalTrap) {
        kind = 'nested-scroll-trap';
        severity = primaryAction || interactive || hasFixedStickyContext ? 'serious' : 'warning';
    } else if (browser === 'webkit' && hasVerticalTrap && issue.webkitOverflowScrolling !== 'touch' && issue.overscrollBehaviorY === 'auto') {
        kind = 'webkit-scroll-momentum';
        severity = 'info';
    } else if (hasHorizontalTrap && primaryAction) {
        kind = 'clipped-action';
        severity = 'warning';
    } else {
        return null;
    }

    const component = issue.component || context.component || context.scope || null;
    const message = kind === 'scroll-jail-body-lock'
        ? `${component || 'Page'} is locked into nested scrolling and cannot continue vertically`
        : kind === 'modal-scroll-jail'
            ? `${component || 'Modal'} contains a nested vertical scroll region`
            : kind === 'keyboard-scroll-clip'
                ? `${component || 'Form'} is clipped by the visual viewport when the keyboard is active`
                : kind === 'webkit-scroll-momentum'
                    ? `${component || 'Scroll container'} may need momentum scrolling on iOS`
                    : kind === 'clipped-action'
                        ? `${component || 'Action'} is clipped inside a horizontal scroll region`
                        : `${component || 'Scroll container'} is nested inside another scroll region`;

    return {
        severity,
        kind,
        message,
        selector: issue.selector || null,
        details: {
            component,
            browser: browser || null,
            scope: context.scope || issue.scope || null,
            viewport: viewport?.width ? (viewport.width < 768 ? 'mobile' : viewport.width < 992 ? 'tablet' : 'desktop') : null,
            viewportWidth: issue.pageScrollWidth ? viewport.width || null : viewport?.width || null,
            viewportHeight: viewport?.height || null,
            pageScrollHeight: issue.pageScrollHeight || null,
            pageScrollWidth: issue.pageScrollWidth || null,
            pageVerticalOverflow: pageOverflow,
            pageHorizontalOverflow: issue.pageHorizontalOverflow || null,
            axis: scrollDirection,
            nestingDepth: nested,
            bodyLocked,
            intentional,
            modalContext,
            dialogContext: Boolean(issue.dialogContext),
            offcanvasContext: Boolean(issue.offcanvasContext),
            interactive,
            primaryAction,
            scrollHeight: issue.scrollHeight || null,
            scrollWidth: issue.scrollWidth || null,
            clientHeight: issue.clientHeight || null,
            clientWidth: issue.clientWidth || null,
            overflowX: issue.overflowX || null,
            overflowY: issue.overflowY || null,
            overflow: issue.overflow || null,
            overscrollBehaviorX: issue.overscrollBehaviorX || null,
            overscrollBehaviorY: issue.overscrollBehaviorY || null,
            overscrollBehavior: issue.overscrollBehavior || null,
            touchAction: issue.touchAction || null,
            webkitOverflowScrolling: issue.webkitOverflowScrolling || null,
            fixedStickyAncestors: issue.fixedStickyAncestors || [],
            scrollAncestors: issue.scrollAncestors || [],
            visualViewport: issue.visualViewport || null,
            keyboardCompromised,
            activeElementSelector: issue.activeElementSelector || null,
            activeElementTag: issue.activeElementTag || null,
            activeElementRect: issue.activeElementRect || null,
            rect: issue.rect || null,
            text: issue.text || null,
            importance: issue.importance || null,
        },
    };
}

export function captureScrollTrapRegion(issue) {
    if (!issue?.rect) return null;

    return {
        selector: issue.selector || null,
        component: issue.component || null,
        clip: issue.rect,
    };
}