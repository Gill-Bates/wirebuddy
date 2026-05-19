//
// tools/ui-lint/lib/layout-diagnostics.mjs
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
    if (classes.length > 0) {
        return `.${classes.join('.')}`;
    }

    return element.tagName.toLowerCase();
}

function isInteractiveElement(element) {
    const tag = element.tagName.toLowerCase();
    return tag === 'button'
        || tag === 'select'
        || tag === 'textarea'
        || (tag === 'a' && element.hasAttribute('href'))
        || element.getAttribute('role') === 'button'
        || element.hasAttribute('data-action')
        || element.hasAttribute('aria-label');
}

function looksLikePrimaryAction(element) {
    const importance = element.getAttribute('data-ui-importance');
    if (importance === 'primary') return true;

    const label = `${element.getAttribute('aria-label') || ''} ${element.textContent || ''}`.toLowerCase();
    return /\b(primary|save|submit|confirm|apply|delete|remove|more actions)\b/.test(label);
}

function describeScrollableAncestor(element, tolerance) {
    let current = element.parentElement;
    while (current) {
        const style = window.getComputedStyle(current);
        const overflowX = style.overflowX;
        const overflowY = style.overflowY;
        const scrollable = ['auto', 'scroll', 'overlay'].includes(overflowX) || ['auto', 'scroll', 'overlay'].includes(overflowY);
        if (scrollable && current.scrollWidth > current.clientWidth + tolerance) {
            return {
                selector: selectorForElement(current),
                overflowX,
                overflowY,
                scrollWidth: Math.round(current.scrollWidth),
                clientWidth: Math.round(current.clientWidth),
            };
        }
        current = current.parentElement;
    }

    return null;
}

function rootCauseCandidate(element, contentRoot, tolerance) {
    let current = element.parentElement;
    while (current && current !== contentRoot.parentElement) {
        const style = window.getComputedStyle(current);
        const display = style.display;
        const flexWrap = style.flexWrap;
        const whiteSpace = style.whiteSpace;
        const minWidth = style.minWidth;
        const position = style.position;
        const overflowX = style.overflowX;
        const gridTemplateColumns = style.gridTemplateColumns;

        if (display === 'flex' && flexWrap === 'nowrap') {
            return {
                selector: selectorForElement(current),
                reason: 'flex-nowrap',
                display,
                flexWrap,
                whiteSpace,
                minWidth,
                position,
                overflowX,
                gridTemplateColumns,
            };
        }

        if (display === 'grid' && /\b(auto|minmax|repeat)\b/i.test(gridTemplateColumns) && current.scrollWidth > current.clientWidth + tolerance) {
            return {
                selector: selectorForElement(current),
                reason: 'grid-intrinsic',
                display,
                flexWrap,
                whiteSpace,
                minWidth,
                position,
                overflowX,
                gridTemplateColumns,
            };
        }

        if (whiteSpace === 'nowrap' && current.scrollWidth > current.clientWidth + tolerance) {
            return {
                selector: selectorForElement(current),
                reason: 'nowrap',
                display,
                flexWrap,
                whiteSpace,
                minWidth,
                position,
                overflowX,
                gridTemplateColumns,
            };
        }

        if ((display === 'flex' || display === 'grid') && minWidth === 'auto') {
            return {
                selector: selectorForElement(current),
                reason: 'missing-min-width-0',
                display,
                flexWrap,
                whiteSpace,
                minWidth,
                position,
                overflowX,
                gridTemplateColumns,
            };
        }

        if (['hidden', 'clip'].includes(overflowX) && current.scrollWidth > current.clientWidth + tolerance) {
            return {
                selector: selectorForElement(current),
                reason: 'clipped-overflow',
                display,
                flexWrap,
                whiteSpace,
                minWidth,
                position,
                overflowX,
                gridTemplateColumns,
            };
        }

        if (['fixed', 'sticky', 'absolute'].includes(position)) {
            return {
                selector: selectorForElement(current),
                reason: `${position}-position`,
                display,
                flexWrap,
                whiteSpace,
                minWidth,
                position,
                overflowX,
                gridTemplateColumns,
            };
        }

        current = current.parentElement;
    }

    return null;
}

export function findOverflowRootCause(element, { tolerance = 2 } = {}) {
    if (!(element instanceof Element)) return null;

    const contentRoot = document.querySelector('main.main-content') || document.body;
    return rootCauseCandidate(element, contentRoot, tolerance);
}

export function captureOverflowRegion(element) {
    if (!(element instanceof Element)) return null;

    const rect = element.getBoundingClientRect();
    return {
        selector: selectorForElement(element),
        component: element.getAttribute('data-ui-component') || null,
        clip: {
            left: Math.round(rect.left),
            top: Math.round(rect.top),
            right: Math.round(rect.right),
            bottom: Math.round(rect.bottom),
            width: Math.round(rect.width),
            height: Math.round(rect.height),
        },
    };
}

export function collectOverflowDiagnostics({ allowedSelectors = [], tolerance = 2, browser = null, scope = null } = {}) {
    const contentRoot = document.querySelector('main.main-content') || document.body;
    const viewportWidth = window.innerWidth;
    const documentElement = document.documentElement;
    const body = document.body;
    const pageScrollWidth = Math.max(documentElement.scrollWidth || 0, body?.scrollWidth || 0);
    const bodyScrollWidth = body?.scrollWidth || 0;
    const pageOverflow = Math.max(0, pageScrollWidth - viewportWidth);
    const hasPageOverflow = pageOverflow > tolerance;

    const selectorFor = (element) => {
        if (!(element instanceof Element)) return null;
        if (element.id) return `#${element.id}`;

        const component = element.getAttribute('data-ui-component');
        if (component) return `[data-ui-component="${component}"]`;

        const action = element.getAttribute('data-action');
        if (action) return `[data-action="${action}"]`;

        const classes = Array.from(element.classList || []).slice(0, 2);
        if (classes.length > 0) {
            return `.${classes.join('.')}`;
        }

        return element.tagName.toLowerCase();
    };

    const isAllowed = (element) => {
        for (const selector of allowedSelectors) {
            try {
                if (element.matches(selector) || element.closest(selector)) return true;
            } catch {
                continue;
            }
        }

        return false;
    };

    const isInteractive = (element) => {
        const tag = element.tagName.toLowerCase();
        return tag === 'button'
            || tag === 'select'
            || tag === 'textarea'
            || (tag === 'a' && element.hasAttribute('href'))
            || element.getAttribute('role') === 'button'
            || element.hasAttribute('data-action')
            || element.hasAttribute('aria-label');
    };

    const looksPrimary = (element) => {
        const importance = element.getAttribute('data-ui-importance');
        if (importance === 'primary') return true;

        const label = `${element.getAttribute('aria-label') || ''} ${element.textContent || ''}`.toLowerCase();
        return /\b(primary|save|submit|confirm|apply|delete|remove|more actions)\b/.test(label);
    };

    const scrollableAncestor = (element) => {
        let current = element.parentElement;
        while (current) {
            const style = window.getComputedStyle(current);
            const overflowX = style.overflowX;
            const overflowY = style.overflowY;
            const scrollable = ['auto', 'scroll', 'overlay'].includes(overflowX) || ['auto', 'scroll', 'overlay'].includes(overflowY);
            if (scrollable && current.scrollWidth > current.clientWidth + tolerance) {
                return {
                    selector: selectorFor(current),
                    overflowX,
                    overflowY,
                    scrollWidth: Math.round(current.scrollWidth),
                    clientWidth: Math.round(current.clientWidth),
                };
            }
            current = current.parentElement;
        }

        return null;
    };

    const rootCause = (element) => {
        let current = element.parentElement;
        while (current && current !== contentRoot.parentElement) {
            const style = window.getComputedStyle(current);
            const display = style.display;
            const flexWrap = style.flexWrap;
            const whiteSpace = style.whiteSpace;
            const minWidth = style.minWidth;
            const position = style.position;
            const overflowX = style.overflowX;
            const gridTemplateColumns = style.gridTemplateColumns;

            if (display === 'flex' && flexWrap === 'nowrap') {
                return {
                    selector: selectorFor(current),
                    reason: 'flex-nowrap',
                    display,
                    flexWrap,
                    whiteSpace,
                    minWidth,
                    position,
                    overflowX,
                    gridTemplateColumns,
                };
            }

            if (display === 'grid' && /\b(auto|minmax|repeat)\b/i.test(gridTemplateColumns) && current.scrollWidth > current.clientWidth + tolerance) {
                return {
                    selector: selectorFor(current),
                    reason: 'grid-intrinsic',
                    display,
                    flexWrap,
                    whiteSpace,
                    minWidth,
                    position,
                    overflowX,
                    gridTemplateColumns,
                };
            }

            if (whiteSpace === 'nowrap' && current.scrollWidth > current.clientWidth + tolerance) {
                return {
                    selector: selectorFor(current),
                    reason: 'nowrap',
                    display,
                    flexWrap,
                    whiteSpace,
                    minWidth,
                    position,
                    overflowX,
                    gridTemplateColumns,
                };
            }

            if ((display === 'flex' || display === 'grid') && minWidth === 'auto') {
                return {
                    selector: selectorFor(current),
                    reason: 'missing-min-width-0',
                    display,
                    flexWrap,
                    whiteSpace,
                    minWidth,
                    position,
                    overflowX,
                    gridTemplateColumns,
                };
            }

            if (['hidden', 'clip'].includes(overflowX) && current.scrollWidth > current.clientWidth + tolerance) {
                return {
                    selector: selectorFor(current),
                    reason: 'clipped-overflow',
                    display,
                    flexWrap,
                    whiteSpace,
                    minWidth,
                    position,
                    overflowX,
                    gridTemplateColumns,
                };
            }

            if (['fixed', 'sticky', 'absolute'].includes(position)) {
                return {
                    selector: selectorFor(current),
                    reason: `${position}-position`,
                    display,
                    flexWrap,
                    whiteSpace,
                    minWidth,
                    position,
                    overflowX,
                    gridTemplateColumns,
                };
            }

            current = current.parentElement;
        }

        return null;
    };

    const elements = Array.from(contentRoot.querySelectorAll('*'));
    const issues = [];

    for (const element of elements) {
        if (isAllowed(element)) continue;

        const rect = element.getBoundingClientRect();
        const overflow = rect.right - viewportWidth;
        if (overflow <= tolerance) continue;

        const scrollContainer = scrollableAncestor(element);
        const localScrollable = Boolean(scrollContainer && scrollContainer.scrollWidth > scrollContainer.clientWidth + tolerance);
        if (localScrollable && !hasPageOverflow) continue;

        const component = element.getAttribute('data-ui-component') || element.closest('[data-ui-component]')?.getAttribute('data-ui-component') || null;
        const importance = element.getAttribute('data-ui-importance') || element.closest('[data-ui-importance]')?.getAttribute('data-ui-importance') || null;

        issues.push({
            selector: selectorFor(element),
            tag: element.tagName.toLowerCase(),
            component,
            importance,
            text: (element.textContent || '').trim().slice(0, 120),
            overflow: Math.round(overflow),
            viewportWidth,
            pageScrollWidth,
            bodyScrollWidth,
            pageOverflow: Math.round(pageOverflow),
            hasPageOverflow,
            localScrollable,
            scrollContainer,
            rootCause: rootCause(element),
            interactive: isInteractive(element),
            primaryAction: looksPrimary(element),
            rect: {
                left: Math.round(rect.left),
                top: Math.round(rect.top),
                right: Math.round(rect.right),
                bottom: Math.round(rect.bottom),
                width: Math.round(rect.width),
                height: Math.round(rect.height),
            },
            browser,
            scope,
        });

        if (issues.length >= 20) break;
    }

    return {
        viewportWidth,
        pageScrollWidth,
        bodyScrollWidth,
        hasPageOverflow,
        browser,
        scope,
        issues,
    };
}

export function classifyOverflowIssue(issue, context = {}) {
    const browser = String(context.browser || issue.browser || '').toLowerCase();
    const viewportWidth = context.viewport?.width || issue.viewportWidth || 0;
    const pageOverflow = Number(issue.pageOverflow ?? Math.max(0, (issue.pageScrollWidth || 0) - viewportWidth));
    const hasPageOverflow = pageOverflow > (context.tolerance ?? 2);
    const rootReason = String(issue.rootCause?.reason || '').toLowerCase();
    const rootCause = issue.rootCause || null;
    const interactive = Boolean(issue.interactive);
    const primaryAction = Boolean(issue.primaryAction || issue.importance === 'primary');
    const localScrollable = Boolean(issue.localScrollable);

    if (localScrollable && !hasPageOverflow && !interactive && !primaryAction) {
        return null;
    }

    let kind = 'horizontal-overflow';
    if (primaryAction || (interactive && hasPageOverflow)) {
        kind = 'clipped-action';
    } else if (rootReason === 'flex-nowrap' || rootReason === 'missing-min-width-0' || rootReason === 'nowrap') {
        kind = 'flex-overflow';
    } else if (rootReason === 'grid-intrinsic') {
        kind = 'grid-conflict';
    } else if (browser === 'webkit' && (rootReason === 'grid-intrinsic' || rootReason === 'missing-min-width-0')) {
        kind = 'browser-regression';
    } else if (rootReason === 'clipped-overflow') {
        kind = 'clipped-action';
    } else if (rootReason === 'fixed-position' || rootReason === 'absolute-position' || rootReason === 'sticky-position') {
        kind = 'responsive-collapse';
    }

    let severity = 'warning';
    if (kind === 'clipped-action' || (hasPageOverflow && (interactive || primaryAction))) {
        severity = 'error';
    } else if (hasPageOverflow && pageOverflow > 48) {
        severity = 'error';
    } else if (browser === 'webkit' && (kind === 'grid-conflict' || kind === 'browser-regression')) {
        severity = 'error';
    } else if (kind === 'flex-overflow' || kind === 'grid-conflict') {
        severity = pageOverflow > 24 ? 'error' : 'warning';
    }

    const component = issue.component || context.component || context.scope || null;
    const selector = issue.selector || null;
    const message = kind === 'clipped-action'
        ? `${component || 'UI'} control is clipped by horizontal overflow`
        : rootCause?.reason === 'grid-intrinsic'
            ? `${component || 'Layout'} overflows because grid sizing exceeds the viewport`
            : rootCause?.reason === 'flex-nowrap'
                ? `${component || 'Layout'} overflows because a flex row cannot shrink`
                : pageOverflow > 0
                    ? `Horizontal overflow exceeds the viewport by ${pageOverflow}px`
                    : 'Horizontal overflow detected';

    return {
        severity,
        kind,
        message,
        selector,
        details: {
            component,
            browser: browser || null,
            scope: context.scope || issue.scope || null,
            viewport: viewportWidth ? (viewportWidth < 768 ? 'mobile' : viewportWidth < 992 ? 'tablet' : 'desktop') : null,
            viewportWidth,
            pageScrollWidth: issue.pageScrollWidth ?? null,
            bodyScrollWidth: issue.bodyScrollWidth ?? null,
            pageOverflow,
            overflow: issue.overflow ?? null,
            localScrollable,
            interactive,
            primaryAction,
            rootCause,
            scrollContainer: issue.scrollContainer || null,
            rect: issue.rect || null,
            text: issue.text || null,
            importance: issue.importance || null,
            hasPageOverflow,
        },
    };
}