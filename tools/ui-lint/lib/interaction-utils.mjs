//
// tools/ui-lint/lib/interaction-utils.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

const VIEWPORT_BREAKPOINTS = {
    mobile: 768,
    tablet: 992,
};

function normalizeText(value) {
    return String(value || '').trim().toLowerCase();
}

function attrSelector(name, value) {
    if (!value) return '';
    return `[${name}=${JSON.stringify(String(value))}]`;
}

export function getViewportAwareTouchTarget(tokens, viewport = {}) {
    const width = Number(viewport.width || viewport.innerWidth || 0);
    const interaction = tokens?.interaction || {};
    const mobile = interaction.touchTargetMinMobile ?? interaction.touchTargetMin ?? 44;
    const tablet = interaction.touchTargetMinTablet ?? interaction.touchTargetMin ?? 40;
    const desktop = interaction.touchTargetMinDesktop ?? interaction.touchTargetMin ?? 32;

    if (width > 0 && width < VIEWPORT_BREAKPOINTS.mobile) return mobile;
    if (width > 0 && width < VIEWPORT_BREAKPOINTS.tablet) return tablet;
    return desktop;
}

export function getDensityMultiplier(density = '') {
    return normalizeText(density) === 'compact' ? 0.85 : 1;
}

export function getInteractionDensity(target = {}) {
    return normalizeText(target.dataUiDensity || target.density || target.closestDensity || '');
}

export function getInteractionImportance(target = {}) {
    const explicit = normalizeText(target.dataUiImportance || target.importance || '');
    if (['primary', 'secondary', 'tertiary'].includes(explicit)) return explicit;

    const action = normalizeText(target.dataAction || target.action || '');
    const classList = Array.isArray(target.classList) ? target.classList.map(normalizeText) : [];
    const ariaLabel = normalizeText(target.ariaLabel || '');

    if (classList.includes('btn-primary') || classList.includes('btn-danger') || classList.includes('btn-outline-danger')) {
        return 'primary';
    }
    if (target.dataUiCritical === true || target.dataUiCritical === 'true') {
        return 'primary';
    }
    if (action.startsWith('delete') || action.startsWith('remove') || action.startsWith('save') || action.startsWith('submit') || action.startsWith('restart')) {
        return 'primary';
    }
    if (action.includes('filter') || action.includes('toggle') || action.includes('download') || action.includes('show-qr') || action.includes('speedtest')) {
        return 'secondary';
    }
    if (ariaLabel.includes('more actions') || ariaLabel.includes('info')) {
        return 'tertiary';
    }
    return 'tertiary';
}

export function buildInteractionSelector(target = {}) {
    const tag = String(target.tag || '').trim().toLowerCase();
    const parts = [];

    if (target.id) {
        return `[id=${JSON.stringify(String(target.id))}]`;
    }

    if (target.dataUiComponent) parts.push(attrSelector('data-ui-component', target.dataUiComponent));
    if (target.dataAction) parts.push(attrSelector('data-action', target.dataAction));
    if (target.dataPeerId) parts.push(attrSelector('data-peer-id', target.dataPeerId));
    if (target.dataNodeId) parts.push(attrSelector('data-node-id', target.dataNodeId));
    if (target.dataUiRole) parts.push(attrSelector('data-ui-role', target.dataUiRole));
    if (target.dataUiImportance) parts.push(attrSelector('data-ui-importance', target.dataUiImportance));
    if (target.ariaLabel) parts.push(attrSelector('aria-label', target.ariaLabel));
    if (target.role) parts.push(attrSelector('role', target.role));

    if (!parts.length) {
        if (tag) return tag;
        return null;
    }

    return `${tag || 'button'}${parts.join('')}`;
}

export async function inspectInteractionTargets(page, targets) {
    return page.evaluate(({ targets: inputTargets }) => {
        const samplePoints = (rect) => {
            const insetX = Math.max(6, Math.min(10, rect.width * 0.2));
            const insetY = Math.max(6, Math.min(10, rect.height * 0.2));
            return [
                [rect.left + rect.width / 2, rect.top + rect.height / 2],
                [rect.left + insetX, rect.top + insetY],
                [rect.right - insetX, rect.top + insetY],
                [rect.left + insetX, rect.bottom - insetY],
                [rect.right - insetX, rect.bottom - insetY],
            ];
        };

        return inputTargets.map((target) => {
            const selector = target.selector;
            const element = selector ? document.querySelector(selector) : null;
            if (!element) {
                return {
                    ...target,
                    exists: false,
                    clickable: false,
                    occluded: false,
                    hidden: true,
                    width: 0,
                    height: 0,
                    pointerEvents: 'none',
                    visibility: 'hidden',
                    display: 'none',
                    opacity: '0',
                };
            }

            const style = window.getComputedStyle(element);
            const rect = element.getBoundingClientRect();
            const hiddenAncestor = element.closest('[hidden], [aria-hidden="true"], .d-none, .invisible, .visually-hidden, [inert]');
            const hidden = Boolean(
                hiddenAncestor ||
                style.display === 'none' ||
                style.visibility === 'hidden' ||
                style.opacity === '0'
            );
            const points = samplePoints(rect);
            const pointHits = points.map(([x, y]) => {
                if (x < 0 || y < 0 || x >= window.innerWidth || y >= window.innerHeight) {
                    return { x, y, hit: false, topTag: null, occluded: true };
                }
                const topEl = document.elementFromPoint(x, y);
                const hit = Boolean(topEl && (topEl === element || element.contains(topEl)));
                return {
                    x,
                    y,
                    hit,
                    topTag: topEl?.tagName || null,
                    topClassName: typeof topEl?.className === 'string' ? topEl.className : null,
                };
            });
            const occluded = !pointHits.some((hit) => hit.hit);
            const closestComponent = element.closest('[data-ui-component]');
            const closestDensity = element.closest('[data-ui-density]');
            const importance = element.getAttribute('data-ui-importance') || null;
            const isDisabled = Boolean(
                element.disabled ||
                element.getAttribute('aria-disabled') === 'true' ||
                element.getAttribute('disabled') !== null
            );
            const pointerEvents = style.pointerEvents || 'auto';
            const inert = Boolean(element.closest('[inert]') || element.hasAttribute('inert'));
            const clickable = !hidden && !isDisabled && !inert && pointerEvents !== 'none' && !occluded;

            return {
                ...target,
                exists: true,
                clickable,
                occluded,
                hidden,
                hiddenAncestor: Boolean(hiddenAncestor),
                disabled: isDisabled,
                inert,
                width: Math.round(rect.width),
                height: Math.round(rect.height),
                left: Math.round(rect.left),
                top: Math.round(rect.top),
                right: Math.round(rect.right),
                bottom: Math.round(rect.bottom),
                pointerEvents,
                visibility: style.visibility,
                display: style.display,
                opacity: style.opacity,
                component: closestComponent?.getAttribute('data-ui-component') || target.component || null,
                density: closestDensity?.getAttribute('data-ui-density') || target.density || null,
                importance: importance || target.importance || null,
                pointHits,
            };
        });
    }, { targets });
}

export function groupInteractionViolations(violations = []) {
    const groups = new Map();

    for (const violation of violations) {
        const details = violation.details || {};
        const normalized = {
            ...violation,
            component: violation.component || details.component || null,
            density: violation.density || details.density || null,
            importance: violation.importance || details.importance || null,
            viewport: violation.viewport || details.viewport || null,
            clickable: violation.clickable ?? details.clickable ?? null,
            occluded: violation.occluded ?? details.occluded ?? null,
            hidden: violation.hidden ?? details.hidden ?? null,
            disabled: violation.disabled ?? details.disabled ?? null,
            inert: violation.inert ?? details.inert ?? null,
            width: violation.width ?? details.width ?? 0,
            height: violation.height ?? details.height ?? 0,
            required: violation.required ?? details.required ?? 0,
        };

        const key = [
            normalized.component || 'ui',
            normalized.density || 'regular',
            normalized.importance || 'tertiary',
        ].join('|');

        const current = groups.get(key);
        if (!current) {
            groups.set(key, {
                ...normalized,
                items: [normalized],
                count: 1,
            });
            continue;
        }

        current.items.push(normalized);
        current.count += 1;
        current.width = Math.min(current.width, normalized.width);
        current.height = Math.min(current.height, normalized.height);
        current.required = Math.max(current.required, normalized.required);
        current.clickable = current.clickable && normalized.clickable;
        current.occluded = current.occluded || normalized.occluded;
        current.hidden = current.hidden || normalized.hidden;
        current.disabled = current.disabled || normalized.disabled;
        current.inert = current.inert || normalized.inert;
        current.selector = current.selector || normalized.selector;
        current.message = current.count > 1
            ? `${current.component || 'UI'} contains ${current.count} ${new Set(current.items.map((item) => item.kind)).size > 1 ? 'problematic' : current.items[0].kind === 'click-target-occluded' ? 'occluded' : 'undersized'} controls`
            : normalized.message;
        current.severity = current.items.some((item) => item.severity === 'error') ? 'error' : 'warning';
    }

    return Array.from(groups.values()).map((group) => ({
        ...group,
        message: group.count > 1
            ? `${group.component || 'UI'} contains ${group.count} ${new Set(group.items.map((item) => item.kind)).size > 1 ? 'problematic' : group.items[0].kind === 'click-target-occluded' ? 'occluded' : 'undersized'} controls`
            : group.message,
    }));
}