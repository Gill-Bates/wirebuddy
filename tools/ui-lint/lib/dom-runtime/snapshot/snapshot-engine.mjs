//
// tools/ui-lint/lib/dom-runtime/snapshot/snapshot-engine.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { buildAccessibilitySnapshot } from './accessibility-snapshot.mjs';
import { buildInteractionSnapshot } from './interaction-snapshot.mjs';
import { buildLayoutSnapshot } from './layout-snapshot.mjs';
import { buildRenderingSnapshot } from './rendering-snapshot.mjs';
import { buildOverlaySnapshot } from '../collections/overlays.mjs';
import { buildScrollTopology } from '../collections/scroll-topology.mjs';
import { buildSemanticGroups } from '../collections/semantic-groups.mjs';
import { buildColorSnapshot } from '../rendering/colors.mjs';
import { buildTypographySnapshot } from '../rendering/typography.mjs';
import { buildCoordinateSpaces } from '../geometry/coordinate-spaces.mjs';
import { buildClippingSnapshot } from '../geometry/clipping.mjs';
import { buildStackingContexts } from '../geometry/stacking-contexts.mjs';
import { normalizeGeometry } from '../geometry/transforms.mjs';
import { buildMutationFingerprint } from '../runtime/mutation-fingerprints.mjs';
import { buildStableId } from '../runtime/stable-ids.mjs';
import { buildCompactSchema } from '../exports/compact-schema.mjs';
import { buildVerboseSchema } from '../exports/verbose-schema.mjs';
import { diffSnapshots } from '../exports/snapshot-diff.mjs';

export async function collectDOMSnapshot(page, options = {}) {
    const rawSnapshot = await page.evaluate(({ options }) => {
        const round = (value) => Math.round(value * 10) / 10;
        const normalizeRect = (rect, scale = 1) => ({
            left: round(rect.left * scale),
            top: round(rect.top * scale),
            right: round(rect.right * scale),
            bottom: round(rect.bottom * scale),
            width: round(rect.width * scale),
            height: round(rect.height * scale),
        });
        const parseMatrix = (transformValue) => {
            if (!transformValue || transformValue === 'none') return [1, 0, 0, 1, 0, 0];
            const matrixMatch = /matrix\(([^)]+)\)/.exec(transformValue);
            if (matrixMatch) {
                return matrixMatch[1].split(',').map((part) => Number.parseFloat(part.trim()) || 0).slice(0, 6);
            }
            const matrix3dMatch = /matrix3d\(([^)]+)\)/.exec(transformValue);
            if (matrix3dMatch) {
                const values = matrix3dMatch[1].split(',').map((part) => Number.parseFloat(part.trim()) || 0);
                return [values[0], values[1], values[4], values[5], values[12] || 0, values[13] || 0];
            }
            return [1, 0, 0, 1, 0, 0];
        };
        const safeAttributes = (element) => Array.from(element.attributes).reduce((attributes, attribute) => {
            attributes[attribute.name] = attribute.value;
            return attributes;
        }, {});
        const buildFingerprint = (node) => [node.tag, node.id || '', node.role || '', node.text || '', node.className || '', node.style.display || '', node.style.visibility || ''].join('|');
        const buildStablePath = (node) => [node.domPath.join('>'), node.accessibility.computedRole, String(node.text || '').slice(0, 48).toLowerCase()].join('|');
        const viewport = {
            width: window.innerWidth,
            height: window.innerHeight,
            scrollX: window.scrollX,
            scrollY: window.scrollY,
        };
        const visualViewport = {
            width: window.visualViewport?.width || window.innerWidth,
            height: window.visualViewport?.height || window.innerHeight,
            scale: window.visualViewport?.scale || 1,
            offsetLeft: window.visualViewport?.offsetLeft || 0,
            offsetTop: window.visualViewport?.offsetTop || 0,
        };
        const contentRoot = document.querySelector(options.contentRootSelector || 'main.main-content') || document.body;
        const visited = [];
        const maxNodes = options.maxNodes || 2000;
        let order = 0;

        const visitContainer = (container, pathParts, framePath) => {
            const children = Array.from(container.children || []);
            for (let index = 0; index < children.length && visited.length < maxNodes; index += 1) {
                const element = children[index];
                const style = window.getComputedStyle(element);
                const rect = element.getBoundingClientRect();
                const hiddenByTree = Boolean(
                    element.closest('.modal:not(.show)') ||
                    element.closest('.collapse:not(.show)') ||
                    element.closest('.navbar-collapse:not(.show)') ||
                    element.closest('.hidden') ||
                    element.closest('.d-none') ||
                    element.closest('[hidden]') ||
                    element.closest('[aria-hidden="true"]') ||
                    element.closest('.tab-pane:not(.active)')
                );
                const visible = !hiddenByTree && style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0' && rect.width > 0 && rect.height > 0;
                const scrollable = ['auto', 'scroll', 'overlay'].some((value) => [style.overflow, style.overflowX, style.overflowY].includes(value)) && (element.scrollHeight > element.clientHeight || element.scrollWidth > element.clientWidth);
                const clippingAncestors = [];
                let ancestor = element.parentElement;
                while (ancestor) {
                    const ancestorStyle = window.getComputedStyle(ancestor);
                    if (['hidden', 'clip', 'scroll', 'auto'].includes(ancestorStyle.overflow) || ['hidden', 'clip', 'scroll', 'auto'].includes(ancestorStyle.overflowX) || ['hidden', 'clip', 'scroll', 'auto'].includes(ancestorStyle.overflowY)) {
                        clippingAncestors.push(ancestor.tagName);
                    }
                    ancestor = ancestor.parentElement;
                }

                const domPath = [...pathParts, `${element.tagName.toLowerCase()}:${index}`];
                const node = {
                    order: ++order,
                    domPath,
                    framePath,
                    tag: element.tagName,
                    id: element.id || null,
                    classList: Array.from(element.classList),
                    className: typeof element.className === 'string' ? element.className : '',
                    text: element.textContent?.trim().slice(0, 200) || '',
                    attributes: safeAttributes(element),
                    role: element.getAttribute('role'),
                    rect: normalizeRect(rect, visualViewport.scale || 1),
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
                        willChange: style.willChange,
                        filter: style.filter,
                        isolation: style.isolation,
                        zIndex: style.zIndex,
                        lineHeight: style.lineHeight,
                        letterSpacing: style.letterSpacing,
                        textRendering: style.textRendering,
                        transform: style.transform,
                        transformOrigin: style.transformOrigin,
                    },
                    transforms: {
                        transformMatrix: parseMatrix(style.transform),
                        transformOrigin: style.transformOrigin || '50% 50%',
                    },
                    viewport,
                    visualViewport,
                    clipping: { clippingAncestors },
                    positioning: {
                        fixed: style.position === 'fixed',
                        sticky: style.position === 'sticky',
                    },
                    scroll: {
                        scrollHeight: element.scrollHeight,
                        scrollWidth: element.scrollWidth,
                        clientHeight: element.clientHeight,
                        clientWidth: element.clientWidth,
                        scrollTop: element.scrollTop,
                        scrollLeft: element.scrollLeft,
                        scrollable,
                    },
                    accessibility: {
                        computedRole: element.getAttribute('role') || element.tagName.toLowerCase(),
                        computedName: element.getAttribute('aria-label') || element.getAttribute('title') || element.getAttribute('alt') || element.textContent?.trim().slice(0, 100) || '',
                        labelledBy: element.getAttribute('aria-labelledby'),
                        describedBy: element.getAttribute('aria-describedby'),
                        hidden: hiddenByTree || element.getAttribute('aria-hidden') === 'true' || style.visibility === 'hidden' || style.display === 'none',
                        disabled: Boolean(element.disabled || element.getAttribute('aria-disabled') === 'true'),
                        inert: element.hasAttribute('inert'),
                        focusable: element.matches('a[href], button, input:not([type="hidden"]), select, textarea, summary, [tabindex]') && element.tabIndex >= 0,
                    },
                    interaction: {
                        interactive: element.matches('button, [role="button"], a[href], input:not([type="hidden"]), select, textarea, summary, [tabindex]:not([tabindex="-1"])'),
                        focusable: element.matches('a[href], button, input:not([type="hidden"]), select, textarea, summary, [tabindex]') && element.tabIndex >= 0,
                        hovered: element.matches(':hover'),
                        active: element.matches(':active'),
                        focused: element === document.activeElement,
                    },
                    semantic: {
                        dataUi: element.getAttribute('data-ui'),
                        dataUiRole: element.getAttribute('data-ui-role'),
                        dataUiComponent: element.getAttribute('data-ui-component'),
                        dataUiDensity: element.getAttribute('data-ui-density'),
                        dataUiImportance: element.getAttribute('data-ui-importance'),
                        dataAction: element.getAttribute('data-action'),
                        dataPeerId: element.getAttribute('data-peer-id'),
                        dataNodeId: element.getAttribute('data-node-id'),
                    },
                };

                node.mutationFingerprint = buildFingerprint(node);
                node.stableId = buildStablePath(node);
                node.rendering = {
                    visible,
                    hidden: !visible,
                    clipped: clippingAncestors.length > 0,
                };

                visited.push(node);

                visitContainer(element, domPath, framePath);

                if (element.shadowRoot) {
                    visitContainer(element.shadowRoot, [...domPath, '#shadow-root'], [...framePath, 'shadow']);
                }

                if (element.tagName === 'IFRAME') {
                    try {
                        const frameDocument = element.contentDocument;
                        if (frameDocument?.documentElement) {
                            visitContainer(frameDocument.documentElement, [...domPath, 'iframe'], [...framePath, 'iframe']);
                        }
                    } catch {
                        // Cross-origin frames are intentionally skipped to preserve deterministic snapshots.
                    }
                }
            }
        };

        visitContainer(contentRoot, [contentRoot.tagName.toLowerCase()], [contentRoot.tagName.toLowerCase()]);
        visited.sort((left, right) => left.stableId.localeCompare(right.stableId) || left.order - right.order);

        const collections = {
            interactive: visited.filter((node) => node.interaction.interactive && node.rendering.visible),
            focusable: visited.filter((node) => node.accessibility.focusable && node.rendering.visible),
            badges: visited.filter((node) => node.classList.includes('badge') && node.rendering.visible),
            cards: visited.filter((node) => node.classList.includes('card') || node.semantic.dataUi === 'card'),
            buttons: visited.filter((node) => node.tag === 'BUTTON' || node.classList.includes('btn')),
            modals: visited.filter((node) => node.classList.includes('modal')),
            scrollContainers: visited.filter((node) => node.scroll.scrollable),
            overlays: visited.filter((node) => node.positioning.fixed || node.positioning.sticky || node.accessibility.computedRole === 'dialog'),
        };

        return {
            schemaVersion: 1,
            engine: 'dom-runtime',
            viewport,
            visualViewport,
            breakpoint: viewport.width >= 1400 ? 'xxl' : viewport.width >= 1200 ? 'xl' : viewport.width >= 992 ? 'lg' : viewport.width >= 768 ? 'md' : viewport.width >= 576 ? 'sm' : 'base',
            contentRoot: {
                tag: contentRoot.tagName,
                id: contentRoot.id || null,
                rect: normalizeRect(contentRoot.getBoundingClientRect(), visualViewport.scale || 1),
            },
            nodeCount: visited.length,
            elementCount: visited.length,
            nodes: visited,
            elements: visited,
            collections,
        };
    }, { options });

    const nodes = rawSnapshot.nodes.map((node) => {
        const enriched = {
            ...node,
            coordinateSpaces: buildCoordinateSpaces({ rect: node.rect, transformMatrix: node.transforms.transformMatrix }, {
                scrollX: rawSnapshot.viewport.scrollX,
                scrollY: rawSnapshot.viewport.scrollY,
                scale: rawSnapshot.visualViewport.scale,
            }),
            typography: buildTypographySnapshot(node.style),
            colors: buildColorSnapshot(node.style).colors,
        };

        enriched.clipping = buildClippingSnapshot(enriched);
        enriched.stacking = buildStackingContexts([enriched])[0];
        enriched.stableId = buildStableId(enriched);
        enriched.mutationFingerprint = buildMutationFingerprint(enriched);
        return enriched;
    });

    const collections = {
        interactive: nodes.filter((node) => node.interaction.interactive && node.rendering.visible),
        focusable: nodes.filter((node) => node.accessibility.focusable && node.rendering.visible),
        badges: nodes.filter((node) => node.classList.includes('badge') && node.rendering.visible),
        cards: nodes.filter((node) => node.classList.includes('card') || node.semantic.dataUi === 'card'),
        buttons: nodes.filter((node) => node.tag === 'BUTTON' || node.classList.includes('btn')),
        modals: nodes.filter((node) => node.classList.includes('modal')),
        scrollContainers: nodes.filter((node) => node.scroll.scrollable),
        overlays: nodes.filter((node) => node.positioning.fixed || node.positioning.sticky || node.accessibility.computedRole === 'dialog'),
    };

    const snapshot = {
        ...rawSnapshot,
        nodes,
        elements: nodes,
        collections,
    };

    snapshot.semanticGroups = buildSemanticGroups(nodes);
    snapshot.scrollTopology = buildScrollTopology(nodes);
    snapshot.overlays = buildOverlaySnapshot(nodes);
    snapshot.layout = buildLayoutSnapshot(snapshot);
    snapshot.rendering = buildRenderingSnapshot(snapshot);
    snapshot.accessibility = buildAccessibilitySnapshot(snapshot);
    snapshot.interaction = buildInteractionSnapshot(snapshot);
    snapshot.compact = buildCompactSchema({
        schemaVersion: snapshot.schemaVersion,
        viewport: snapshot.viewport,
        collections: snapshot.collections,
        counts: { nodes: snapshot.nodeCount },
    });
    snapshot.verbose = buildVerboseSchema(snapshot);
    snapshot.diff = diffSnapshots(snapshot, snapshot);

    return snapshot;
}

export function querySnapshot(snapshot, predicate) {
    return (snapshot.nodes || snapshot.elements || []).filter(predicate);
}

export function getByDataUi(snapshot, uiName) {
    return querySnapshot(snapshot, (node) => node.semantic?.dataUi === uiName || node.dataUi === uiName);
}

export function getByClass(snapshot, className) {
    return querySnapshot(snapshot, (node) => node.classList?.includes(className));
}

export function getByTag(snapshot, tagName) {
    const upper = tagName.toUpperCase();
    return querySnapshot(snapshot, (node) => node.tag === upper);
}
