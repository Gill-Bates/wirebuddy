//
// app/static/js/dashboard_grid.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// GridStack-based layout layer for the dashboard: position, size and visibility of the existing
// KPI/gauge/speedtest/map/recent-peers widgets. It owns NONE of the dashboard data — dashboard.js
// keeps loading data, the Leaflet map and the Chart.js chart unchanged. This script only arranges
// the tiles and persists the arrangement per user via /api/dashboard/layout.
(function () {
    'use strict';

    // Guard: only run on the dashboard page, and never load twice.
    if (!document.getElementById('wb-dashboard-grid')) return;
    if (window.WBDashboardGrid) return;

    const api = window.apiCall;
    const toast = window.wbToast;
    const $ = (id) => document.getElementById(id);
    // Derive a user-facing error string from an ApiError (or any thrown value).
    const messageFrom = (error) => (error && error.message) ? String(error.message) : 'Something went wrong.';

    const CELL_HEIGHT = 72;
    // Half the tile gutter: GridStack insets every tile by this on each side (--wb-dash-gap in css/pages/dashboard.css).
    const GRID_MARGIN = 8;
    // The server's upper bound for a widget's y (see _DASHBOARD_MAX_Y in app/api/dashboard_layout.py);
    // the stored-layout check and separateOverlaps() both clamp to it.
    const MAX_Y = 1000;
    // Map and chart deliberately fill their tile (height 100%), so their content never asks for rows;
    // measuring them would only echo the tile back. Every other tile may grow past its stored height.
    const FILL_IDS = new Set(['speedtest-chart', 'peer-map']);
    const REVEAL_TIMEOUT_MS = 2500; // below the CSS failsafe (4s) so a slow load still reveals via JS
    // Keep in sync with the @media (width <= 991.98px) stacked block in css/pages/dashboard.css. Below lg
    // the 12 columns are too narrow for the KPI and gauge tiles, so phones and tablets share the stack.
    const MOBILE_QUERY = '(max-width: 991.98px)';

    // Factory default derived from the frozen widget registry (dashboard_widgets.js, loaded before
    // this script and exposed as window.WBDashboardRegistry — the single source of truth shared with
    // the Python allowlist via the anti-drift test).
    const { registry } = window.WBDashboardRegistry;
    const DEFAULT_LAYOUT = registry.map((def) => ({
        id: def.id, x: def.defaultX, y: def.defaultY,
        w: def.defaultSize.w, h: def.defaultSize.h,
        visible: def.defaultVisible, label: def.label,
    }));
    const defaultEntry = (def) => ({ id: def.id, x: def.x, y: def.y, w: def.w, h: def.h, visible: def.visible });

    // Latch the first wb:dashboard-data-ready at script load, before the awaited layout GET, so the
    // reveal never misses it: dashboard.js dispatches that event once from the .finally() of its first
    // refreshAll(), which runs in parallel with initLayout(). If the data layer wins the race the
    // listener in revealGrid() would attach too late and the grid would wait out REVEAL_TIMEOUT_MS.
    // Resolving a promise registered here instead makes the ordering irrelevant.
    const dataReady = new Promise((resolve) => document.addEventListener('wb:dashboard-data-ready', resolve, { once: true }));

    let grid = null;
    const widgetState = new Map(); // id -> { id, x, y, w, h, visible }
    let savedLayout = null;
    let savedToastShownThisSession = false;
    let fitFrame = 0;
    const fitRows = new Map(); // id -> rows the last fit set; such a height is content-driven, not stored
    let fitting = false; // true while fit-driven updates run: they are not user layout changes
    let applyingLayout = false;
    let editingNow = false;

    function widgetElement(id) {
        return document.querySelector(`.grid-stack-item[data-widget-id="${id}"]`);
    }

    // A broken/foreign/future-version stored layout must never make the dashboard unusable; any
    // problem here falls back to the known-good default instead of raising.
    function mergeWithDefault(stored) {
        const byId = new Map();
        if (stored && stored.version === 1 && Array.isArray(stored.widgets)) {
            for (const widget of stored.widgets) {
                if (!widget || typeof widget.id !== 'string') continue;
                byId.set(widget.id, widget); // unknown ids are dropped below: only DEFAULT_LAYOUT ids are read
            }
        }
        const merged = DEFAULT_LAYOUT.map((def) => {
            const saved = byId.get(def.id);
            if (!saved) return defaultEntry(def);
            const inRange = (value, max) => Number.isInteger(value) && value >= 0 && value <= max;
            // A widget must fit fully within the vertical bound (y + h <= MAX_Y), matching the server's
            // check in app/api/dashboard_layout.py; otherwise a bottom-pinned tile would pass the
            // resolver unchanged and still cross MAX_Y.
            const valid = inRange(saved.x, 11) && inRange(saved.y, MAX_Y) &&
                Number.isInteger(saved.w) && saved.w >= 1 && saved.w <= 12 &&
                Number.isInteger(saved.h) && saved.h >= 1 && saved.h <= 100 &&
                saved.x + saved.w <= 12 && saved.y + saved.h <= MAX_Y;
            if (!valid) return defaultEntry(def);
            return { id: def.id, x: saved.x, y: saved.y, w: saved.w, h: saved.h, visible: saved.visible !== false };
        });
        // separateOverlaps returns null when overlaps cannot be resolved within the vertical bound. A
        // broken saved layout must never leave the dashboard unusable, so fall back to the known-good
        // default, which has no overlaps and therefore always separates.
        const resolved = separateOverlaps(merged);
        return resolved || separateOverlaps(DEFAULT_LAYOUT.map(defaultEntry)) || DEFAULT_LAYOUT.map(defaultEntry);
    }

    // A stored layout can hold overlapping boxes (e.g. a stale push). The upper/left box keeps its
    // place and the later one moves down. Returns the resolved layout, or null when an overlap cannot
    // be pushed down without crossing MAX_Y: an unresolvable layout is reported, never looped.
    function separateOverlaps(layout) {
        const placed = [];
        const overlaps = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
        const byPosition = layout.filter((entry) => entry.visible).sort((a, b) => a.y - b.y || a.x - b.x);
        for (const entry of byPosition) {
            let blocker;
            while ((blocker = placed.find((other) => overlaps(entry, other)))) {
                // Each shuffle must move the box strictly down and stay within the server's y bound. If
                // the next position makes no forward progress or would cross MAX_Y, the layout is
                // unresolvable: bail out so the caller can discard it, instead of spinning forever.
                const nextY = blocker.y + blocker.h;
                if (nextY <= entry.y || nextY + entry.h > MAX_Y) return null;
                entry.y = nextY;
            }
            placed.push(entry);
        }
        return layout;
    }

    // Two passes: every widget first goes to its final cell shifted far down, then up to its row. A
    // widget moved straight into place would otherwise collide with neighbours still at the template
    // position and shove them (and the final layout) around.
    const PARK_ROWS = 10000;

    function applyLayout(layout) {
        applyingLayout = true;
        grid.batchUpdate();
        try {
            const shown = [];
            for (const entry of layout) {
                widgetState.set(entry.id, { ...entry });
                const el = widgetElement(entry.id);
                if (!el) continue;
                if (entry.visible) {
                    el.classList.remove('d-none');
                    if (!el.gridstackNode) grid.makeWidget(el);
                    grid.update(el, { x: entry.x, y: entry.y + PARK_ROWS, w: entry.w, h: entry.h });
                    shown.push([el, entry]);
                } else {
                    if (el.gridstackNode) grid.removeWidget(el, false);
                    el.classList.add('d-none');
                }
            }
            for (const [el, entry] of shown) grid.update(el, { y: entry.y });
        } finally {
            grid.batchUpdate(false); // commits the batch (GridStack has no separate commit() call)
            applyingLayout = false;
        }
    }

    // Content height without the tile's stretch (cards use h-100), so the measure can shrink again.
    function naturalHeight(inner) {
        const { height, alignSelf } = inner.style;
        inner.style.setProperty('height', 'auto', 'important'); // Bootstrap's h-100 is !important
        inner.style.alignSelf = 'flex-start';
        const natural = inner.offsetHeight + 1; // +1 covers the rounding of offsetHeight
        inner.style.height = height;
        inner.style.alignSelf = alignSelf;
        return natural;
    }

    // Rows so the content fits without clipping. The item is rows * cell tall; the content box is
    // smaller by the frame GridStack leaves around it.
    function neededRows(el) {
        const content = el.querySelector('.grid-stack-item-content');
        const inner = content?.firstElementChild;
        if (!inner) return 1;
        const frame = el.offsetHeight - content.offsetHeight;
        return Math.ceil((naturalHeight(inner) + frame) / CELL_HEIGHT);
    }

    // The stored height is a FLOOR, not a target: the fit only ever grows a tile past its stored size,
    // it never shrinks it below. Otherwise a short list (one peer) would collapse the tile and leave
    // the column shorter than the map beside it. widgetState holds the stored h (syncStateFromGrid
    // never writes a fit-driven height back into it).
    function fitWidget(el, needed) {
        const node = el.gridstackNode;
        if (!node) return;
        const id = el.dataset.widgetId;
        const stored = widgetState.get(id)?.h || 1;
        const rows = Math.max(stored, needed, 1);
        fitRows.set(id, rows);
        if (node.h !== rows) grid.update(el, { h: rows });
    }

    function fitLayout() {
        fitFrame = 0;
        // Below the breakpoint the tiles are stacked with natural height; rows are irrelevant there.
        if (!grid || window.matchMedia(MOBILE_QUERY).matches) return;
        // A fit batch during a drag or resize would swallow the user's own change event.
        if (document.querySelector('.ui-draggable-dragging, .ui-resizable-resizing')) return;
        fitting = true;
        try {
            grid.batchUpdate();
            const items = [...document.querySelectorAll('.grid-stack-item[data-widget-id]')]
                .filter((el) => el.gridstackNode && !el.classList.contains('d-none') && !FILL_IDS.has(el.dataset.widgetId));
            const needed = new Map(items.map((el) => [el, neededRows(el)]));
            // KPI tiles share one height, so a two-metric card that needs a row more does not leave
            // its single-value neighbours short.
            const kpiRows = Math.max(0, ...items.filter((el) => el.dataset.widgetId.startsWith('kpi-')).map((el) => needed.get(el)));
            for (const el of items) fitWidget(el, el.dataset.widgetId.startsWith('kpi-') ? kpiRows : needed.get(el));
        } finally {
            grid.batchUpdate(false);
            fitting = false;
        }
    }

    function scheduleFit() {
        if (!fitFrame) fitFrame = requestAnimationFrame(fitLayout);
    }

    // Anything that changes a tile's content size re-runs the fit: window and sidebar width (grid
    // observer), text and card collapse (mutations), and the icon font arriving late.
    function observeContent() {
        const root = $('wb-dashboard-grid');
        window.addEventListener('resize', scheduleFit);
        document.fonts?.ready.then(scheduleFit);
        new MutationObserver(scheduleFit).observe(root, {
            subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ['class', 'hidden'],
        });
        if (!('ResizeObserver' in window)) return;
        const observer = new ResizeObserver(scheduleFit);
        observer.observe(root);
        root.querySelectorAll('.grid-stack-item-content > *').forEach((inner) => observer.observe(inner));
    }

    // Change events can report a position before GridStack's final compaction or miss pushed
    // neighbours, so the saved layout is read from the settled grid, not from the event deltas.
    function syncStateFromGrid() {
        for (const def of DEFAULT_LAYOUT) {
            const node = widgetElement(def.id)?.gridstackNode;
            const prev = widgetState.get(def.id);
            if (!node || !prev || prev.visible === false) continue;
            const h = fitRows.get(def.id) === node.h ? prev.h : node.h;
            widgetState.set(def.id, { id: def.id, x: node.x, y: node.y, w: node.w, h, visible: true });
        }
    }

    // Only the known structured props travel to the server; nothing from the DOM/HTML is ever sent.
    async function saveLayout() {
        syncStateFromGrid();
        const widgets = DEFAULT_LAYOUT.map((def) => {
            const state = widgetState.get(def.id);
            return { id: def.id, x: state.x, y: state.y, w: state.w, h: state.h, visible: state.visible };
        });
        try {
            await api('PUT', '/api/dashboard/layout', { version: 1, widgets });
            savedLayout = widgets.map((widget) => ({ ...widget }));
            if (!savedToastShownThisSession) {
                savedToastShownThisSession = true;
                toast('Dashboard layout saved.');
            }
        } catch (error) {
            toast(messageFrom(error), 'danger');
            // The PUT was rejected, so the edited arrangement on screen is unsaved and a reload would
            // discard it silently. Roll the grid back to the last persisted layout so what is shown
            // always matches what is stored.
            if (savedLayout) {
                applyLayout(savedLayout.map((entry) => ({ ...entry })));
                renderAddWidgetList();
                scheduleFit();
            }
        }
    }

    function onGridChange(_event, items) {
        if (fitting || applyingLayout || !editingNow) return;
        for (const item of items || []) {
            const id = item.el?.dataset?.widgetId;
            if (!id) continue;
            const prev = widgetState.get(id);
            const h = prev && fitRows.get(id) === item.h ? prev.h : item.h;
            widgetState.set(id, { id, x: item.x, y: item.y, w: item.w, h, visible: true });
        }
    }

    function setEditing(editing) {
        editingNow = editing;
        $('wb-dashboard-grid').classList.toggle('wb-dashboard-editing', editing);
        document.querySelectorAll('.dashboard-widget-header').forEach((header) => header.classList.toggle('d-none', !editing));
        $('wb-dashboard-edit-toggle').classList.toggle('d-none', editing);
        $('wb-dashboard-add-widget').classList.toggle('d-none', !editing);
        $('wb-dashboard-reset-layout').classList.toggle('d-none', !editing);
        $('wb-dashboard-edit-done').classList.toggle('d-none', !editing);
        grid.enableMove(editing);
        grid.enableResize(editing);
        if (editing) savedToastShownThisSession = false; // one save-toast per editing session
        // The button that held focus is hidden now; hand focus to its counterpart (not when a viewport
        // change hid both).
        const next = $(editing ? 'wb-dashboard-edit-done' : 'wb-dashboard-edit-toggle');
        if (next.offsetParent) next.focus();
    }

    function toggleWidgetVisibility(id, visible) {
        const state = widgetState.get(id) || DEFAULT_LAYOUT.find((def) => def.id === id);
        const el = widgetElement(id);
        if (!el) return;
        grid.batchUpdate();
        try {
            if (visible) {
                el.classList.remove('d-none');
                grid.makeWidget(el);
                grid.update(el, { x: state.x, y: state.y, w: state.w, h: state.h });
            } else if (el.gridstackNode) {
                grid.removeWidget(el, false);
                el.classList.add('d-none');
            }
        } finally {
            grid.batchUpdate(false);
        }
        widgetState.set(id, { ...state, visible });
        scheduleFit();
        renderAddWidgetList();
    }

    function renderAddWidgetList() {
        const list = $('wb-add-widget-list');
        list.replaceChildren(
            ...DEFAULT_LAYOUT.map((def) => {
                const visible = widgetState.get(def.id)?.visible !== false;
                const item = document.createElement('li');
                item.className = 'list-group-item d-flex align-items-center justify-content-between gap-2';
                const label = document.createElement('span');
                label.textContent = def.label;
                const button = document.createElement('button');
                button.type = 'button';
                button.className = visible ? 'btn btn-sm btn-outline-secondary' : 'btn btn-sm btn-primary';
                button.textContent = visible ? 'Remove' : 'Add';
                button.setAttribute('aria-label', `${visible ? 'Remove' : 'Add'} widget: ${def.label}`);
                button.addEventListener('click', () => toggleWidgetVisibility(def.id, !visible));
                item.append(label, button);
                return item;
            })
        );
    }

    function resetLayout() {
        applyLayout(DEFAULT_LAYOUT.map(defaultEntry));
        scheduleFit();
        renderAddWidgetList();
        toast('Dashboard layout restored.', 'success');
    }

    function cancelEditing() {
        setEditing(false);
        applyLayout(savedLayout.map((entry) => ({ ...entry })));
        renderAddWidgetList();
        scheduleFit();
    }

    // The grid starts hidden (template class) so tiles never visibly travel from their template
    // positions to the stored layout; it is revealed in one step once positions and heights are final.
    async function revealGrid() {
        try {
            // Icon-font metrics and the first live data change tile heights, so wait for both (bounded).
            // dataReady is latched at script load (see module top) so a data layer that finishes before
            // this point is not missed.
            await Promise.race([
                Promise.all([document.fonts?.ready, dataReady]),
                new Promise((resolve) => setTimeout(resolve, REVEAL_TIMEOUT_MS)),
            ]);
            if (fitFrame) { cancelAnimationFrame(fitFrame); fitFrame = 0; }
            fitLayout();
            // Rehook the chart and map against their final tile sizes once at reveal; both no-op until
            // their instance exists (dashboard.js owns them), then window.resize/resizestop catch up.
            window.WBDashboard?.resizeSpeedtestChart?.();
            window.WBDashboard?.invalidatePeerMap?.();
        } finally {
            $('wb-dashboard-grid').classList.remove('wb-dashboard-grid--loading');
            // Animation is only wanted for user drags and later content changes, not for the first paint.
            requestAnimationFrame(() => grid?.setAnimation(true));
        }
    }

    function buildLayout() {
        grid = window.GridStack.init({
            column: 12,
            cellHeight: CELL_HEIGHT,
            margin: GRID_MARGIN,
            float: true, // no gravity: a tile stays in the free cell it is dropped on
            animate: false,
            disableDrag: true,
            disableResize: true,
            alwaysShowResizeHandle: true, // View-mode CSS hides the grip; edit mode needs it visible.
            handle: '.dashboard-widget-header', // grab a tile by its header strip, like a Grafana panel
        }, '#wb-dashboard-grid');

        grid.on('change', onGridChange);
        grid.on('dragstop', scheduleFit);
        // On resizestop re-fit AND rehook only the matching tile. GridStack 14 stores a single handler
        // per event name, so both concerns share one resizestop handler rather than two registrations
        // (the second would otherwise overwrite the first). GridStack 14 invokes (event, el);
        // attribution is defensive (prefer el, else resolve the item from the event target).
        grid.on('resizestop', (event, el) => {
            scheduleFit();
            const node = (el && el.getAttribute) ? el : event?.target?.closest?.('.grid-stack-item');
            const id = node && node.getAttribute('data-widget-id');
            if (id === 'speedtest-chart') window.WBDashboard?.resizeSpeedtestChart?.();
            else if (id === 'peer-map') window.WBDashboard?.invalidatePeerMap?.();
        });

        // Edit stays disabled until initLayout() has fetched/applied the layout and set savedLayout +
        // widgetState. Otherwise Escape (cancelEditing -> savedLayout.map) or Done (saveLayout reading
        // widgetState) during a slow GET would dereference null/empty state.
        $('wb-dashboard-edit-toggle').disabled = true;
        $('wb-dashboard-edit-toggle').addEventListener('click', () => setEditing(true));
        $('wb-dashboard-edit-done').addEventListener('click', async () => {
            setEditing(false);
            $('wb-dashboard-edit-toggle').disabled = true;
            try { await saveLayout(); } finally { $('wb-dashboard-edit-toggle').disabled = false; }
        });
        $('wb-dashboard-reset-layout').addEventListener('click', resetLayout);
        document.addEventListener('keydown', (event) => {
            if (!editingNow || event.key !== 'Escape' || event.isComposing ||
                event.ctrlKey || event.metaKey || event.altKey || event.shiftKey ||
                (event.target instanceof Element && event.target.closest('input, textarea, [contenteditable]')) ||
                document.querySelector('.modal.show')) return;
            cancelEditing();
        });
        // Positions are ignored by the stacked phone layout, so editing ends when the viewport shrinks
        // to it. Cancel like Escape (restore savedLayout) rather than just leaving editing: an unsaved
        // drag/resize must not stay visually in place after editing has ended.
        window.matchMedia(MOBILE_QUERY).addEventListener('change', (event) => { if (event.matches && editingNow) cancelEditing(); });
    }

    async function initLayout() {
        buildLayout();
        let stored = null;
        try {
            const result = await api('GET', '/api/dashboard/layout');
            stored = result ? result.layout : null;
        } catch (error) {
            // A failed GET falls back to the factory default like a missing/invalid stored layout; the
            // reveal + seam wiring below still run so the veil is always removed.
            toast(messageFrom(error), 'danger');
        }
        savedLayout = mergeWithDefault(stored);
        applyLayout(savedLayout);
        $('wb-dashboard-edit-toggle').disabled = false; // layout applied: editing is now safe (see buildLayout)
        renderAddWidgetList();
        fitLayout();
        observeContent();
        await revealGrid();
    }

    window.WBDashboardGrid = Object.freeze({ initLayout });
    initLayout();
})();
