//
// app/static/js/dashboard_widgets.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Dashboard widget registry: the single JS source for widget identity, layout and order.
// dashboard_grid.js derives DEFAULT_LAYOUT from this array; dashboard.html's data-widget-id blocks
// follow it. The eight ids below are the stable, persisted widget identities for WireBuddy's
// dashboard and must never be renamed (a stored layout references them).
//
// This is NOT the only place a widget id lives: the Python allowlist _DASHBOARD_WIDGETS in
// app/api/dashboard_layout.py stays the backend authority (a hand-written frozenset, no import-time
// IO). The two id sets are kept from drifting by tests/test_dashboard_widget_registry.py, not by
// runtime derivation, so a new widget id must still be added in both places; the anti-drift test
// fails if they diverge.
//
// Contract honoured for the anti-drift guard (see design Decision 3): single-quoted id: literals,
// every entry carries an explicit integer defaultX:, and the array stays wrapped in a frozen
// registry array (opened by the const below and closed by its matching bracket).

/**
 * @typedef {Object} WidgetDef
 * @property {string}  id            Stable widget id (kebab-case). Matches data-widget-id in the DOM
 *                                   and the server allowlist. NEVER renamed (persisted in layouts).
 * @property {string}  label         Human label (Add-Widget list + widget header).
 * @property {'kpi'|'gauge'|'chart'|'map'|'list'} kind   Widget kind (descriptive metadata).
 * @property {{w:number, h:number}}  defaultSize   Default grid cells (w 1..12, h 1..100; x+w<=12).
 * @property {boolean} defaultVisible Whether it is in the factory default layout.
 * @property {number} defaultX       Factory x (required for every entry).
 * @property {number} defaultY       Factory y (required for every entry).
 */

(function () {
    'use strict';

    // The registry array order is the single JS ordering contract: it equals DEFAULT_LAYOUT id order,
    // the template's document (and mobile stack) order and the "Add widget" list order.
    const registry = Object.freeze([
        Object.freeze({ id: 'kpi-nodes', label: 'Nodes', kind: 'kpi', defaultSize: Object.freeze({ w: 3, h: 2 }), defaultVisible: true, defaultX: 0, defaultY: 0 }),
        Object.freeze({ id: 'kpi-connections', label: 'Connections', kind: 'kpi', defaultSize: Object.freeze({ w: 3, h: 2 }), defaultVisible: true, defaultX: 3, defaultY: 0 }),
        Object.freeze({ id: 'kpi-traffic', label: 'Traffic', kind: 'kpi', defaultSize: Object.freeze({ w: 3, h: 2 }), defaultVisible: true, defaultX: 6, defaultY: 0 }),
        Object.freeze({ id: 'kpi-bandwidth', label: 'Bandwidth', kind: 'kpi', defaultSize: Object.freeze({ w: 3, h: 2 }), defaultVisible: true, defaultX: 9, defaultY: 0 }),
        Object.freeze({ id: 'network-gauges', label: 'Network', kind: 'gauge', defaultSize: Object.freeze({ w: 8, h: 5 }), defaultVisible: true, defaultX: 0, defaultY: 2 }),
        Object.freeze({ id: 'speedtest-chart', label: 'Speedtest', kind: 'chart', defaultSize: Object.freeze({ w: 4, h: 5 }), defaultVisible: true, defaultX: 8, defaultY: 2 }),
        Object.freeze({ id: 'peer-map', label: 'Peer Locations', kind: 'map', defaultSize: Object.freeze({ w: 8, h: 8 }), defaultVisible: true, defaultX: 0, defaultY: 7 }),
        Object.freeze({ id: 'recent-peers', label: 'Recent Peer Activity', kind: 'list', defaultSize: Object.freeze({ w: 4, h: 8 }), defaultVisible: true, defaultX: 8, defaultY: 7 }),
    ]);

    // Browser path: expose the frozen registry as a global, consumed by dashboard_grid.js (loaded
    // after this script). Node path (tests): also export via module.exports so the anti-drift pytest
    // (and a plain `node -e require(...)`) can read the registry with no DOM and no bundler.
    if (typeof window !== 'undefined') {
        window.WBDashboardRegistry = Object.freeze({ registry });
    }
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = { registry };
    }
})();
