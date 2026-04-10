//
// app/static/js/traffic.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

/**
 * Traffic Page - WireBuddy
 * Displays per-peer traffic charts and traffic breakdown by country/ASN.
 * 
 * Security: This file is loaded as an external script to comply with CSP (no 'unsafe-inline').
 * Data from the server is passed via data- attributes on the #traffic-app element.
 */
(function () {
    'use strict';

    const DEBUG = false;
    const AUTO_REFRESH_MS = 30000;
    const API_TIMEOUT_MS = 25000;
    const MAX_BACKOFF_MS = 300000;
    const MIN_VISIBLE_REFRESH_INTERVAL_MS = 5000;
    const RESIZE_FETCH_THRESHOLD = 0.2;

    // Responsive data point settings
    const MIN_POINTS = 10;
    const MAX_POINTS = 120;
    // Pixels per data point (higher = fewer points)
    const PIXELS_PER_POINT = 8;

    // State variables (scoped within IIFE to avoid global pollution)
    let trafficCombinedChart = null;
    let cleanupComplete = false;
    let cachedTrafficData = null;
    let cachedCountryData = null;
    let cachedASNData = null;
    let refreshScheduler = null;
    let trafficRangeDebounce = null;
    let lastVisibleRefresh = 0;
    let lastMaxPoints = 0;
    let resizeDebounce = null;
    let isInitialRender = true;
    let knownTrafficPeers = [];
    let lastCountryRenderKey = '';
    let lastASNRenderKey = '';
    let themeObserver = null;
    let visibilityHandler = null;
    let resizeHandler = null;
    let peerFilterHandler = null;
    let rangeChangeHandler = null;
    let peerFilterTimeout = null; // Timeout handle for peer filter debounce
    let peerFilterAbort = null; // AbortController for peer filter transition race handling
    let lastInvalidPeerWarned = '';

    // Color palette for multiple peers
    const peerColors = Object.freeze([
        '#3b82f6',   // blue
        '#10b981',   // emerald green
        '#6f42c1',   // purple
        '#0dcaf0',   // cyan
        '#f59e0b',   // amber orange
        '#d63384',   // pink
        '#20c997',   // teal
        '#ef4444',   // red
    ]);

    // Get user permissions and config from data attributes
    const appEl = document.getElementById('traffic-app');
    // Handle both "true" and "1" (SQLite stores booleans as integers)
    const isAdmin = appEl?.dataset.isAdmin === 'true' || appEl?.dataset.isAdmin === '1';
    const trafficAnalysisEnabled = appEl?.dataset.trafficAnalysisEnabled === 'true' || appEl?.dataset.trafficAnalysisEnabled === '1';

    // DOM element references
    const trafficCombinedCanvas = isAdmin ? document.getElementById('trafficCombinedChart') : null;
    const trafficCombinedLoading = isAdmin ? document.getElementById('traffic-combined-loading') : null;
    const trafficCombinedWrap = isAdmin ? document.getElementById('traffic-combined-chart-wrap') : null;
    const trafficEmptyState = isAdmin ? document.getElementById('traffic-empty-state') : null;
    // Note: trafficPeerFilter only exists in admin view (controlled by {% if user['is_admin'] %})
    const trafficPeerFilter = document.getElementById('traffic-peer-filter');
    const trafficRange = document.getElementById('traffic-range');

    // Country traffic elements
    const countryLoading = document.getElementById('country-traffic-loading');
    const countryContent = document.getElementById('country-traffic-content');
    const countryEmpty = document.getElementById('country-traffic-empty');
    const countrySummary = document.getElementById('country-traffic-summary');
    const countryTbody = document.getElementById('country-traffic-tbody');

    // ASN traffic elements
    const asnLoading = document.getElementById('asn-traffic-loading');
    const asnContent = document.getElementById('asn-traffic-content');
    const asnEmpty = document.getElementById('asn-traffic-empty');
    const asnSummary = document.getElementById('asn-traffic-summary');
    const asnTbody = document.getElementById('asn-traffic-tbody');

    // Utility functions from WBShared
    const dbg = window.WBShared?.createDebugLogger?.('Traffic', DEBUG)
        || ((...args) => { if (DEBUG) console.log('[Traffic]', ...args); });
    const clearElement = window.WBShared?.clearElement || ((el) => { if (el) el.replaceChildren(); });
    const isAbortError = window.WBShared?.isAbortError || ((err) => err?.code === 'ABORTED' || err?.name === 'AbortError' || err?.message === 'Request cancelled');

    // Defensive fallback if WBShared.formatTrafficMetric is missing
    const formatTrafficMetric = window.WBShared?.formatTrafficMetric
        || (() => { throw new Error('WBShared.formatTrafficMetric required'); });

    // Use shared chartEmptyState function
    const chartEmptyState = window.WBShared?.chartEmptyState || ((text = 'No data available.') => {
        const wrapper = document.createElement('div');
        wrapper.className = 'chart-empty-state';
        const icon = document.createElement('span');
        icon.className = 'material-icons';
        icon.textContent = 'show_chart';
        icon.setAttribute('aria-hidden', 'true');
        const msg = document.createElement('span');
        msg.className = 'chart-empty-state-text';
        msg.textContent = text;
        wrapper.append(icon, msg);
        return wrapper;
    });

    /**
     * Validate that a URL is safe for use in img src attributes.
     * Only allows same-origin static paths.
     */
    function isSafeImageUrl(url) {
        if (!url || typeof url !== 'string') return false;
        try {
            const u = new URL(url, window.location.origin);
            if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
            return u.origin === window.location.origin && u.pathname.startsWith('/static/');
        } catch {
            return false;
        }
    }

    // Convert range key to human-readable label
    function getRangeLabel(rangeKey) {
        const labels = {
            '6h': 'last 6 hours',
            '24h': 'last 24 hours',
            '7d': 'last 7 days',
            '30d': 'last 30 days',
            '90d': 'last 90 days',
            '180d': 'last 180 days',
            'y1': 'last year',
        };
        return labels[rangeKey] || rangeKey;
    }

    function isValidPeerFilterValue(value) {
        if (!value) return false;
        const trimmed = String(value).trim();
        if (!trimmed) return false;
        return /^[A-Za-z0-9._\- #]+$/.test(trimmed);
    }

    function getServerPeerFilterOrEmpty() {
        const raw = trafficPeerFilter?.value || '';
        if (!raw) return '';
        if (isValidPeerFilterValue(raw)) return raw;

        if (lastInvalidPeerWarned !== raw) {
            lastInvalidPeerWarned = raw;
            const msg = 'Selected peer cannot be server-filtered due to unsupported characters.';
            if (typeof wbToast === 'function') {
                wbToast(msg, 'warning');
            } else {
                console.warn('Traffic page:', msg, raw);
            }
        }
        return '';
    }

    /**
     * Create a table cell element with text content.
     */
    function createCell(tag, className, textContent) {
        const cell = document.createElement(tag);
        if (className) cell.className = className;
        if (textContent !== undefined && textContent !== null) cell.textContent = textContent;
        return cell;
    }

    /**
     * Create a traffic metric inline element (arrow + value).
     */
    function createTrafficMetric(value, unit, direction) {
        const wrapper = document.createElement('span');
        wrapper.className = 'traffic-metric-inline';

        const arrow = document.createElement('span');
        arrow.className = `traffic-arrow traffic-arrow-${direction}`;
        arrow.setAttribute('aria-hidden', 'true');
        arrow.textContent = direction === 'rx' ? '↓' : '↑';

        const small = document.createElement('small');
        small.textContent = formatTrafficMetric(value, unit);

        wrapper.appendChild(arrow);
        wrapper.appendChild(small);
        return wrapper;
    }

    /**
     * Create combined RX/TX cell for mobile view.
     */
    function createRxTxCombinedCell(rx, tx, unit) {
        const cell = document.createElement('td');
        cell.className = 'text-end text-nowrap traffic-rxtx-combined';

        const stack = document.createElement('div');
        stack.className = 'rxtx-stack';

        // RX line
        const rxLine = document.createElement('span');
        rxLine.className = 'rxtx-line';
        const rxArrow = document.createElement('span');
        rxArrow.className = 'rxtx-arrow rx-arrow';
        rxArrow.textContent = '↓';
        const rxSmall = document.createElement('small');
        rxSmall.textContent = formatTrafficMetric(rx, unit);
        rxLine.appendChild(rxArrow);
        rxLine.appendChild(rxSmall);

        // TX line
        const txLine = document.createElement('span');
        txLine.className = 'rxtx-line';
        const txArrow = document.createElement('span');
        txArrow.className = 'rxtx-arrow tx-arrow';
        txArrow.textContent = '↑';
        const txSmall = document.createElement('small');
        txSmall.textContent = formatTrafficMetric(tx, unit);
        txLine.appendChild(txArrow);
        txLine.appendChild(txSmall);

        stack.appendChild(rxLine);
        stack.appendChild(txLine);
        cell.appendChild(stack);
        return cell;
    }

    /**
     * Create traffic progress bars (RX + TX).
     */
    function createTrafficBars(rx, tx, total, maxTotal, unit) {
        const wrapper = document.createElement('div');
        wrapper.className = 'd-flex gap-1 mt-1';

        const pct = maxTotal > 0 ? (total / maxTotal) * 100 : 0;
        wrapper.style.width = `${Math.max(pct, 3)}%`;

        const rxPct = total > 0 ? (rx / total) * 100 : 50;
        const txPct = 100 - rxPct;

        // RX bar (decorative - data already in table)
        const rxBar = document.createElement('div');
        rxBar.className = 'traffic-bar traffic-bar-rx';
        rxBar.style.width = `${rxPct}%`;
        rxBar.setAttribute('aria-hidden', 'true');
        rxBar.setAttribute('title', `RX ${formatTrafficMetric(rx, unit)}`);

        // TX bar (decorative - data already in table)
        const txBar = document.createElement('div');
        txBar.className = 'traffic-bar traffic-bar-tx';
        txBar.style.width = `${txPct}%`;
        txBar.setAttribute('aria-hidden', 'true');
        txBar.setAttribute('title', `TX ${formatTrafficMetric(tx, unit)}`);

        wrapper.appendChild(rxBar);
        wrapper.appendChild(txBar);
        return wrapper;
    }

    /**
     * Creates a short label for chart x-axis based on time range.
     */
    function shortLabel(isoStr, hours) {
        const d = new Date(isoStr);
        if (isNaN(d.getTime())) return '—';
        try {
            const h = Number(hours);
            if (h > 168) {
                return d.toLocaleDateString([], { month: 'short', day: '2-digit' });
            }
            if (h > 24) {
                return d.toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
            }
            return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        } catch {
            return d.toISOString().slice(0, 16).replace('T', ' ');
        }
    }

    function getChartColors() {
        const isDark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
        return {
            gridColor: isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)',
            textColor: isDark ? '#9ca3af' : '#6b7280',
            rx: '#10b981',  // emerald green for download
            tx: '#f59e0b',  // amber orange for upload
        };
    }

    function getChartRenderProfile() {
        const vw = window.innerWidth || 1024;
        if (vw <= 575) {
            return {
                minPoints: 12,
                maxPoints: 24,
                pixelsPerPoint: 24,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointHitRadius: 14,
                maxXTicks: 4,
            };
        }
        if (vw <= 767) {
            return {
                minPoints: 16,
                maxPoints: 30,
                pixelsPerPoint: 18,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointHitRadius: 12,
                maxXTicks: 5,
            };
        }
        if (vw <= 991) {
            return {
                minPoints: 20,
                maxPoints: 60,
                pixelsPerPoint: 12,
                pointRadius: 1.5,
                pointHoverRadius: 4,
                pointHitRadius: 8,
                maxXTicks: 8,
            };
        }
        return {
            minPoints: MIN_POINTS,
            maxPoints: MAX_POINTS,
            pixelsPerPoint: PIXELS_PER_POINT,
            pointRadius: 3,
            pointHoverRadius: 5,
            pointHitRadius: 8,
            maxXTicks: 10,
        };
    }

    /**
     * Calculate optimal number of data points based on chart container width.
     * Returns fewer points for smaller screens to improve readability.
     */
    function getOptimalMaxPoints() {
        const profile = getChartRenderProfile();
        // Use the chart wrap element width, fallback to viewport width
        let chartWidth = trafficCombinedWrap?.clientWidth || window.innerWidth;
        // Account for card padding on mobile
        if (window.innerWidth < 576) {
            chartWidth = Math.max(chartWidth - 32, 200);
        }
        // Calculate points: wider screen = more points
        const calculated = Math.floor(chartWidth / profile.pixelsPerPoint);
        return Math.max(profile.minPoints, Math.min(calculated, profile.maxPoints));
    }

    function updateChartTheme() {
        const colors = getChartColors();
        if (trafficCombinedChart) {
            if (trafficCombinedChart.options?.plugins?.legend?.labels) {
                trafficCombinedChart.options.plugins.legend.labels.color = colors.textColor;
            }
            if (trafficCombinedChart.options?.scales?.x?.ticks) trafficCombinedChart.options.scales.x.ticks.color = colors.textColor;
            if (trafficCombinedChart.options?.scales?.x?.title) trafficCombinedChart.options.scales.x.title.color = colors.textColor;
            if (trafficCombinedChart.options?.scales?.x?.grid) trafficCombinedChart.options.scales.x.grid.color = colors.gridColor;
            if (trafficCombinedChart.options?.scales?.y?.ticks) trafficCombinedChart.options.scales.y.ticks.color = colors.textColor;
            if (trafficCombinedChart.options?.scales?.y?.title) trafficCombinedChart.options.scales.y.title.color = colors.textColor;
            if (trafficCombinedChart.options?.scales?.y?.grid) trafficCombinedChart.options.scales.y.grid.color = colors.gridColor;
            trafficCombinedChart.update();
        }
    }

    function destroyTrafficCharts() {
        // Use Chart.js registry as source of truth to avoid tracking multiple references
        if (trafficCombinedCanvas && typeof Chart !== 'undefined') {
            const existingChart = Chart.getChart(trafficCombinedCanvas);
            if (existingChart) {
                existingChart.destroy();
            }
        }
        trafficCombinedChart = null;
    }

    /**
     * Generic traffic table renderer to eliminate duplication between country and ASN tables.
     * 
     * @param {Object} config - Render configuration
     * @param {Array} config.items - Array of items to render (countries or ASNs)
     * @param {string} config.unit - Traffic unit (B, KB, MB, GB, TB)
     * @param {string} config.peerFilter - Selected peer filter value
     * @param {Object} config.elements - DOM element references
     * @param {Function} config.createFirstCell - Function to create the first cell (flag or ASN badge)
     * @param {Function} config.createNameCell - Function to create the name cell
     * @param {Function} config.buildRenderKey - Function to build the deduplication key
     * @param {Object} config.renderKey - Object with get/set for last render key
     * @param {string} config.itemNoun - Singular noun for summary (e.g., 'country', 'provider')
     * @param {string} config.itemNounPlural - Plural noun for summary
     * @param {boolean} config.hasPeerData - Whether peer attribution data exists
     * @param {number} config.unfilteredCount - Count before peer filtering
     */
    function renderTrafficTable(config) {
        const {
            items, unit, peerFilter, elements, createFirstCell, createNameCell,
            buildRenderKey, renderKey, itemNoun, itemNounPlural, hasPeerData, unfilteredCount
        } = config;
        const { loading, content, empty, summary, tbody } = elements;

        // Hide loading indicator on first render
        if (loading && !loading.classList.contains('d-none')) {
            loading.classList.add('d-none');
        }

        if (items.length === 0) {
            const emptyKey = `empty:${peerFilter}`;
            renderKey.set(emptyKey);
            if (content) content.classList.add('d-none');
            if (empty) {
                empty.classList.remove('d-none');
                clearElement(empty);
                // More specific message when peer filter is active but no peer data exists
                let emptyMsg = `No ${itemNoun} traffic data available.`;
                if (peerFilter) {
                    if (!hasPeerData && unfilteredCount > 0) {
                        emptyMsg = 'Peer attribution not available. Enable Traffic Analysis in Settings.';
                    } else {
                        emptyMsg = `No ${itemNoun} traffic data for this peer.`;
                    }
                }
                empty.appendChild(chartEmptyState(emptyMsg));
            }
            if (summary) summary.textContent = '';
            return;
        }

        if (content) content.classList.remove('d-none');
        if (empty) empty.classList.add('d-none');

        // Summary text with time range
        const totalTraffic = items.reduce((s, item) => s + item.total, 0);
        const rangeLabel = getRangeLabel(trafficRange?.value || '24h');
        if (summary) {
            const noun = items.length === 1 ? itemNoun : itemNounPlural;
            summary.textContent = `${items.length} ${noun} · ${formatTrafficMetric(totalTraffic, unit)} (${rangeLabel})`;
        }

        if (!tbody) return;
        const maxTotal = items[0]?.total || 1;

        // Render deduplication - skip if data unchanged
        const newRenderKey = buildRenderKey(items, unit, peerFilter);
        if (newRenderKey === renderKey.get()) return;
        renderKey.set(newRenderKey);

        // Build rows using DOM construction (safe from XSS)
        const fragment = document.createDocumentFragment();
        items.forEach((item, i) => {
            const row = document.createElement('tr');
            row.className = 'traffic-row';
            row.style.setProperty('--row-i', i);

            // First cell (flag or ASN badge)
            const firstCell = createFirstCell(item);

            // Name + bars cell
            const nameCell = createNameCell(item);
            nameCell.appendChild(createTrafficBars(item.rx, item.tx, item.total, maxTotal, unit));

            // RX cell (desktop)
            const rxCell = createCell('td', 'text-end text-nowrap traffic-col-rx');
            rxCell.appendChild(createTrafficMetric(item.rx, unit, 'rx'));

            // TX cell (desktop)
            const txCell = createCell('td', 'text-end text-nowrap traffic-col-tx');
            txCell.appendChild(createTrafficMetric(item.tx, unit, 'tx'));

            // Combined RX/TX cell (mobile)
            const combinedCell = createRxTxCombinedCell(item.rx, item.tx, unit);

            // Total cell
            const totalCell = createCell('td', 'text-end text-nowrap fw-medium', formatTrafficMetric(item.total, unit));

            row.appendChild(firstCell);
            row.appendChild(nameCell);
            row.appendChild(rxCell);
            row.appendChild(txCell);
            row.appendChild(combinedCell);
            row.appendChild(totalCell);
            fragment.appendChild(row);
        });

        clearElement(tbody);
        tbody.appendChild(fragment);
    }

    /* ── Country Traffic ───────────────────────────────── */

    async function refreshCountryTraffic(signal) {
        try {
            const range = trafficRange?.value || '24h';
            const peerFilter = getServerPeerFilterOrEmpty();
            let url = `/api/wireguard/stats/traffic-by-country?range_key=${encodeURIComponent(range)}`;
            if (peerFilter) {
                url += `&peer=${encodeURIComponent(peerFilter)}`;
            }
            const result = await api(
                'GET',
                url,
                null,
                { signal, timeoutMs: API_TIMEOUT_MS },
            );
            cachedCountryData = result;
            renderCountryTraffic();
            return true;
        } catch (e) {
            if (isAbortError(e)) return true;
            console.error('Country traffic error:', e);
            return false;
        }
    }

    function renderCountryTraffic() {
        const data = cachedCountryData?.data || cachedCountryData;
        if (!data) return;

        let countries = Array.isArray(data.countries) ? data.countries : [];
        const unit = data.display_unit || 'MB';

        // Check if peer attribution data exists (any country has peer_names)
        const hasPeerData = countries.some(c => Array.isArray(c.peer_names) && c.peer_names.length > 0);

        // Note: Server-side filtering is now applied via the `peer` query param.
        // Client-side filtering is kept as fallback for historical data without by_peer.
        const peerFilter = getServerPeerFilterOrEmpty();
        const unfilteredCount = countries.length;

        // Filter out countries with zero or negligible traffic (that would display as "0")
        const minDisplayThreshold = (unit === 'MB' || unit === 'GB') ? 0.05 : 0.005;
        countries = countries.filter(c => c.total >= minDisplayThreshold);

        renderTrafficTable({
            items: countries,
            unit,
            peerFilter,
            elements: {
                loading: countryLoading,
                content: countryContent,
                empty: countryEmpty,
                summary: countrySummary,
                tbody: countryTbody,
            },
            createFirstCell: (country) => {
                const flagCell = createCell('td', 'text-center');
                if (country.flag && isSafeImageUrl(country.flag)) {
                    const img = document.createElement('img');
                    img.src = country.flag;
                    img.alt = country.name ? `Flag of ${country.name}` : '';
                    img.className = 'country-flag';
                    img.loading = 'lazy';
                    // Attach error handler during creation
                    img.addEventListener('error', () => { img.style.display = 'none'; }, { once: true });
                    flagCell.appendChild(img);
                } else {
                    const icon = document.createElement('span');
                    icon.className = 'material-icons traffic-fallback-icon';
                    icon.setAttribute('aria-hidden', 'true');
                    icon.textContent = 'public';
                    flagCell.appendChild(icon);
                }
                return flagCell;
            },
            createNameCell: (country) => {
                const nameCell = createCell('td');
                const nameDiv = document.createElement('div');
                nameDiv.className = 'fw-medium';
                nameDiv.title = country.name || '';
                nameDiv.textContent = country.name || '';
                nameCell.appendChild(nameDiv);
                return nameCell;
            },
            buildRenderKey: (items, u, pf) => {
                // Use item identifiers for robust deduplication (avoids hash collisions)
                const hash = items.map((c, i) =>
                    `${c.code || c.name || i}:${c.total.toFixed(2)}`
                ).join(';');
                return `${u}|${pf}|${items.length}|${hash}`;
            },
            renderKey: {
                get: () => lastCountryRenderKey,
                set: (key) => { lastCountryRenderKey = key; }
            },
            itemNoun: 'country',
            itemNounPlural: 'countries',
            hasPeerData,
            unfilteredCount,
        });
    }

    /* ── ASN Traffic ───────────────────────────────── */

    async function refreshASNTraffic(signal) {
        try {
            const range = trafficRange?.value || '24h';
            const peerFilter = getServerPeerFilterOrEmpty();
            let url = `/api/wireguard/stats/traffic-by-asn?range_key=${encodeURIComponent(range)}`;
            if (peerFilter) {
                url += `&peer=${encodeURIComponent(peerFilter)}`;
            }
            const result = await api(
                'GET',
                url,
                null,
                { signal, timeoutMs: API_TIMEOUT_MS },
            );
            cachedASNData = result;
            renderASNTraffic();
            return true;
        } catch (e) {
            if (isAbortError(e)) return true;
            console.error('ASN traffic error:', e);
            return false;
        }
    }

    function renderASNTraffic() {
        const data = cachedASNData?.data || cachedASNData;
        if (!data) return;

        let asns = Array.isArray(data.asns) ? data.asns : [];
        const unit = data.display_unit || 'MB';

        // Check if peer attribution data exists (any ASN has peer_names)
        const hasPeerData = asns.some(a => Array.isArray(a.peer_names) && a.peer_names.length > 0);

        // Note: Server-side filtering is now applied via the `peer` query param.
        // Client-side filtering is kept as fallback for historical data without by_peer.
        const peerFilter = getServerPeerFilterOrEmpty();
        const unfilteredCount = asns.length;

        // Filter out ASNs with zero or negligible traffic (that would display as "0")
        const minDisplayThreshold = (unit === 'MB' || unit === 'GB') ? 0.05 : 0.005;
        asns = asns.filter(a => a.total >= minDisplayThreshold);

        renderTrafficTable({
            items: asns,
            unit,
            peerFilter,
            elements: {
                loading: asnLoading,
                content: asnContent,
                empty: asnEmpty,
                summary: asnSummary,
                tbody: asnTbody,
            },
            createFirstCell: (asn) => {
                const asnCell = createCell('td', 'traffic-col-asn');
                const asnBadge = document.createElement('span');
                asnBadge.className = 'badge bg-secondary bg-opacity-25 text-body asn-badge';
                asnBadge.textContent = asn.asn === '0' ? '–' : `AS${asn.asn}`;
                asnCell.appendChild(asnBadge);
                return asnCell;
            },
            createNameCell: (asn) => {
                const nameCell = createCell('td');
                const nameDiv = document.createElement('div');
                nameDiv.className = 'fw-medium';
                nameDiv.title = asn.name || '';
                nameDiv.textContent = asn.name || '';

                // Add inline ASN for mobile (only if ASN exists)
                if (asn.asn && asn.asn !== '0') {
                    const asnInline = document.createElement('span');
                    asnInline.className = 'asn-inline';
                    asnInline.textContent = `AS${asn.asn}`;
                    nameDiv.appendChild(asnInline);
                }

                nameCell.appendChild(nameDiv);
                return nameCell;
            },
            buildRenderKey: (items, u, pf) => {
                // Use item identifiers for robust deduplication (avoids hash collisions)
                const hash = items.map((a, i) =>
                    `${a.asn || a.name || i}:${a.total.toFixed(2)}`
                ).join(';');
                return `${u}|${pf}|${items.length}|${hash}`;
            },
            renderKey: {
                get: () => lastASNRenderKey,
                set: (key) => { lastASNRenderKey = key; }
            },
            itemNoun: 'provider',
            itemNounPlural: 'providers',
            hasPeerData,
            unfilteredCount,
        });
    }

    /* ── Peer Filter Management ───────────────────────────────── */

    function updateTrafficPeerFilter(peers) {
        if (!trafficPeerFilter) return;
        const currentValue = trafficPeerFilter.value;

        const peerOptions = peers.map(p => ({
            value: p.name || p.key || 'Unknown',
            key: p.key || p.name,
            label: p.name || p.key || 'Unknown',
        }));

        const newKeys = peerOptions.map(p => p.key).sort().join(',');
        const oldKeys = knownTrafficPeers.map(p => p.key).sort().join(',');
        if (newKeys === oldKeys) return;

        knownTrafficPeers = peerOptions;

        // Build select options using DOM construction
        const defaultOpt = document.createElement('option');
        defaultOpt.value = '';
        defaultOpt.textContent = 'All Peers';
        trafficPeerFilter.replaceChildren(defaultOpt);

        peerOptions.forEach(p => {
            const opt = document.createElement('option');
            opt.value = p.value;
            opt.dataset.key = p.key;
            opt.textContent = p.label;
            trafficPeerFilter.appendChild(opt);
        });

        trafficPeerFilter.value = currentValue;
        if (trafficPeerFilter.value !== currentValue) trafficPeerFilter.value = '';
    }

    /* ── Traffic Charts (Admin only) ───────────────────────────────── */

    async function refreshTrafficCharts(signal) {
        if (!isAdmin) return true;
        try {
            const range = trafficRange?.value || '24h';
            const maxPoints = getOptimalMaxPoints();
            lastMaxPoints = maxPoints;
            dbg(`Fetching traffic data: range=${range}, max_points=${maxPoints}, viewport=${window.innerWidth}px`);
            const traffic = await api(
                'GET',
                `/api/wireguard/stats/traffic?range_key=${encodeURIComponent(range)}&max_points=${maxPoints}`,
                null,
                { signal, timeoutMs: API_TIMEOUT_MS },
            );
            cachedTrafficData = traffic;
            renderTrafficCharts();
            return true;
        } catch (e) {
            if (isAbortError(e)) return true;
            console.error('Traffic chart error:', e);
            // Hide loading spinner and show error state on failure
            if (trafficCombinedLoading) trafficCombinedLoading.classList.add('d-none');
            if (trafficCombinedWrap) trafficCombinedWrap.classList.add('d-none');
            if (trafficEmptyState) {
                trafficEmptyState.classList.remove('d-none');
                clearElement(trafficEmptyState);
                trafficEmptyState.appendChild(chartEmptyState('Failed to load traffic data. Will retry...'));
            }
            return false;
        }
    }

    function renderTrafficCharts() {
        if (!isAdmin || !trafficCombinedWrap || !trafficEmptyState || !trafficCombinedCanvas) return;
        // Handle both wrapped { data: {...} } and bare response formats
        const traffic = cachedTrafficData?.data || cachedTrafficData;
        if (!traffic) return;

        // Hide loading indicator and show content on first render
        if (trafficCombinedLoading && !trafficCombinedLoading.classList.contains('d-none')) {
            trafficCombinedLoading.classList.add('d-none');
        }

        // Check if logging is disabled
        if (traffic.logging_disabled) {
            destroyTrafficCharts();
            trafficCombinedWrap.classList.add('d-none');
            if (trafficCombinedLoading) trafficCombinedLoading.classList.add('d-none');
            trafficEmptyState.classList.remove('d-none');
            clearElement(trafficEmptyState);
            trafficEmptyState.appendChild(chartEmptyState('Logging disabled. Enable logging in Settings → Logs to collect traffic data.'));
            return;
        }

        const peerFilter = trafficPeerFilter?.value || '';
        const hours = Number(traffic?.hours || 24);
        const labels = (traffic?.labels || []).map(ts => shortLabel(ts, hours));
        const unit = traffic?.display_unit || 'MB';
        let peers = Array.isArray(traffic?.peers_display) && traffic.peers_display.length
            ? traffic.peers_display
            : (Array.isArray(traffic?.peers) ? traffic.peers : []);

        // Use all_peers for filter dropdown (includes peers without traffic data)
        const allPeersForFilter = Array.isArray(traffic?.all_peers) ? traffic.all_peers : peers;
        updateTrafficPeerFilter(allPeersForFilter);
        if (peerFilter) {
            peers = peers.filter(p => p.key === peerFilter || p.name === peerFilter);
        }

        // Show empty state if no peers available
        if (peers.length === 0) {
            destroyTrafficCharts();
            trafficCombinedWrap.classList.add('d-none');
            if (trafficCombinedLoading) trafficCombinedLoading.classList.add('d-none');
            trafficEmptyState.classList.remove('d-none');
            clearElement(trafficEmptyState);
            trafficEmptyState.appendChild(chartEmptyState('No traffic data available.'));
            return;
        }

        trafficCombinedWrap.classList.remove('d-none');
        if (trafficCombinedLoading) trafficCombinedLoading.classList.add('d-none');
        trafficEmptyState.classList.add('d-none');

        // Build datasets — theme-aware colors
        const colors = getChartColors();
        const chartProfile = getChartRenderProfile();
        const datasets = [];
        const isAllPeersView = !peerFilter && peers.length > 1;

        if (isAllPeersView) {
            // All Peers: one cumulative (RX+TX) line per peer
            peers.forEach((peer, idx) => {
                const rx = Array.isArray(peer.rx) ? peer.rx : [];
                const tx = Array.isArray(peer.tx) ? peer.tx : [];
                const peerName = peer.name || peer.key || `Peer ${idx + 1}`;
                const color = peerColors[idx % peerColors.length];
                // Sum RX + TX per bucket
                const total = rx.map((r, i) => Number(r || 0) + Number(tx[i] || 0));
                datasets.push({
                    label: peerName,
                    data: total,
                    borderColor: color,
                    backgroundColor: 'transparent',
                    fill: false,
                    tension: 0.3,
                    pointRadius: chartProfile.pointRadius,
                    pointHoverRadius: chartProfile.pointHoverRadius,
                    pointHitRadius: chartProfile.pointHitRadius,
                    borderWidth: 2,
                });
            });
        } else {
            // Single peer: separate RX and TX lines
            const peer = peers[0];
            const rx = Array.isArray(peer.rx) ? peer.rx : [];
            const tx = Array.isArray(peer.tx) ? peer.tx : [];
            datasets.push({
                label: '↓ RX',
                data: rx.map(v => Number(v || 0)),
                borderColor: colors.rx,
                backgroundColor: `${colors.rx}1f`,
                fill: true,
                tension: 0.3,
                pointRadius: chartProfile.pointRadius,
                pointHoverRadius: chartProfile.pointHoverRadius,
                pointHitRadius: chartProfile.pointHitRadius,
                borderWidth: 2,
            });
            datasets.push({
                label: '↑ TX',
                data: tx.map(v => Number(v || 0)),
                borderColor: colors.tx,
                backgroundColor: 'transparent',
                fill: false,
                tension: 0.3,
                pointRadius: chartProfile.pointRadius,
                pointHoverRadius: chartProfile.pointHoverRadius,
                pointHitRadius: chartProfile.pointHitRadius,
                borderWidth: 2,
            });
        }

        if (trafficCombinedChart) {
            trafficCombinedChart.data.labels = labels;
            trafficCombinedChart.data.datasets = datasets;
            if (trafficCombinedChart.options?.scales?.y?.title) {
                trafficCombinedChart.options.scales.y.title.text = unit;
            }
            if (trafficCombinedChart.options?.plugins?.tooltip?.callbacks) {
                trafficCombinedChart.options.plugins.tooltip.callbacks.label =
                    c => `${c.dataset.label}: ${formatTrafficMetric(c.parsed.y || 0, unit)}`;
            }
            if (trafficCombinedChart.options?.scales?.y?.ticks) {
                trafficCombinedChart.options.scales.y.ticks.callback =
                    v => formatTrafficMetric(v, unit);
            }
            if (trafficCombinedChart.options?.scales?.x?.ticks) {
                trafficCombinedChart.options.scales.x.ticks.maxTicksLimit = chartProfile.maxXTicks;
            }
            // Update legend to recalculate sums with current unit
            if (trafficCombinedChart.options?.plugins?.legend?.labels) {
                trafficCombinedChart.options.plugins.legend.labels.generateLabels = (chart) => {
                    const original = Chart.defaults.plugins.legend.labels.generateLabels(chart);
                    return original.map((item) => {
                        const dataset = chart.data.datasets[item.datasetIndex];
                        if (dataset && Array.isArray(dataset.data)) {
                            const sum = dataset.data.reduce((acc, val) => acc + (Number(val) || 0), 0);
                            const formattedSum = formatTrafficMetric(sum, unit);
                            item.text = `${item.text} (${formattedSum})`;
                        }
                        return item;
                    });
                };
            }
            trafficCombinedChart.update('none');
            return;
        }

        // Guard against Chart.js not being loaded
        if (typeof Chart === 'undefined') {
            console.error('Chart.js not loaded');
            return;
        }

        // Ensure no orphaned Chart.js instance exists for this canvas
        const existingChart = Chart.getChart(trafficCombinedCanvas);
        if (existingChart) {
            existingChart.destroy();
        }

        const ctx = trafficCombinedCanvas?.getContext('2d');
        if (!ctx) {
            console.error('Traffic chart canvas context unavailable');
            return;
        }
        trafficCombinedChart = new Chart(ctx, {
            type: 'line',
            data: { labels, datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: {
                        display: true,
                        position: 'bottom',
                        labels: {
                            usePointStyle: true,
                            pointStyle: 'rect',
                            boxWidth: 10,
                            color: colors.textColor,
                            padding: 12,
                            font: { size: 11 },
                            generateLabels: (chart) => {
                                const original = Chart.defaults.plugins.legend.labels.generateLabels(chart);
                                // Add sum to each label
                                return original.map((item, index) => {
                                    const dataset = chart.data.datasets[item.datasetIndex];
                                    if (dataset && Array.isArray(dataset.data)) {
                                        const sum = dataset.data.reduce((acc, val) => acc + (Number(val) || 0), 0);
                                        const formattedSum = formatTrafficMetric(sum, unit);
                                        item.text = `${item.text} (${formattedSum})`;
                                    }
                                    return item;
                                });
                            },
                        },
                    },
                    tooltip: {
                        callbacks: {
                            label: c => `${c.dataset.label}: ${formatTrafficMetric(c.parsed.y || 0, unit)}`,
                        },
                    },
                },
                scales: {
                    x: {
                        title: { display: true, text: 'Time', color: colors.textColor },
                        ticks: { maxTicksLimit: chartProfile.maxXTicks, color: colors.textColor },
                        grid: { color: colors.gridColor },
                    },
                    y: {
                        beginAtZero: true,
                        title: { display: true, text: unit, color: colors.textColor },
                        grid: { color: colors.gridColor },
                        ticks: {
                            maxTicksLimit: 6,
                            color: colors.textColor,
                            callback: v => formatTrafficMetric(v, unit),
                        },
                    },
                },
            },
        });
    }

    /* ── Refresh Management ───────────────────────────────── */

    async function refreshAll() {
        if (!refreshScheduler) return;
        await refreshScheduler.refresh();
    }

    function startAutoRefresh(intervalMs) {
        if (!refreshScheduler) return;
        refreshScheduler.start(intervalMs);
    }

    function stopAutoRefresh() {
        if (!refreshScheduler) return;
        refreshScheduler.stop();
    }

    /**
     * Centralized cleanup to ensure consistency across beforeunload and pagehide.
     * Idempotent - safe to call multiple times.
     */
    function cleanup() {
        if (cleanupComplete) return;
        cleanupComplete = true;

        clearTimeout(trafficRangeDebounce);
        clearTimeout(resizeDebounce);
        clearTimeout(peerFilterTimeout);
        if (peerFilterAbort) {
            peerFilterAbort.abort();
            peerFilterAbort = null;
        }
        if (themeObserver) {
            themeObserver.disconnect();
            themeObserver = null;
        }
        if (visibilityHandler) {
            document.removeEventListener('visibilitychange', visibilityHandler);
            visibilityHandler = null;
        }
        if (resizeHandler) {
            window.removeEventListener('resize', resizeHandler);
            resizeHandler = null;
        }
        if (peerFilterHandler && trafficPeerFilter) {
            trafficPeerFilter.removeEventListener('change', peerFilterHandler);
            peerFilterHandler = null;
        }
        if (rangeChangeHandler && trafficRange) {
            trafficRange.removeEventListener('change', rangeChangeHandler);
            rangeChangeHandler = null;
        }
        // Remove cleanup listeners to prevent duplicate registrations on bfcache restore
        window.removeEventListener('beforeunload', cleanup);
        window.removeEventListener('pagehide', cleanup);
        destroyTrafficCharts();
        if (refreshScheduler) {
            refreshScheduler.destroy();
            refreshScheduler = null;
        }
    }

    /* ── Initialization ───────────────────────────────── */

    function initTraffic() {
        dbg('Initializing traffic page...');

        // Skip initialization if traffic analysis is disabled
        if (!trafficAnalysisEnabled) {
            dbg('Traffic analysis disabled, skipping initialization');
            return;
        }

        // Reset state for bfcache restore
        isInitialRender = true;
        cleanupComplete = false;

        // Clean up any existing chart from bfcache restore.
        destroyTrafficCharts();

        if (typeof api !== 'function' || typeof wbToast !== 'function') {
            console.error('Traffic page requires api() and wbToast() from base.html');
            return;
        }
        if (!window.WBShared?.RefreshScheduler) {
            console.error('Traffic page requires WBShared.RefreshScheduler');
            return;
        }

        // Validate required DOM elements BEFORE setting up resources
        if (!trafficRange) {
            console.error('Traffic page: required element #traffic-range not found');
            return;
        }
        if (!countryTbody || !asnTbody) {
            console.error('Traffic page: required table elements not found');
            return;
        }

        refreshScheduler = new window.WBShared.RefreshScheduler({
            autoRefreshMs: AUTO_REFRESH_MS,
            maxBackoffMs: MAX_BACKOFF_MS,
            log: dbg,
            onAllFailed: ({ consecutiveFailures, backoffMs }) => {
                dbg(`All API calls failed (${consecutiveFailures}x), next refresh in ${Math.round(backoffMs / 1000)}s`);
            },
            onRecovered: () => {
                dbg('API recovered, refresh interval reset to', AUTO_REFRESH_MS / 1000, 's');
            },
            refreshFn: async (signal) => {
                // Guard against scheduler being destroyed during refresh
                if (!refreshScheduler) return false;

                const results = await Promise.allSettled([
                    refreshTrafficCharts(signal),
                    refreshCountryTraffic(signal),
                    refreshASNTraffic(signal),
                ]);
                const statuses = results.map(r => (r.status === 'fulfilled' ? r.value : false));
                return statuses.some(v => v === true);
            },
        });

        // Observe theme changes for chart color updates
        themeObserver = new MutationObserver(() => updateChartTheme());
        themeObserver.observe(document.documentElement, {
            attributes: true,
            attributeFilter: ['data-bs-theme'],
        });

        // Store handler reference for cleanup
        visibilityHandler = () => {
            if (document.hidden) {
                stopAutoRefresh();
            } else {
                const now = Date.now();
                if (now - lastVisibleRefresh > MIN_VISIBLE_REFRESH_INTERVAL_MS) {
                    lastVisibleRefresh = now;
                    refreshAll();
                }
                startAutoRefresh();
            }
        };
        document.addEventListener('visibilitychange', visibilityHandler);

        // Centralized cleanup on page unload
        window.addEventListener('beforeunload', cleanup);
        window.addEventListener('pagehide', cleanup);

        peerFilterHandler = () => {
            // Cancel previous transition workflow to ensure latest selection wins.
            if (peerFilterAbort) {
                peerFilterAbort.abort();
            }
            peerFilterAbort = new AbortController();
            const signal = peerFilterAbort.signal;

            // Cancel any pending timeout from previous filter change
            clearTimeout(peerFilterTimeout);
            peerFilterTimeout = null;

            // Server-side filtering requires a full refresh to re-fetch data with the new peer filter.
            // This ensures Country and ASN traffic reflect only the selected peer's traffic.
            if (!trafficCombinedWrap) {
                // No chart to fade, refresh immediately
                void refreshAll();
                return;
            }

            // Skip fade effect on initial render - only fade when user actively changes filter
            if (isInitialRender) {
                void refreshAll();
                return;
            }

            // Fade out chart, refresh on transition complete
            let handled = false;
            const handleTransitionEnd = async () => {
                if (handled || signal.aborted) return;
                handled = true;
                if (peerFilterTimeout) {
                    clearTimeout(peerFilterTimeout);
                    peerFilterTimeout = null;
                }
                try {
                    await refreshAll();
                } catch (e) {
                    dbg('Refresh failed during filter transition:', e);
                }
                if (signal.aborted) return;
                requestAnimationFrame(() => {
                    if (signal.aborted) return;
                    trafficCombinedWrap.classList.remove('traffic-chart-fading');
                });
                if (peerFilterAbort?.signal === signal) {
                    peerFilterAbort = null;
                }
            };

            trafficCombinedWrap.classList.remove('traffic-chart-fading');
            trafficCombinedWrap.addEventListener('transitionend', () => {
                void handleTransitionEnd();
            }, { once: true, signal });

            // Restart transition without forced synchronous reflow.
            requestAnimationFrame(() => {
                requestAnimationFrame(() => {
                    if (signal.aborted) return;
                    trafficCombinedWrap.classList.add('traffic-chart-fading');
                });
            });

            // Fallback timeout in case transitionend doesn't fire
            peerFilterTimeout = setTimeout(() => {
                void handleTransitionEnd();
            }, 300);
        };
        trafficPeerFilter?.addEventListener('change', peerFilterHandler);

        rangeChangeHandler = () => {
            clearTimeout(trafficRangeDebounce);
            trafficRangeDebounce = setTimeout(() => {
                refreshAll();
            }, 200);
        };
        trafficRange?.addEventListener('change', rangeChangeHandler);

        // Responsive resize handler (admin only - non-admins have no chart)
        // Chart.js handles visual resizing automatically. We only need to fetch new data
        // if the optimal point count increases beyond what we have cached.
        if (isAdmin) {
            resizeHandler = () => {
                clearTimeout(resizeDebounce);
                resizeDebounce = setTimeout(() => {
                    const newMaxPoints = getOptimalMaxPoints();

                    if (lastMaxPoints <= 0) {
                        lastMaxPoints = newMaxPoints;
                        dbg(`Resize baseline set: ${newMaxPoints} points`);
                        return;
                    }

                    // Re-fetch when the optimal point count changes significantly
                    // (both up AND down — e.g. rotating phone from landscape to portrait)
                    if (Math.abs(newMaxPoints - lastMaxPoints) > lastMaxPoints * RESIZE_FETCH_THRESHOLD) {
                        dbg(`Resize detected: ${lastMaxPoints} -> ${newMaxPoints} points, fetching new data...`);
                        void refreshAll();
                    } else {
                        // Just re-render from cache - Chart.js handles the responsive layout
                        dbg(`Resize detected: chart will adapt automatically`);
                    }
                }, 500);
            };
            window.addEventListener('resize', resizeHandler);
        }

        // Initial data fetch and start auto-refresh
        refreshAll()
            .catch(e => dbg('Initial refresh failed:', e))
            .finally(() => {
                startAutoRefresh();
                isInitialRender = false;
            });
    }

    // Run initialization when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTraffic);
    } else {
        initTraffic();
    }
})();
