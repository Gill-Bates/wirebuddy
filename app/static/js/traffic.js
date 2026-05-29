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
    const MAX_ALL_PEER_SERIES = 12;
    const MIN_VISIBLE_REFRESH_INTERVAL_MS = 5000;
    const RESIZE_FETCH_THRESHOLD = 0.2;
    const RANGE_LABELS = Object.freeze({
        '6h': 'last 6 hours',
        '24h': 'last 24 hours',
        '7d': 'last 7 days',
        '30d': 'last 30 days',
        '90d': 'last 90 days',
        '180d': 'last 180 days',
        'y1': 'last year',
    });

    // Flag icons base URL - validated to ensure safe origins only
    const DEFAULT_FLAG_ICON_BASE = 'https://cdn.jsdelivr.net/npm/flag-icons@7.3.2/flags/4x3';
    const ALLOWED_FLAG_ORIGINS = new Set(['cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com']);

    function safeFlagBaseUrl(raw) {
        try {
            const url = new URL(String(raw || DEFAULT_FLAG_ICON_BASE));
            // Allow same-origin paths
            if (url.origin === window.location.origin) {
                return url.pathname.replace(/\/+$/, '');
            }
            // Allow known CDNs with HTTPS only
            if (url.protocol === 'https:' && ALLOWED_FLAG_ORIGINS.has(url.hostname)) {
                return url.href.replace(/\/+$/, '');
            }
            return DEFAULT_FLAG_ICON_BASE;
        } catch {
            return DEFAULT_FLAG_ICON_BASE;
        }
    }

    const FLAG_ICON_BASE_URL = safeFlagBaseUrl(null);

    // Responsive data point settings
    const MIN_POINTS = 10;
    const MAX_POINTS = 120;
    // Pixels per data point (higher = fewer points)
    const PIXELS_PER_POINT = 8;

    // State variables (scoped within IIFE to avoid global pollution)
    let trafficCombinedChart = null;
    let cleanupComplete = false;
    let cachedTrafficData = null;
    let cachedTrafficLabels = null;
    let cachedCountryData = null;
    let cachedASNData = null;
    let refreshScheduler = null;
    let trafficRangeDebounce = null;
    let lastVisibleRefresh = 0;
    let lastMaxPoints = 0;
    let resizeDebounce = null;
    let knownTrafficPeerKeys = '';
    let themeObserver = null;
    let visibilityHandler = null;
    let resizeHandler = null;
    let peerFilterHandler = null;
    let rangeChangeHandler = null;
    let pagehideHandler = null;
    let peerFilterTimeout = null; // Timeout handle for peer filter debounce
    let pendingRefreshScopes = [];
    let lastInvalidPeerWarned = '';

    const countryRenderKey = { current: '' };
    const asnRenderKey = { current: '' };

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
    const isAdmin = appEl?.dataset.isAdmin === 'true';
    const trafficAnalysisEnabled = appEl?.dataset.trafficAnalysisEnabled === 'true';

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

    const WBShared = window.WBShared;
    if (!WBShared) {
        throw new Error('WBShared must be loaded before traffic.js');
    }

    // Utility functions from WBShared
    const dbg = WBShared.createDebugLogger?.('Traffic', DEBUG)
        || ((...args) => { if (DEBUG) console.log('[Traffic]', ...args); });
    const clearElement = WBShared.clearElement;
    const isAbortError = WBShared.isAbortError;
    const formatTrafficMetric = WBShared.formatTrafficMetric;
    const chartEmptyState = WBShared.chartEmptyState;

    function getRangeLabel(rangeKey) {
        return RANGE_LABELS[rangeKey] ?? rangeKey;
    }

    function countryCodeToFlagEmoji(countryCode) {
        if (!/^[a-z]{2}$/i.test(countryCode)) return '';

        try {
            return countryCode
                .toUpperCase()
                .split('')
                .map((char) => String.fromCodePoint(127397 + char.charCodeAt(0)))
                .join('');
        } catch {
            return '';
        }
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
     * Create a traffic metric inline element.
     * Returns a wrapper span containing a directional arrow and a formatted value.
     *
     * @param {number} value - Raw traffic value.
     * @param {string} unit - Display unit used by formatTrafficMetric.
     * @param {'rx'|'tx'} direction - Traffic direction; 'rx' renders ↓, 'tx' renders ↑.
     * @returns {HTMLSpanElement}
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

        const rxLine = document.createElement('span');
        rxLine.className = 'rxtx-line';
        rxLine.appendChild(createTrafficMetric(rx, unit, 'rx'));

        const txLine = document.createElement('span');
        txLine.className = 'rxtx-line';
        txLine.appendChild(createTrafficMetric(tx, unit, 'tx'));

        stack.appendChild(rxLine);
        stack.appendChild(txLine);
        cell.appendChild(stack);
        return cell;
    }

    /**
     * Create traffic progress bars (RX + TX).
     */
    function createTrafficBars(rx, tx, total, maxTotal, unit) {
        // Defensive coercion: server may send strings for numeric fields
        const numTotal = Number(total) || 0;
        const numMax = Number(maxTotal) || 1;
        const numRx = Number(rx) || 0;

        const pct = numMax > 0 ? (numTotal / numMax) * 100 : 0;
        const rxPct = numTotal > 0 ? (numRx / numTotal) * 100 : 50;
        const txPct = 100 - rxPct;

        const svgNS = 'http://www.w3.org/2000/svg';
        const wrapper = document.createElementNS(svgNS, 'svg');
        wrapper.classList.add('traffic-bar');
        wrapper.setAttribute('width', `${Math.max(pct, 3)}%`);
        wrapper.setAttribute('height', '6');
        wrapper.setAttribute('viewBox', '0 0 100 6');
        wrapper.setAttribute('preserveAspectRatio', 'none');
        wrapper.setAttribute('aria-hidden', 'true');

        // RX bar (decorative - data already in table)
        const rxBar = document.createElementNS(svgNS, 'rect');
        rxBar.classList.add('traffic-bar-rx');
        rxBar.setAttribute('x', '0');
        rxBar.setAttribute('y', '0');
        rxBar.setAttribute('width', `${rxPct}`);
        rxBar.setAttribute('height', '6');
        rxBar.setAttribute('title', `RX ${formatTrafficMetric(rx, unit)}`);

        // TX bar (decorative - data already in table)
        const txBar = document.createElementNS(svgNS, 'rect');
        txBar.classList.add('traffic-bar-tx');
        txBar.setAttribute('x', `${rxPct}`);
        txBar.setAttribute('y', '0');
        txBar.setAttribute('width', `${txPct}`);
        txBar.setAttribute('height', '6');
        txBar.setAttribute('title', `TX ${formatTrafficMetric(tx, unit)}`);

        wrapper.appendChild(rxBar);
        wrapper.appendChild(txBar);
        return wrapper;
    }

    function showLoadingState({ loading, content, empty, summary }, summaryText = '') {
        if (loading) loading.classList.remove('d-none');
        if (content) {
            content.classList.add('d-none');
            content.setAttribute('aria-busy', 'true');
        }
        if (empty) empty.classList.add('d-none');
        if (summary) summary.textContent = summaryText;
    }

    function showSectionError({ loading, content, empty, summary }, message) {
        if (loading) loading.classList.add('d-none');
        if (content) {
            content.classList.add('d-none');
            content.removeAttribute('aria-busy');
        }
        if (empty) {
            empty.classList.remove('d-none');
            clearElement(empty);
            empty.appendChild(chartEmptyState(message));
        }
        if (summary) summary.textContent = '';
    }

    function showTrafficLoading(options = {}) {
        const { chart = false, country = false, asn = false } = options;

        if (chart && isAdmin) {
            if (trafficCombinedWrap) {
                trafficCombinedWrap.classList.add('d-none');
                trafficCombinedWrap.setAttribute('aria-busy', 'true');
            }
            if (trafficEmptyState) trafficEmptyState.classList.add('d-none');
            if (trafficCombinedLoading) trafficCombinedLoading.classList.remove('d-none');
        }

        if (country) {
            showLoadingState(
                {
                    loading: countryLoading,
                    content: countryContent,
                    empty: countryEmpty,
                    summary: countrySummary,
                },
                'Calculating...',
            );
        }

        if (asn) {
            showLoadingState(
                {
                    loading: asnLoading,
                    content: asnContent,
                    empty: asnEmpty,
                    summary: asnSummary,
                },
                'Calculating...',
            );
        }
    }

    function mergeRefreshScope(left, right) {
        if (left === 'all' || right === 'all') return 'all';
        return left ?? right ?? 'all';
    }

    function queueRefreshScope(scope) {
        pendingRefreshScopes.push(scope);
    }

    function dequeueRefreshScope() {
        if (pendingRefreshScopes.length === 0) return 'all';

        let mergedScope = pendingRefreshScopes[0] ?? 'all';
        for (let index = 1; index < pendingRefreshScopes.length; index += 1) {
            mergedScope = mergeRefreshScope(mergedScope, pendingRefreshScopes[index]);
        }
        pendingRefreshScopes = [];
        return mergedScope;
    }

    function unwrapApiData(result) {
        return result?.data ?? result;
    }

    /**
     * Format an ISO timestamp as a short chart x-axis label.
     *
     * @param {string} isoStr - ISO 8601 timestamp string.
     * @param {number|string} hours - Time range duration in hours.
     * @returns {string}
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

    function makeLegendLabelGenerator(unit) {
        return (chart) => {
            const original = Chart.defaults.plugins.legend.labels.generateLabels(chart);
            return original.map((item) => {
                const dataset = chart.data.datasets[item.datasetIndex];
                if (dataset && Array.isArray(dataset.data)) {
                    const sum = dataset.data.reduce((acc, val) => acc + (Number(val) || 0), 0);
                    item.text = `${item.text} (${formatTrafficMetric(sum, unit)})`;
                }
                return item;
            });
        };
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

    function buildCountryRenderKey(items, unit, peerFilter) {
        const hash = items.map((country, index) =>
            `${country.code || country.name || index}:${Number(country.total || 0).toFixed(2)}`
        ).join(';');
        return `${unit}|${peerFilter}|${items.length}|${hash}`;
    }

    function buildAsnRenderKey(items, unit, peerFilter) {
        const hash = items.map((asn, index) =>
            `${asn.asn || asn.name || index}:${Number(asn.total || 0).toFixed(2)}`
        ).join(';');
        return `${unit}|${peerFilter}|${items.length}|${hash}`;
    }

    function normalizePeerSeries(peer) {
        const rx = Array.isArray(peer?.rx) ? peer.rx.map((value) => Number(value || 0)) : [];
        const tx = Array.isArray(peer?.tx) ? peer.tx.map((value) => Number(value || 0)) : [];
        const bucketCount = Math.max(rx.length, tx.length);
        const total = [];

        for (let index = 0; index < bucketCount; index += 1) {
            total.push((rx[index] || 0) + (tx[index] || 0));
        }

        return {
            ...peer,
            rx,
            tx,
            total,
            totalSum: total.reduce((sum, value) => sum + value, 0),
        };
    }

    function limitAllPeerSeries(peers) {
        const normalizedPeers = peers.map(normalizePeerSeries);
        if (normalizedPeers.length <= MAX_ALL_PEER_SERIES) {
            return normalizedPeers;
        }

        const sortedPeers = [...normalizedPeers].sort((left, right) => right.totalSum - left.totalSum);
        const visiblePeers = sortedPeers.slice(0, MAX_ALL_PEER_SERIES - 1);
        const hiddenPeers = sortedPeers.slice(MAX_ALL_PEER_SERIES - 1);
        const bucketCount = hiddenPeers.reduce((max, peer) => Math.max(max, peer.total.length), 0);
        const otherTotal = Array.from({ length: bucketCount }, (_, index) =>
            hiddenPeers.reduce((sum, peer) => sum + (peer.total[index] || 0), 0)
        );

        visiblePeers.push({
            key: '__other__',
            name: `Other (${hiddenPeers.length})`,
            total: otherTotal,
            totalSum: otherTotal.reduce((sum, value) => sum + value, 0),
        });

        return visiblePeers;
    }

    function createCountryFirstCell(country) {
        const flagCell = createCell('td', 'text-center');
        const countryCode = String(country.code ?? '').trim().toLowerCase();

        if (/^[a-z]{2}$/.test(countryCode)) {
            const flag = document.createElement('img');
            flag.className = 'country-flag';
            flag.alt = country.name ? `Flag of ${country.name}` : 'Country flag';
            flag.width = 24;
            flag.height = 18;
            flag.loading = 'lazy';
            flag.decoding = 'async';
            flag.src = `${FLAG_ICON_BASE_URL}/${countryCode}.svg`;
            flag.addEventListener('error', () => {
                flag.remove();
                const icon = document.createElement('span');
                icon.className = 'material-icons traffic-fallback-icon';
                icon.setAttribute('aria-hidden', 'true');
                icon.textContent = 'public';
                flagCell.appendChild(icon);
            }, { once: true });
            flagCell.appendChild(flag);
        } else {
            const icon = document.createElement('span');
            icon.className = 'material-icons traffic-fallback-icon';
            icon.setAttribute('aria-hidden', 'true');
            icon.textContent = 'public';
            flagCell.appendChild(icon);
        }
        return flagCell;
    }

    function createCountryNameCell(country) {
        const nameCell = createCell('td');
        const nameDiv = document.createElement('div');
        nameDiv.className = 'fw-medium';
        nameDiv.title = country.name ?? '';
        nameDiv.textContent = country.name ?? '';
        nameCell.appendChild(nameDiv);
        return nameCell;
    }

    function createAsnFirstCell(asn) {
        const asnCell = createCell('td', 'traffic-col-asn');
        const asnBadge = document.createElement('span');
        asnBadge.className = 'badge bg-secondary bg-opacity-25 text-body asn-badge';
        asnBadge.textContent = asn.asn === '0' ? '–' : `AS${asn.asn}`;
        asnCell.appendChild(asnBadge);
        return asnCell;
    }

    function createAsnNameCell(asn) {
        const nameCell = createCell('td');
        const nameDiv = document.createElement('div');
        nameDiv.className = 'fw-medium';
        nameDiv.title = asn.name ?? '';
        nameDiv.textContent = asn.name ?? '';

        if (asn.asn && asn.asn !== '0') {
            const asnInline = document.createElement('span');
            asnInline.className = 'asn-inline';
            asnInline.textContent = `AS${asn.asn}`;
            nameDiv.appendChild(asnInline);
        }

        nameCell.appendChild(nameDiv);
        return nameCell;
    }

    async function refreshTrafficBreakdown(signal, config) {
        const { endpoint, setCache, getCache, render, elements, logLabel, uiErrorMessage } = config;
        try {
            const range = trafficRange?.value || '24h';
            const peerFilter = getServerPeerFilterOrEmpty();
            let url = `${endpoint}?range_key=${encodeURIComponent(range)}`;
            if (peerFilter) {
                url += `&peer=${encodeURIComponent(peerFilter)}`;
            }
            const result = await api('GET', url, null, { signal, timeoutMs: API_TIMEOUT_MS });
            setCache(unwrapApiData(result));
            render();
            return true;
        } catch (e) {
            if (isAbortError(e)) return true;
            console.error(logLabel, e);
            if (getCache()) {
                render();
            } else {
                showSectionError(elements, uiErrorMessage);
            }
            return false;
        }
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
    * @param {boolean} config.hasPeerData - Whether any item has peer_names data;
    * used to distinguish missing attribution from a true empty peer result.
    * @param {number} config.unfilteredCount - Server item count before client-side display threshold filtering.
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
        const totalTraffic = items.reduce((s, item) => s + Number(item.total || 0), 0);
        const rangeLabel = getRangeLabel(trafficRange?.value || '24h');
        if (summary) {
            const noun = items.length === 1 ? itemNoun : itemNounPlural;
            summary.textContent = `${items.length} ${noun} · ${formatTrafficMetric(totalTraffic, unit)} (${rangeLabel})`;
        }

        if (!tbody) return;
        const maxTotal = Number(items[0]?.total) || 1;

        // Render deduplication - skip if data unchanged
        const newRenderKey = buildRenderKey(items, unit, peerFilter);
        if (newRenderKey === renderKey.current) return;
        renderKey.current = newRenderKey;

        // Build rows using DOM construction (safe from XSS)
        const fragment = document.createDocumentFragment();
        items.forEach((item, i) => {
            const row = document.createElement('tr');
            row.className = 'traffic-row';

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
        return refreshTrafficBreakdown(signal, {
            endpoint: '/api/wireguard/stats/traffic-by-country',
            setCache: (data) => { cachedCountryData = data; },
            getCache: () => cachedCountryData,
            render: renderCountryTraffic,
            elements: {
                loading: countryLoading,
                content: countryContent,
                empty: countryEmpty,
                summary: countrySummary,
            },
            logLabel: 'Country traffic error:',
            uiErrorMessage: 'Failed to load country traffic. Will retry...',
        });
    }

    function renderCountryTraffic() {
        const data = cachedCountryData;
        if (!data) return;

        if (countryContent) countryContent.removeAttribute('aria-busy');

        let countries = Array.isArray(data.countries) ? data.countries : [];
        const unit = data.display_unit ?? 'MB';

        // Check if peer attribution data exists (any country has peer_names)
        const hasPeerData = countries.some(c => Array.isArray(c.peer_names) && c.peer_names.length > 0);

        // Note: Server-side filtering is now applied via the `peer` query param.
        // Client-side filtering is kept as fallback for historical data without by_peer.
        const peerFilter = getServerPeerFilterOrEmpty();
        const unfilteredCount = countries.length;

        // Filter out countries with zero or negligible traffic (that would display as "0")
        const minDisplayThreshold = (unit === 'MB' || unit === 'GB') ? 0.05 : 0.005;
        countries = countries.filter(c => {
            const total = Number(c.total);
            return Number.isFinite(total) && total >= minDisplayThreshold;
        });

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
            createFirstCell: createCountryFirstCell,
            createNameCell: createCountryNameCell,
            buildRenderKey: buildCountryRenderKey,
            renderKey: countryRenderKey,
            itemNoun: 'country',
            itemNounPlural: 'countries',
            hasPeerData,
            unfilteredCount,
        });
    }

    /* ── ASN Traffic ───────────────────────────────── */

    async function refreshASNTraffic(signal) {
        return refreshTrafficBreakdown(signal, {
            endpoint: '/api/wireguard/stats/traffic-by-asn',
            setCache: (data) => { cachedASNData = data; },
            getCache: () => cachedASNData,
            render: renderASNTraffic,
            elements: {
                loading: asnLoading,
                content: asnContent,
                empty: asnEmpty,
                summary: asnSummary,
            },
            logLabel: 'ASN traffic error:',
            uiErrorMessage: 'Failed to load ASN traffic. Will retry...',
        });
    }

    function renderASNTraffic() {
        const data = cachedASNData;
        if (!data) return;

        if (asnContent) asnContent.removeAttribute('aria-busy');

        let asns = Array.isArray(data.asns) ? data.asns : [];
        const unit = data.display_unit ?? 'MB';

        // Check if peer attribution data exists (any ASN has peer_names)
        const hasPeerData = asns.some(a => Array.isArray(a.peer_names) && a.peer_names.length > 0);

        // Note: Server-side filtering is now applied via the `peer` query param.
        // Client-side filtering is kept as fallback for historical data without by_peer.
        const peerFilter = getServerPeerFilterOrEmpty();
        const unfilteredCount = asns.length;

        // Filter out ASNs with zero or negligible traffic (that would display as "0")
        const minDisplayThreshold = (unit === 'MB' || unit === 'GB') ? 0.05 : 0.005;
        asns = asns.filter(a => {
            const total = Number(a.total);
            return Number.isFinite(total) && total >= minDisplayThreshold;
        });

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
            createFirstCell: createAsnFirstCell,
            createNameCell: createAsnNameCell,
            buildRenderKey: buildAsnRenderKey,
            renderKey: asnRenderKey,
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
            value: p.name ?? p.key ?? 'Unknown',
            key: p.key ?? p.name,
            label: p.name ?? p.key ?? 'Unknown',
        }));

        const newKeys = peerOptions.map(p => p.key).sort().join(',');
        if (newKeys === knownTrafficPeerKeys) return;

        knownTrafficPeerKeys = newKeys;

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
            cachedTrafficData = unwrapApiData(traffic);
            cachedTrafficLabels = null;
            renderTrafficCharts();
            return true;
        } catch (e) {
            if (isAbortError(e)) return true;
            console.error('Traffic chart error:', e);
            showSectionError(
                {
                    loading: trafficCombinedLoading,
                    content: trafficCombinedWrap,
                    empty: trafficEmptyState,
                    summary: null,
                },
                'Failed to load traffic data. Will retry...'
            );
            return false;
        }
    }

    function renderTrafficCharts() {
        if (!isAdmin || !trafficCombinedWrap || !trafficEmptyState || !trafficCombinedCanvas) return;
        const traffic = cachedTrafficData;
        if (!traffic) return;

        trafficCombinedWrap.removeAttribute('aria-busy');

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

        const peerFilter = trafficPeerFilter?.value ?? '';
        const hours = Number(traffic?.hours ?? 24);
        if (!cachedTrafficLabels) {
            cachedTrafficLabels = (traffic?.labels ?? []).map(ts => shortLabel(ts, hours));
        }
        const labels = cachedTrafficLabels;
        const unit = traffic?.display_unit ?? 'MB';
        let peers = Array.isArray(traffic?.peers) ? traffic.peers : [];

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
            const visiblePeers = limitAllPeerSeries(peers);
            // All Peers: one cumulative (RX+TX) line per peer
            visiblePeers.forEach((peer, idx) => {
                const peerName = peer.name ?? peer.key ?? `Peer ${idx + 1}`;
                const color = peerColors[idx % peerColors.length];
                datasets.push({
                    label: peerName,
                    data: peer.total,
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
                trafficCombinedChart.options.plugins.legend.labels.generateLabels = makeLegendLabelGenerator(unit);
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
                            generateLabels: makeLegendLabelGenerator(unit),
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

    async function refreshAll(scope = 'all') {
        if (!refreshScheduler) return;
        queueRefreshScope(scope);
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
    * Centralized cleanup for full page teardown only.
     * Idempotent - safe to call multiple times.
     */
    function cleanup() {
        if (cleanupComplete) return;
        cleanupComplete = true;

        clearTimeout(trafficRangeDebounce);
        clearTimeout(resizeDebounce);
        clearTimeout(peerFilterTimeout);
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
        if (pagehideHandler) {
            window.removeEventListener('pagehide', pagehideHandler);
            pagehideHandler = null;
        }
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

                const scope = dequeueRefreshScope();

                const refreshTasks = [];
                if (scope === 'all') {
                    refreshTasks.push(refreshTrafficCharts(signal));
                }
                refreshTasks.push(refreshCountryTraffic(signal), refreshASNTraffic(signal));

                const results = await Promise.allSettled(refreshTasks);
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
                    void refreshAll();
                }
                startAutoRefresh();
            }
        };
        document.addEventListener('visibilitychange', visibilityHandler);

        // Only tear down when the page is actually discarded.
        pagehideHandler = (event) => {
            if (!event.persisted) {
                cleanup();
            }
        };
        window.addEventListener('pagehide', pagehideHandler);

        peerFilterHandler = () => {
            clearTimeout(peerFilterTimeout);
            const needsChartFetch = !cachedTrafficData;

            // Show spinners immediately for instant feedback (always show chart spinner for UX)
            showTrafficLoading({
                chart: isAdmin,
                country: true,
                asn: true,
            });

            peerFilterTimeout = setTimeout(() => {
                if (!needsChartFetch) {
                    renderTrafficCharts();
                }

                void refreshAll(needsChartFetch ? 'all' : 'breakdowns')
                    .catch((e) => dbg('Refresh failed during filter change:', e));
            }, 50);
        };
        trafficPeerFilter?.addEventListener('change', peerFilterHandler);

        rangeChangeHandler = () => {
            clearTimeout(trafficRangeDebounce);
            showTrafficLoading({ chart: isAdmin, country: true, asn: true });
            trafficRangeDebounce = setTimeout(() => {
                void refreshAll('all');
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
            });
    }

    // Run initialization when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTraffic);
    } else {
        initTraffic();
    }
})();
