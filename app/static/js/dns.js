//
// app/static/js/dns.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// NOTE: Client-side only – backend must enforce authorization on all mutations
// User permission check (handle both "true" and "1" - SQLite stores booleans as integers)
const dnsApp = document.getElementById('dns-app');
const isAdmin = dnsApp ? (dnsApp.dataset.isAdmin === 'true' || dnsApp.dataset.isAdmin === '1') : false;
const clearNode = window.WBShared?.clearElement || (el => el?.replaceChildren());
const chartEmptyState = window.WBShared?.chartEmptyState || (() => document.createElement('div'));

// Track ad-blocker enabled state (for Top Blocked / Blockrate disabled message)
let _adBlockerEnabled = dnsApp ? (dnsApp.dataset.enableBlocklist === 'true' || dnsApp.dataset.enableBlocklist === '1') : true;

// Named constants
const LOG_BATCH_SIZE = 50;  // Items to render per batch
const LOG_FETCH_LIMIT = 1000;  // Max items to fetch from API
const SCROLL_THRESHOLD_PX = 100;  // Trigger infinite scroll when this close to bottom
const SEARCH_DEBOUNCE_MS = 250;  // Debounce delay for search input
const MENU_VIEWPORT_MARGIN_PX = 8;  // Minimum margin for context menu
const FADE_FALLBACK_MS = 300;  // Fallback timeout for CSS transitions

let _logData = [];
let _peerMap = {};
let _trendChart = null;
let _renderedCount = 0;  // How many items currently rendered
let _filteredData = [];  // Filtered data for infinite scroll
let _logsLoadInProgress = false;  // Guard against concurrent loadLogsOnly calls
let _searchTimer = null;  // Debounce timer for search
let _scrollRaf = null;  // RAF handle for scroll throttle
let _logActionState = null; // Active row action context
let _isInitialTopDomainsRender = true; // Skip fade on first render
let _topDomainFadeTimeout = null; // Timeout handle for fade animation fallback
let _fadeAbort = null; // AbortController for peer filter fade animation
let _pageAbort = new AbortController();  // Abort controller for page cleanup

/**
 * Get comma-separated client IPs for the currently selected peer filter.
 * Returns empty string if "All Peers" is selected.
 */
function getSelectedPeerClientIps() {
    const peerFilterEl = document.getElementById('peer-filter');
    if (!peerFilterEl) return '';
    const selectedPeer = peerFilterEl.value;
    if (!selectedPeer || selectedPeer === 'all') return '';

    // Reverse lookup: find all IPs that map to the selected peer name
    const ips = [];
    for (const [ip, name] of Object.entries(_peerMap)) {
        if (name === selectedPeer) {
            ips.push(ip);
        }
    }
    return ips.map(encodeURIComponent).join(',');
}

document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') closeLogActionMenu();
});

function closeLogActionMenu() {
    const menu = document.getElementById('log-action-menu');
    if (!menu) return;
    menu.classList.remove('show');
    _logActionState = null;
    // Reset ARIA expanded state - scoped to log table only
    document.querySelectorAll('#log-body [aria-expanded="true"]')
        .forEach(el => el.setAttribute('aria-expanded', 'false'));
}

function openLogActionMenu(q, clickEvent) {
    if (!isAdmin) return;
    // Close any previously open menu to prevent state conflicts
    closeLogActionMenu();
    const menu = document.getElementById('log-action-menu');
    if (!menu) return;

    const blocked = !!q.blocked;
    const actions = blocked
        ? [
            { label: 'Unblock for this Client', action: 'unblock', scope: 'client' },
            { label: 'Unblock', action: 'unblock', scope: 'global' },
        ]
        : [
            { label: 'Block for this Client', action: 'block', scope: 'client' },
            { label: 'Block', action: 'block', scope: 'global' },
        ];

    clearNode(menu);

    // Set ARIA attributes for accessibility
    menu.setAttribute('role', 'menu');
    menu.setAttribute('aria-label', `Actions for ${q.domain}`);

    for (const item of actions) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'dropdown-item';
        btn.setAttribute('role', 'menuitem');
        btn.textContent = item.label;
        btn.addEventListener('click', (ev) => {
            ev.preventDefault();
            ev.stopPropagation();
            void applyLogRuleAction(item.action, item.scope);
        });
        menu.appendChild(btn);
    }

    _logActionState = {
        domain: q.domain || '',
        client: q.client || '',
        clientName: _peerMap[(q.client || '').toLowerCase()] || '',
        blocked,
    };

    // Position the menu - handle both mouse and keyboard events
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    let x, y;

    if (clickEvent.type === 'click' || clickEvent.type === 'pointerdown') {
        // Mouse event: position near click
        x = clickEvent.clientX;
        y = clickEvent.clientY;
    } else {
        // Keyboard event: position near the focused row
        const row = clickEvent.target.closest('tr');
        if (row) {
            const rect = row.getBoundingClientRect();
            x = rect.left + rect.width / 2;
            y = rect.bottom;
        } else {
            // Fallback to center of viewport
            x = viewportWidth / 2;
            y = viewportHeight / 2;
        }
    }

    // Make menu visible but invisible to measure dimensions without flash
    menu.style.visibility = 'hidden';
    menu.classList.add('show');
    const menuRect = menu.getBoundingClientRect();

    // Position with viewport boundary checking using actual menu dimensions
    menu.style.left = `${Math.max(MENU_VIEWPORT_MARGIN_PX, Math.min(x, viewportWidth - menuRect.width - MENU_VIEWPORT_MARGIN_PX))}px`;
    menu.style.top = `${Math.max(MENU_VIEWPORT_MARGIN_PX, Math.min(y, viewportHeight - menuRect.height - MENU_VIEWPORT_MARGIN_PX))}px`;
    menu.style.visibility = '';  // Now make visible

    // Accessibility: make menu focusable and focus it
    menu.setAttribute('tabindex', '-1');
    menu.focus();

    // Set ARIA expanded on the triggering row
    const target = clickEvent.target instanceof Element ? clickEvent.target : null;
    const row = target?.closest('tr');
    if (row) row.setAttribute('aria-expanded', 'true');
}

async function applyLogRuleAction(action, scope) {
    const state = _logActionState;
    closeLogActionMenu();
    if (!state || !state.domain) return;

    const payload = {
        action,
        scope,
        domain: state.domain,
    };
    if (scope === 'client') {
        payload.client = state.client;
        if (state.clientName) payload.client_name = state.clientName;
    }

    wbToast('Applying rule…', 'success');

    try {
        const res = await api('POST', '/api/dns/custom-rules/actions', payload);
        if (res?.duplicate) {
            wbToast('Rule already exists', 'info');
        } else {
            wbToast(res?.message || 'Rule applied', 'success');
        }
        await loadLogsOnly();
    } catch (e) {
        wbToast('Failed to apply DNS rule: ' + e.message, 'danger');
    }
}

function getChartThemeColors() {
    const isDark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
    return {
        gridColor: isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)',
        textColor: isDark ? '#9ca3af' : '#6b7280',
    };
}

function applyTrendTheme() {
    if (!_trendChart) return;
    const { gridColor, textColor } = getChartThemeColors();
    _trendChart.options.scales.y.grid.color = gridColor;
    _trendChart.options.scales.y.ticks.color = textColor;
    _trendChart.options.scales.y.title.color = textColor;
    _trendChart.options.scales.y1.grid.color = gridColor;
    _trendChart.options.scales.y1.ticks.color = textColor;
    _trendChart.options.scales.y1.title.color = textColor;
    _trendChart.options.plugins.legend.labels.color = textColor;
    _trendChart.update();
}

function _fmtTrendLabel(isoStr) {
    const d = new Date(isoStr);
    // Format as day/month for 30-day view
    return d.toLocaleDateString([], { day: '2-digit', month: 'short' });
}

function fmtNum(n) {
    if (!Number.isFinite(n) || n <= 0) return '0';
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M';
    if (n >= 10_000) return (n / 1_000).toFixed(0) + 'k';
    if (n >= 1_000) return (n / 1_000).toFixed(1).replace(/\.0$/, '') + 'k';
    return Math.floor(n).toString();
}

/**
 * Calculate optimal bucket size for DNS trend chart based on viewport width.
 * Returns bucket_minutes capped to backend API limit (<= 1440).
 */
function getTrendBucketMinutes() {
    const width = window.innerWidth;
    // Mobile (<576px): 12h buckets = ~60 points over 30 days.
    if (width < 576) return 720;
    // Tablet (<992px): 18h buckets = ~40 points.
    if (width < 992) return 1080;
    // Desktop: 24h buckets = ~30 points.
    return 1440;
}

async function loadTrend() {
    const loadingEl = document.getElementById('trend-loading');
    const trendWrap = document.getElementById('trend-chart-wrap');
    const emptyEl = document.getElementById('trend-empty');

    // Show disabled message when ad-blocker is disabled
    if (!_adBlockerEnabled) {
        loadingEl.classList.add('d-none');
        trendWrap.classList.add('d-none');
        emptyEl.classList.remove('d-none');
        if (_trendChart) {
            _trendChart.destroy();
            _trendChart = null;
        }
        clearNode(emptyEl);
        emptyEl.appendChild(chartEmptyState('DNS Ad-Blocker Disabled. Enable DNS Ad-Blocker in Settings to use this feature.'));
        return;
    }

    try {
        // 30 days = 720 hours, bucket size adapts to viewport
        const bucketMinutes = Math.min(1440, Math.max(5, getTrendBucketMinutes()));
        const clientIps = getSelectedPeerClientIps();
        const clientIpsParam = clientIps ? `&client_ips=${clientIps}` : '';
        let t;
        try {
            t = await api('GET', `/api/dns/trend?hours=720&bucket_minutes=${bucketMinutes}${clientIpsParam}`, null, { signal: _pageAbort.signal });
        } catch (err) {
            // Fallback for strict query validation mismatches on older deployments.
            if (err?.code === 'HTTP_422' && bucketMinutes !== 1440) {
                t = await api('GET', `/api/dns/trend?hours=720&bucket_minutes=1440${clientIpsParam}`, null, { signal: _pageAbort.signal });
            } else {
                throw err;
            }
        }
        const labels = (t.labels || []).map(_fmtTrendLabel);
        const blocked = t.blocked || [];
        const total = t.total || [];
        const rate = t.block_rate || [];

        const hasData = labels.length > 0 && total.some(v => v > 0);
        if (!hasData) {
            loadingEl.classList.add('d-none');
            trendWrap.classList.add('d-none');
            emptyEl.classList.remove('d-none');
            if (_trendChart) {
                _trendChart.destroy();
                _trendChart = null;
            }
            clearNode(emptyEl);
            emptyEl.appendChild(chartEmptyState());
            return;
        }

        // Hide loading, show chart
        loadingEl.classList.add('d-none');
        trendWrap.classList.remove('d-none');
        emptyEl.classList.add('d-none');

        // Ensure canvas exists (may have been replaced by empty state)
        if (!trendWrap.querySelector('#dnsTrendChart')) {
            clearNode(trendWrap);
            const canvas = document.createElement('canvas');
            canvas.id = 'dnsTrendChart';
            trendWrap.appendChild(canvas);
            _trendChart = null;
        }

        const { gridColor, textColor } = getChartThemeColors();
        // Smaller points on mobile for better readability
        const isMobile = window.innerWidth < 576;
        const pointRadius = isMobile ? 2 : 3;
        const pointHoverRadius = isMobile ? 4 : 5;

        const ctx = document.getElementById('dnsTrendChart').getContext('2d');
        if (!_trendChart) {
            _trendChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels,
                    datasets: [
                        {
                            label: 'Blocked',
                            data: blocked,
                            borderColor: '#dc3545',
                            backgroundColor: 'rgba(220, 53, 69, 0.12)',
                            yAxisID: 'y',
                            tension: 0.3,
                            fill: true,
                            pointRadius,
                            pointHoverRadius,
                        },
                        {
                            label: 'Total',
                            data: total,
                            borderColor: '#0d6efd',
                            backgroundColor: 'transparent',
                            yAxisID: 'y',
                            tension: 0.3,
                            pointRadius,
                            pointHoverRadius,
                        },
                        {
                            label: 'Block Rate %',
                            data: rate,
                            borderColor: '#f59e0b',
                            backgroundColor: 'transparent',
                            yAxisID: 'y1',
                            tension: 0.3,
                            borderDash: [4, 3],
                            pointRadius,
                            pointHoverRadius,
                        },
                    ],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: { mode: 'index', intersect: false },
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: textColor,
                                usePointStyle: true,
                                pointStyle: 'rect',
                                boxWidth: 10,
                                padding: 12,
                                font: { size: 11 },
                            },
                        },
                    },
                    scales: {
                        x: {
                            ticks: {
                                color: textColor,
                                maxRotation: 45,
                                autoSkip: true,
                                maxTicksLimit: 15,
                            },
                            grid: { display: false },
                        },
                        y: {
                            beginAtZero: true,
                            grid: { color: gridColor },
                            ticks: {
                                color: textColor,
                                callback: v => v >= 1e6 ? (v / 1e6).toFixed(1).replace(/\.0$/, '') + 'M' : v >= 1e3 ? (v / 1e3).toFixed(1).replace(/\.0$/, '') + 'K' : v
                            },
                            title: { display: true, text: 'Queries', color: textColor },
                        },
                        y1: {
                            position: 'right',
                            beginAtZero: true,
                            min: 0,
                            max: 100,
                            grid: { drawOnChartArea: false },
                            ticks: { color: textColor, callback: v => v + '%' },
                            title: { display: true, text: 'Block Rate %', color: textColor },
                        },
                    },
                },
            });
        } else {
            _trendChart.data.labels = labels;
            _trendChart.data.datasets[0].data = blocked;
            _trendChart.data.datasets[1].data = total;
            _trendChart.data.datasets[2].data = rate;
            _trendChart.data.datasets[0].pointRadius = pointRadius;
            _trendChart.data.datasets[1].pointRadius = pointRadius;
            _trendChart.data.datasets[2].pointRadius = pointRadius;
            _trendChart.data.datasets[0].pointHoverRadius = pointHoverRadius;
            _trendChart.data.datasets[1].pointHoverRadius = pointHoverRadius;
            _trendChart.data.datasets[2].pointHoverRadius = pointHoverRadius;
            _trendChart.update();
        }

        document.getElementById('trend-meta').textContent = '';
    } catch (e) {
        if (e.name !== 'AbortError') {
            console.error('Trend load failed:', e);
        }
        document.getElementById('trend-meta').textContent = 'Trend unavailable';
    }
}

async function loadStats() {
    try {
        const s = await api('GET', '/api/dns/status', null, { signal: _pageAbort.signal });

        // Update status using DOM APIs (safe from XSS)
        const statusEl = document.getElementById('stat-status');
        if (statusEl) {
            statusEl.textContent = s.is_running ? 'Active' : 'Off';
            statusEl.className = `dns-stat-value ${s.is_running ? 'text-success' : 'text-danger'}`;
        }

        document.getElementById('stat-queries').textContent = fmtNum(s.total_queries);
        document.getElementById('stat-blocked').textContent = fmtNum(s.blocked_queries);
        document.getElementById('stat-percent').textContent = s.block_percentage + '%';
        document.getElementById('stat-domains').textContent = fmtNum(s.unique_domains);
        document.getElementById('stat-blocklist').textContent =
            Number.isFinite(s.blocklist_size) ? s.blocklist_size.toLocaleString() : '0';

        // Update adblocker button state
        const btn = document.getElementById('adblocker-btn');
        const btnText = document.getElementById('adblocker-btn-text');
        if (btn && isAdmin) {
            // Disable button if Unbound is not installed
            if (s.unavailable) {
                btn.disabled = true;
                btn.title = s.reason || 'DNS unavailable';
                btn.classList.remove('btn-adblocker-enabled');
                btn.classList.add('btn-adblocker-disabled');
                if (btnText) btnText.textContent = 'Ad-Blocker: Unavailable';
            } else {
                btn.disabled = false;
                btn.title = '';
            }
        }
    } catch (e) {
        // Update status for error state using DOM APIs
        const statusEl = document.getElementById('stat-status');
        if (statusEl) {
            statusEl.textContent = '?';
            statusEl.className = 'dns-stat-value text-muted';
        }
        document.getElementById('stat-queries').textContent = '–';
        document.getElementById('stat-blocked').textContent = '–';
        document.getElementById('stat-percent').textContent = '–';
        document.getElementById('stat-domains').textContent = '–';
        document.getElementById('stat-blocklist').textContent = '–';
    }
}

/**
 * Render disabled state for a Top Domain card (when ad-blocker is off).
 */
function renderTopDomainDisabled({ loadingId, contentId, emptyId, disabledId, unavailableId }) {
    const loadingEl = document.getElementById(loadingId);
    const contentEl = document.getElementById(contentId);
    const emptyEl = document.getElementById(emptyId);
    const disabledEl = document.getElementById(disabledId);
    const unavailableEl = document.getElementById(unavailableId);
    if (loadingEl) loadingEl.classList.add('d-none');
    if (contentEl) contentEl.classList.add('d-none');
    if (emptyEl) emptyEl.classList.add('d-none');
    if (unavailableEl) unavailableEl.classList.add('d-none');
    if (disabledEl) disabledEl.classList.remove('d-none');
}

async function loadTopDomains() {
    try {
        const clientIps = getSelectedPeerClientIps();
        const clientIpsParam = clientIps ? `&client_ips=${clientIps}` : '';
        const data = await api('GET', `/api/dns/top-domains?limit=15${clientIpsParam}`, null, { signal: _pageAbort.signal });
        const topQueried = data.top_queried || [];
        const topBlocked = data.top_blocked || [];

        // Top Queried always renders regardless of ad-blocker state
        renderTopDomainBars({
            items: topQueried,
            loadingId: 'top-queried-loading',
            contentId: 'top-queried-content',
            listId: 'top-queried-list',
            emptyId: 'top-queried-empty',
            unavailableId: 'top-queried-unavailable',
            colors: queriedColors,
            defaultColor: '#0d6efd'
        });

        // Top Blocked: show disabled message when ad-blocker is off
        if (!_adBlockerEnabled) {
            renderTopDomainDisabled({
                loadingId: 'top-blocked-loading',
                contentId: 'top-blocked-content',
                emptyId: 'top-blocked-empty',
                disabledId: 'top-blocked-disabled',
                unavailableId: 'top-blocked-unavailable'
            });
        } else {
            renderTopDomainBars({
                items: topBlocked,
                loadingId: 'top-blocked-loading',
                contentId: 'top-blocked-content',
                listId: 'top-blocked-list',
                emptyId: 'top-blocked-empty',
                disabledId: 'top-blocked-disabled',
                unavailableId: 'top-blocked-unavailable',
                colors: blockedColors,
                defaultColor: '#dc3545'
            });
        }
    } catch (e) {
        console.error('Top domains error:', e);
    }
}

// Shared color palettes
const queriedColors = [
    '#0d6efd', '#6f42c1', '#0dcaf0', '#198754', '#20c997',
    '#ffc107', '#fd7e14', '#dc3545', '#d63384'
];
const blockedColors = [
    '#dc3545', '#fd7e14', '#ffc107', '#198754', '#0dcaf0',
    '#0d6efd', '#6f42c1', '#d63384', '#20c997'
];

function getChartColors(labels, palette) {
    return labels.map((label, i) => palette[i % palette.length]);
}

function prepareBarChartData(items, maxSlices = 12) {
    if (!items.length) return { labels: [], values: [], total: 0 };

    const total = items.reduce((sum, d) => sum + Number(d.count || 0), 0);
    const sorted = [...items].sort((a, b) => (b.count || 0) - (a.count || 0));

    let labels = [];
    let values = [];
    let otherCount = 0;

    for (let i = 0; i < sorted.length; i++) {
        const d = sorted[i];
        const count = Number(d.count || 0);

        if (i < maxSlices) {
            labels.push(d.domain || 'Unknown');
            values.push(count);
        } else {
            otherCount += count;
        }
    }

    if (otherCount > 0) {
        labels.push('Other');
        values.push(otherCount);
    }

    return { labels, values, total };
}

// Shared function to render bar charts for top domains
function renderTopDomainBars({ items, loadingId, contentId, listId, emptyId, disabledId, unavailableId, colors, maxSlices = 12, defaultColor = '#0d6efd' }) {
    const loadingEl = document.getElementById(loadingId);
    const contentEl = document.getElementById(contentId);
    const listEl = document.getElementById(listId);
    const emptyEl = document.getElementById(emptyId);
    const disabledEl = document.getElementById(disabledId);
    const unavailableEl = document.getElementById(unavailableId);

    if (loadingEl) loadingEl.classList.add('d-none');
    if (disabledEl) disabledEl.classList.add('d-none');
    if (unavailableEl) unavailableEl.classList.add('d-none');

    if (!items.length) {
        if (contentEl) contentEl.classList.add('d-none');
        if (emptyEl) emptyEl.classList.remove('d-none');
        return;
    }

    if (contentEl) contentEl.classList.remove('d-none');
    if (emptyEl) emptyEl.classList.add('d-none');

    const { labels, values, total } = prepareBarChartData(items, maxSlices);
    const chartColors = getChartColors(labels, colors);
    const maxVal = Math.max(...values, 1);

    clearNode(listEl);
    labels.forEach((label, i) => {
        const val = values[i];
        const pct = (val / maxVal) * 100;
        const totalPct = total > 0 ? (val / total * 100).toFixed(1) : 0;
        const color = chartColors[i] || defaultColor;

        const itemWrap = document.createElement('div');
        itemWrap.className = 'd-flex flex-column gap-1';

        const topRow = document.createElement('div');
        topRow.className = 'd-flex justify-content-between align-items-end gap-2 top-domain-top-row';

        const nameEl = document.createElement('span');
        nameEl.className = 'log-domain text-truncate top-domain-name';
        nameEl.textContent = label;
        nameEl.title = label;

        const statsWrap = document.createElement('div');
        statsWrap.className = 'd-flex align-items-baseline gap-2 top-domain-stats-wrap';

        const valEl = document.createElement('span');
        valEl.className = 'top-domain-stats';
        valEl.textContent = fmtNum(val);

        const pctEl = document.createElement('span');
        pctEl.className = 'badge bg-secondary top-domain-percent';
        pctEl.textContent = totalPct + '%';

        statsWrap.appendChild(valEl);
        statsWrap.appendChild(pctEl);
        topRow.appendChild(nameEl);
        topRow.appendChild(statsWrap);

        const barWrap = document.createElement('div');
        barWrap.className = 'w-100 bg-secondary bg-opacity-25 top-domain-bar-track';

        const barInner = document.createElement('div');
        barInner.className = 'top-domain-bar';
        barInner.style.width = pct + '%';
        barInner.style.backgroundColor = color;

        barWrap.appendChild(barInner);
        itemWrap.appendChild(topRow);
        itemWrap.appendChild(barWrap);
        listEl.appendChild(itemWrap);
    });
}

function showLogsLoadingState() {
    const tbody = document.getElementById('log-body');
    if (!tbody) return;

    clearNode(tbody);
    const tr = document.createElement('tr');
    tr.className = 'log-empty-row';
    const td = document.createElement('td');
    td.colSpan = 3;
    td.className = 'py-5';

    const wrap = document.createElement('div');
    wrap.className = 'd-flex justify-content-center align-items-center';

    const spinner = document.createElement('div');
    spinner.className = 'spinner-border text-primary';
    spinner.setAttribute('role', 'status');

    const hidden = document.createElement('span');
    hidden.className = 'visually-hidden';
    hidden.textContent = 'Loading...';

    spinner.appendChild(hidden);
    wrap.appendChild(spinner);
    td.appendChild(wrap);
    tr.appendChild(td);
    tbody.appendChild(tr);
}

async function loadLogsOnly(showLoading = true) {
    if (_logsLoadInProgress) return;
    _logsLoadInProgress = true;
    try {
        if (showLoading) {
            showLogsLoadingState();
        }
        const data = await api('GET', `/api/dns/logs?lines=${LOG_FETCH_LIMIT}`, null, { signal: _pageAbort.signal });
        // IMPORTANT: Backend should omit client field for non-admins in the API response.
        // This client-side stripping is cosmetic only - data already sent over the wire.
        // Fix: GET /api/dns/logs should check user.is_admin before including client IPs.
        const newData = (data.queries || []).map(q =>
            isAdmin ? q : { ...q, client: undefined }
        );

        // Lightweight change detection using first/last + sample from middle
        const sig = (arr) => {
            if (!arr.length) return '';
            const mid = Math.floor(arr.length / 2);
            return `${arr.length}:${arr[0]?.timestamp}:${arr[mid]?.timestamp}:${arr.at(-1)?.timestamp}`;
        };
        const dataChanged = sig(newData) !== sig(_logData);
        if (!showLoading && !dataChanged) {
            // Data unchanged during poll - skip render
            return;
        }

        // Close action menu to prevent stale references
        closeLogActionMenu();

        // Preserve scroll state if data changed during background poll
        const logContainer = document.getElementById('log-table-wrap');
        const scrollTop = logContainer?.scrollTop ?? 0;
        const prevRendered = _renderedCount;

        _logData = newData;
        _renderedCount = 0;
        renderLogs();

        // Re-render additional batches to restore scroll depth (yield to avoid UI blocking)
        if (!showLoading && prevRendered > LOG_BATCH_SIZE) {
            const restoreScrollAsync = async () => {
                while (_renderedCount < Math.min(prevRendered, _filteredData.length)) {
                    renderLogs(true);
                    // Yield to allow UI updates
                    await new Promise(r => requestAnimationFrame(r));
                }
                // Restore scroll position (clamped to prevent overshoot if dataset shrunk)
                if (logContainer) {
                    logContainer.scrollTop = Math.min(scrollTop, logContainer.scrollHeight - logContainer.clientHeight);
                }
            };
            void restoreScrollAsync();
        }
    } catch (e) {
        console.error('Failed to load logs:', e);
        if (showLoading) {
            const tbody = document.getElementById('log-body');
            if (!tbody) return;
            clearNode(tbody);
            const tr = document.createElement('tr');
            tr.className = 'log-empty-row';
            const td = document.createElement('td');
            td.colSpan = 3;
            td.className = 'text-center text-danger';
            td.textContent = 'Failed to load logs';
            tr.appendChild(td);
            tbody.appendChild(tr);
        }
    } finally {
        _logsLoadInProgress = false;
    }
}

async function loadPeers() {
    if (!isAdmin) {
        _peerMap = {};
        const peerFilter = document.getElementById('peer-filter');
        if (peerFilter) {
            clearNode(peerFilter);
            const allOpt = document.createElement('option');
            allOpt.value = 'all';
            allOpt.textContent = 'All Peers';
            peerFilter.appendChild(allOpt);
            peerFilter.value = 'all';
            peerFilter.disabled = true;
        }
        return;
    }
    try {
        const data = await api('GET', '/api/wireguard/stats/peers-enriched', null, { signal: _pageAbort.signal });
        const peers = data.peers || [];
        const peerFilter = document.getElementById('peer-filter');
        if (!peerFilter) return; // Guard against null

        const previousValue = peerFilter.value || 'all';
        const newMap = {}; // Build atomically to avoid partial state on error

        const seenNames = new Set();
        clearNode(peerFilter);

        const allOpt = document.createElement('option');
        allOpt.value = 'all';
        allOpt.textContent = 'All Peers';
        peerFilter.appendChild(allOpt);

        for (const peer of peers) {
            // Skip node tunnel peers (inter-node connections)
            if (peer.is_node_tunnel) continue;

            const name = peer.name || peer.public_key?.substring(0, 8) || 'Unknown';
            const addrParts = (peer.peer_address || '').split(',');
            for (const part of addrParts) {
                const ip = part.trim().split('/')[0].toLowerCase();
                if (ip) newMap[ip] = name;
            }

            if (peer.name && !seenNames.has(name)) {
                seenNames.add(name);
                const opt = document.createElement('option');
                opt.value = name;
                opt.textContent = name;
                peerFilter.appendChild(opt);
            }
        }

        // Atomic swap to avoid partial state
        _peerMap = newMap;

        const exists = Array.from(peerFilter.options).some(opt => opt.value === previousValue);
        peerFilter.value = exists ? previousValue : 'all';
    } catch (e) {
        console.error('Failed to load peers:', e);
    }
}

function renderLogs(append = false) {
    const filterEl = document.getElementById('log-filter');
    const peerFilterEl = document.getElementById('peer-filter');
    const searchEl = document.getElementById('log-search');
    const tbody = document.getElementById('log-body');

    if (!filterEl || !peerFilterEl || !searchEl || !tbody) return;

    const filter = filterEl.value;
    const peerFilter = peerFilterEl.value;
    const search = searchEl.value.toLowerCase();
    // Snapshot peerMap to avoid race conditions with async loads
    const peerMapSnapshot = _peerMap;

    // If not appending, reset and filter fresh
    if (!append) {
        _renderedCount = 0;
        // Always create a copy to avoid reference issues
        _filteredData = _logData.filter(q => {
            if (filter === 'blocked' && !q.blocked) return false;
            if (filter === 'allowed' && q.blocked) return false;
            if (peerFilter !== 'all' && (q.client_name || peerMapSnapshot[(q.client || '').toLowerCase()] || '') !== peerFilter) return false;
            if (search && !(q.domain || '').toLowerCase().includes(search)) return false;
            return true;
        });
        clearNode(tbody);

        // Update screen reader announcement with result count
        const srAnnounce = document.getElementById('log-sr-announce');
        if (srAnnounce) {
            const count = _filteredData.length;
            const text = count === 1 ? '1 result' : `${count} results`;
            srAnnounce.textContent = search || filter !== 'all' || peerFilter !== 'all' ? text : '';
        }

        // Show empty message only on initial render
        if (!_filteredData.length) {
            const tr = document.createElement('tr');
            tr.className = 'log-empty-row';
            const td = document.createElement('td');
            td.colSpan = 3;
            td.className = 'log-empty-cell';
            td.appendChild(chartEmptyState());
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }
    }

    // Guard for append mode
    if (_renderedCount >= _filteredData.length) return;

    const startIdx = _renderedCount;
    const endIdx = Math.min(_renderedCount + LOG_BATCH_SIZE, _filteredData.length);
    const batch = _filteredData.slice(startIdx, endIdx);

    const frag = document.createDocumentFragment();
    for (let i = 0; i < batch.length; i++) {
        const q = batch[i];
        const tr = document.createElement('tr');
        if (q.blocked) tr.className = 'table-danger bg-opacity-10';
        if (isAdmin) {
            tr.classList.add('log-row-actionable');
            tr.title = 'Click for rule actions';
            tr.setAttribute('tabindex', '0');
            tr.setAttribute('role', 'button');
            tr.setAttribute('aria-haspopup', 'menu');
            tr.setAttribute('aria-expanded', 'false');
        }
        tr.dataset.logIndex = startIdx + i;

        const tdTime = document.createElement('td');
        tdTime.setAttribute('data-label', 'Time');
        tdTime.className = 'text-muted log-col-time';
        const timestamp = String(q.timestamp || '');
        const timeParts = timestamp.includes('T')
            ? timestamp.split('T')
            : timestamp.split(' ');
        if (timeParts.length >= 2) {
            const timeStack = document.createElement('div');
            timeStack.className = 'log-time-stack';
            const dateSpan = document.createElement('span');
            dateSpan.className = 'log-time-date';
            dateSpan.textContent = timeParts[0];
            const clockSpan = document.createElement('span');
            clockSpan.className = 'log-time-clock';
            clockSpan.textContent = timeParts[1];
            timeStack.appendChild(dateSpan);
            timeStack.appendChild(clockSpan);
            tdTime.appendChild(timeStack);
        } else {
            tdTime.textContent = timestamp;
        }

        // Domain with client/peer info below in gray
        const tdDomain = document.createElement('td');
        tdDomain.setAttribute('data-label', 'Domain');
        const domainWrap = document.createElement('div');
        domainWrap.className = 'log-domain-stack';
        const domainText = document.createElement('span');
        domainText.className = 'log-domain';
        domainText.textContent = q.domain || '';
        domainWrap.appendChild(domainText);

        // Add client/peer info below domain
        const peerName = peerMapSnapshot[(q.client || '').toLowerCase()];
        const clientInfo = document.createElement('span');
        clientInfo.className = 'text-muted log-domain-client';
        if (!isAdmin) {
            // NOTE: Cosmetic masking only – backend should omit sensitive fields for non-admins
            clientInfo.textContent = `***** (*****)`;
        } else {
            clientInfo.textContent = peerName ? `${peerName} (${q.client})` : (q.client || '');
        }
        domainWrap.appendChild(clientInfo);
        tdDomain.appendChild(domainWrap);

        const tdType = document.createElement('td');
        tdType.setAttribute('data-label', 'Type');
        tdType.className = 'log-col-type';
        const typeCode = document.createElement('code');
        typeCode.textContent = q.type || '';
        tdType.appendChild(typeCode);

        tr.appendChild(tdTime);
        tr.appendChild(tdDomain);
        tr.appendChild(tdType);
        frag.appendChild(tr);
    }

    tbody.appendChild(frag);
    _renderedCount = endIdx;
}

function debouncedRenderLogs() {
    clearTimeout(_searchTimer);
    _searchTimer = setTimeout(renderLogs, SEARCH_DEBOUNCE_MS);
}

function loadMoreLogs() {
    if (_renderedCount >= _filteredData.length) return;  // All rendered
    renderLogs(true);  // Append mode
}

// Ad-Blocker dropdown state
let _adblockerCountdownInterval = null;
let _adblockerDisabledUntil = 0;

function updateAdblockerButton(enabled, disabledUntil = 0) {
    const btn = document.getElementById('adblocker-btn');
    const btnText = document.getElementById('adblocker-btn-text');
    const countdown = document.getElementById('adblocker-countdown');
    if (!btn || !btnText || !countdown) return;

    // Update ad-blocker state and re-render affected cards if changed
    const wasEnabled = _adBlockerEnabled;
    _adBlockerEnabled = enabled;

    // If state changed, re-render Top Blocked Domains and Blockrate Trend
    if (wasEnabled !== enabled) {
        void loadTopDomains();
        void loadTrend();
    }

    _adblockerDisabledUntil = disabledUntil;

    // Update button color
    btn.classList.remove('btn-adblocker-enabled', 'btn-adblocker-disabled');
    btn.classList.add(enabled ? 'btn-adblocker-enabled' : 'btn-adblocker-disabled');

    // Update button text
    btnText.textContent = enabled ? 'Ad-Blocker: Enabled' : 'Ad-Blocker: Disabled';

    // Handle countdown
    if (_adblockerCountdownInterval) {
        clearInterval(_adblockerCountdownInterval);
        _adblockerCountdownInterval = null;
    }

    const now = Math.floor(Date.now() / 1000);
    if (!enabled && disabledUntil > now) {
        countdown.classList.remove('d-none');
        updateCountdownDisplay();
        _adblockerCountdownInterval = setInterval(updateCountdownDisplay, 1000);
    } else {
        countdown.classList.add('d-none');
        countdown.textContent = '';
    }
}

function updateCountdownDisplay() {
    const countdown = document.getElementById('adblocker-countdown');
    if (!countdown) return;

    const now = Math.floor(Date.now() / 1000);
    const remaining = _adblockerDisabledUntil - now;

    if (remaining <= 0) {
        countdown.classList.add('d-none');
        countdown.textContent = '';
        if (_adblockerCountdownInterval) {
            clearInterval(_adblockerCountdownInterval);
            _adblockerCountdownInterval = null;
        }
        // Timer expired - reload status from server
        loadAdblockerStatus();
        return;
    }

    const hours = Math.floor(remaining / 3600);
    const minutes = Math.floor((remaining % 3600) / 60);
    const seconds = remaining % 60;

    if (hours > 0) {
        countdown.textContent = `(${hours}h ${minutes}m ${seconds}s)`;
    } else if (minutes > 0) {
        countdown.textContent = `(${minutes}m ${seconds}s)`;
    } else {
        countdown.textContent = `(${seconds}s)`;
    }
}

async function loadAdblockerStatus() {
    try {
        const data = await api('GET', '/api/dns/adblocker/status', null, { signal: _pageAbort.signal });
        updateAdblockerButton(data.enabled, data.disabled_until || 0);
    } catch (e) {
        console.error('Failed to load adblocker status:', e);
    }
}

async function setAdblockerMode(mode) {
    if (!isAdmin) {
        wbToast('Only admins can change Ad-Blocker settings', 'danger');
        return;
    }

    const btn = document.getElementById('adblocker-btn');
    if (btn) btn.disabled = true;

    try {
        const data = await api('POST', '/api/dns/adblocker/mode', { mode: mode });
        updateAdblockerButton(data.enabled, data.disabled_until || 0);
        wbToast(data.enabled ? 'Ad-Blocker enabled' : 'Ad-Blocker disabled', 'success');
        await loadStats();

        // Close dropdown after selection
        const dropdown = bootstrap.Dropdown.getInstance(btn);
        if (dropdown) dropdown.hide();
    } catch (e) {
        wbToast('Failed to update Ad-Blocker: ' + e.message, 'danger');
    } finally {
        if (btn && isAdmin) btn.disabled = false;
    }
}

// Adblocker dropdown event listeners
document.querySelectorAll('[data-adblocker-mode]').forEach(item => {
    item.addEventListener('click', function (e) {
        e.preventDefault();
        if (!isAdmin) return;
        const mode = this.getAttribute('data-adblocker-mode');
        setAdblockerMode(mode);
    });
});

let _lastSlowPoll = 0;
const SLOW_POLL_INTERVAL = 60000;

const _refreshScheduler = new window.WBShared.RefreshScheduler({
    autoRefreshMs: 15000,
    maxBackoffMs: 300000,
    refreshFn: async () => {
        // Promise.allSettled never rejects - check results instead
        const results = await Promise.allSettled([loadStats(), loadLogsOnly(false)]);
        // Require at least one critical call to succeed (not just "any")
        const statsOk = results[0].status === 'fulfilled';
        const logsOk = results[1].status === 'fulfilled';
        const fastOk = statsOk || logsOk;

        if (Date.now() - _lastSlowPoll > SLOW_POLL_INTERVAL) {
            _lastSlowPoll = Date.now();
            const slowResults = await Promise.allSettled([loadTopDomains(), loadTrend(), loadPeers()]);
            const slowOk = slowResults.some(r => r.status === 'fulfilled');
            return fastOk || slowOk;
        }
        return fastOk;
    }
});

function startPolling() {
    _refreshScheduler.start();
}

function stopPolling() {
    _refreshScheduler.stop();
}

document.addEventListener('visibilitychange', async () => {
    if (document.hidden) {
        stopPolling();
        closeLogActionMenu();
    } else {
        // Reset slow poll tracking on tab switch
        _lastSlowPoll = 0;
        await _refreshScheduler.refresh();
        startPolling();
    }
});

document.addEventListener('click', (ev) => {
    const menu = document.getElementById('log-action-menu');
    if (!menu) return;
    if (!menu.contains(ev.target)) {
        closeLogActionMenu();
    }
});

const themeObserver = new MutationObserver(() => {
    applyTrendTheme();
});
themeObserver.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['data-bs-theme'],
});
window.addEventListener('pagehide', () => {
    themeObserver.disconnect();
    if (_trendChart) {
        _trendChart.destroy();
        _trendChart = null;
    }
    if (_adblockerCountdownInterval) {
        clearInterval(_adblockerCountdownInterval);
        _adblockerCountdownInterval = null;
    }
    if (_searchTimer) {
        clearTimeout(_searchTimer);
        _searchTimer = null;
    }
    if (_fadeAbort) {
        _fadeAbort.abort();
        _fadeAbort = null;
    }
    // Abort all in-flight API requests
    _pageAbort.abort();
}, { once: true });

// Infinite scroll for Query Log (throttled with RAF)
const logContainer = document.getElementById('log-table-wrap');
if (logContainer) {
    logContainer.addEventListener('scroll', function () {
        if (_scrollRaf) return;
        _scrollRaf = requestAnimationFrame(() => {
            const scrollBottom = logContainer.scrollHeight - logContainer.scrollTop - logContainer.clientHeight;
            if (scrollBottom < SCROLL_THRESHOLD_PX) {
                loadMoreLogs();
            }
            _scrollRaf = null;
        });
    });
}

// Event delegation for log row actions with keyboard support
const logBody = document.getElementById('log-body');
if (logBody) {
    logBody.addEventListener('click', (ev) => {
        const target = ev.target instanceof Element ? ev.target : null;
        const row = target?.closest('tr.log-row-actionable');
        if (!row) return;
        const idx = parseInt(row.dataset.logIndex, 10);
        const q = _filteredData[idx];
        if (q) {
            ev.preventDefault();
            // NOTE: stopPropagation removed - closeLogActionMenu now called in openLogActionMenu
            openLogActionMenu(q, ev);
        }
    });

    logBody.addEventListener('keydown', (ev) => {
        if (ev.key !== 'Enter' && ev.key !== ' ') return;
        const target = ev.target instanceof Element ? ev.target : null;
        const row = target?.closest('tr.log-row-actionable');
        if (!row) return;
        const idx = parseInt(row.dataset.logIndex, 10);
        const q = _filteredData[idx];
        if (q) {
            ev.preventDefault();
            openLogActionMenu(q, ev);
        }
    });
}

// Attach event listeners to filter controls (moved from inline handlers for CSP compliance)
const logFilterSelect = document.getElementById('log-filter');
if (logFilterSelect) {
    // Load fresh data when filter changes
    logFilterSelect.addEventListener('change', () => renderLogs());
}

const peerFilterSelect = document.getElementById('peer-filter');
if (peerFilterSelect) {
    // Load fresh data when peer filter changes - affects logs, trend, and top domains
    peerFilterSelect.addEventListener('change', async () => {
        // Logs are filtered client-side, re-render immediately
        renderLogs();

        // Cancel any stale animation from previous filter change
        if (_fadeAbort) _fadeAbort.abort();
        _fadeAbort = new AbortController();
        const signal = _fadeAbort.signal;

        if (_topDomainFadeTimeout) {
            clearTimeout(_topDomainFadeTimeout);
            _topDomainFadeTimeout = null;
        }

        // Fade out top domains cards before re-rendering
        const topQueriedCard = document.getElementById('top-queried-content')?.parentElement;
        const topBlockedCard = document.getElementById('top-blocked-content')?.parentElement;

        if (!topQueriedCard || !topBlockedCard) {
            // No cards to fade, render immediately
            await Promise.allSettled([loadTrend(), loadTopDomains()]);
            return;
        }

        // Skip fade effect on initial render - only fade when user actively changes filter
        if (_isInitialTopDomainsRender) {
            await Promise.allSettled([loadTrend(), loadTopDomains()]);
            return;
        }

        // Remove classes first to ensure fresh transition starts
        topQueriedCard.classList.remove('top-domain-card-fading');
        topBlockedCard.classList.remove('top-domain-card-fading');
        // Force reflow to restart CSS transition
        void topQueriedCard.offsetHeight;

        // Fade out cards, re-render on transition complete
        let transitionHandled = false;
        const handleTransitionEnd = () => {
            if (transitionHandled || signal.aborted) return;
            transitionHandled = true;
            if (_topDomainFadeTimeout) {
                clearTimeout(_topDomainFadeTimeout);
                _topDomainFadeTimeout = null;
            }
            Promise.allSettled([loadTrend(), loadTopDomains()]).then(() => {
                if (signal.aborted) return;
                requestAnimationFrame(() => {
                    topQueriedCard.classList.remove('top-domain-card-fading');
                    topBlockedCard.classList.remove('top-domain-card-fading');
                });
            });
        };

        topQueriedCard.addEventListener('transitionend', handleTransitionEnd,
            { once: true, signal });
        topQueriedCard.classList.add('top-domain-card-fading');
        topBlockedCard.classList.add('top-domain-card-fading');

        // Fallback timeout in case transitionend doesn't fire
        _topDomainFadeTimeout = setTimeout(() => {
            if (!signal.aborted) handleTransitionEnd();
        }, FADE_FALLBACK_MS);
    });
}

const logSearchInput = document.getElementById('log-search');
if (logSearchInput) {
    // Only filter existing data on search (debounced)
    logSearchInput.addEventListener('input', debouncedRenderLogs);
}

// Pull-to-refresh for mobile
const pullRefreshIndicator = document.getElementById('log-pull-refresh');
const logTableWrap = document.getElementById('log-table-wrap');

if (pullRefreshIndicator && logTableWrap && 'ontouchstart' in window) {
    let touchStartY = 0;
    let touchCurrentY = 0;
    let isPulling = false;
    let isRefreshing = false;
    const PULL_THRESHOLD = 60;

    logTableWrap.addEventListener('touchstart', (e) => {
        // Only allow pull-to-refresh when scrolled to top
        if (logTableWrap.scrollTop === 0 && !isRefreshing) {
            touchStartY = e.touches[0].clientY;
            isPulling = true;
        }
    }, { passive: true });

    logTableWrap.addEventListener('touchmove', (e) => {
        if (!isPulling || isRefreshing) return;

        touchCurrentY = e.touches[0].clientY;
        const pullDistance = touchCurrentY - touchStartY;

        // Only show indicator when pulling down
        if (pullDistance > 0 && logTableWrap.scrollTop === 0) {
            pullRefreshIndicator.style.height = `${Math.min(pullDistance * 0.5, 50)}px`;
            pullRefreshIndicator.classList.add('pulling');

            if (pullDistance >= PULL_THRESHOLD) {
                pullRefreshIndicator.classList.add('ready');
                const pullText = pullRefreshIndicator.querySelector('.pull-text');
                if (pullText) pullText.textContent = 'Release to refresh';
            } else {
                pullRefreshIndicator.classList.remove('ready');
                const pullText = pullRefreshIndicator.querySelector('.pull-text');
                if (pullText) pullText.textContent = 'Pull to refresh';
            }
        }
    }, { passive: true });

    logTableWrap.addEventListener('touchend', async () => {
        if (!isPulling || isRefreshing) return;

        const pullDistance = touchCurrentY - touchStartY;

        if (pullDistance >= PULL_THRESHOLD && logTableWrap.scrollTop === 0) {
            // Trigger refresh
            isRefreshing = true;
            pullRefreshIndicator.classList.remove('ready');
            pullRefreshIndicator.classList.add('refreshing');
            const pt1 = pullRefreshIndicator.querySelector('.pull-text');
            if (pt1) pt1.textContent = 'Refreshing...';
            const arr1 = pullRefreshIndicator.querySelector('.pull-arrow');
            if (arr1) arr1.textContent = 'autorenew';

            try {
                await loadLogsOnly(false);
            } finally {
                // Reset indicator
                isRefreshing = false;
                pullRefreshIndicator.classList.remove('pulling', 'refreshing');
                pullRefreshIndicator.style.height = '0';

                const pt2 = pullRefreshIndicator.querySelector('.pull-text');
                if (pt2) pt2.textContent = 'Pull to refresh';
                const arr2 = pullRefreshIndicator.querySelector('.pull-arrow');
                if (arr2) arr2.textContent = 'arrow_downward';
            }
        } else {
            // Reset without refresh
            pullRefreshIndicator.classList.remove('pulling', 'ready');
            pullRefreshIndicator.style.height = '0';
        }

        isPulling = false;
        touchStartY = 0;
        touchCurrentY = 0;
    }, { passive: true });
}

// Initial load
(async () => {
    // Load peers first to avoid race with log filtering
    await loadPeers();

    const results = await Promise.allSettled([
        loadStats(), loadTopDomains(),
        loadTrend(), loadLogsOnly(), loadAdblockerStatus()
    ]);
    const failures = results.filter(r => r.status === 'rejected');
    if (results.length > 0 && failures.length === results.length) {
        console.error('DNS page: all API calls failed');
    }
    // Mark initial render complete after first data load
    _isInitialTopDomainsRender = false;
    startPolling();
})();
