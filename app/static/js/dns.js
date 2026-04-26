//
// app/static/js/dns.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// NOTE: Client-side only – backend must enforce authorization on all mutations
const dnsApp = document.getElementById('dns-app');
const WBShared = window.WBShared;
if (!WBShared) {
    throw new Error('WBShared must be loaded before dns.js');
}
const clearNode = WBShared.clearElement;
const chartEmptyState = WBShared.chartEmptyState;

// Helper: parse dataset boolean (SQLite stores booleans as integers, so handle both "true" and "1")
function _readDatasetBool(el, key, defaultValue = false) {
    if (!el) return defaultValue;
    const val = el.dataset[key];
    return val === 'true' || val === '1';
}

// User permission check
const isAdmin = _readDatasetBool(dnsApp, 'isAdmin');
// Track ad-blocker enabled state (for Top Blocked / Blockrate disabled message)
let _adBlockerEnabled = _readDatasetBool(dnsApp, 'enableBlocklist', true);
// Initial DNS availability state from server-rendered dataset
let _dnsUnavailable = _readDatasetBool(dnsApp, 'dnsUnavailable');

// Named constants
const LOG_BATCH_SIZE = 50;  // Items to render per batch
const LOG_FETCH_LIMIT = 1000;  // Max items to fetch from API
const SCROLL_THRESHOLD_PX = 150;  // Trigger infinite scroll when this close to bottom
const SEARCH_DEBOUNCE_MS = 250;  // Debounce delay for search input
const MENU_VIEWPORT_MARGIN_PX = 8;  // Minimum margin for context menu

let _logData = [];
let _logDataVersion = 0;  // Incremented whenever _logData content changes
let _peerMap = {};
let _trendChart = null;
let _renderedCount = 0;  // How many items currently rendered
let _filteredData = [];  // Filtered data for infinite scroll
let _lastFilterKey = '';  // Cache key for filter state
let _logsLoadInProgress = false;  // Guard against concurrent loadLogsOnly calls
let _logsLoadPending = false;  // Queue one trailing loadLogsOnly call
let _logsLoadPendingShowLoading = false;  // Preserve strongest UI intent for queued load
let _searchTimer = null;  // Debounce timer for search
let _scrollRaf = null;  // RAF handle for scroll throttle
let _logAutoFillQueued = false;  // Prevent stacked auto-fill checks
let _logActionState = null; // Active row action context
let _isInitialTopDomainsRender = true; // Skip fade on first render
let _restoreAbort = null; // AbortController for async log scroll restoration
let _peerMapVersion = 0; // Invalidate cached log filter when peer map changes
let _pageAbort = new AbortController();  // Abort controller for page cleanup
let _peerFilterFadeSeq = 0;

const _stateEls = {
    queriedLoading: document.getElementById('top-queried-loading'),
    queriedContent: document.getElementById('top-queried-content'),
    queriedEmpty: document.getElementById('top-queried-empty'),
    queriedUnavailable: document.getElementById('top-queried-unavailable'),
    blockedLoading: document.getElementById('top-blocked-loading'),
    blockedContent: document.getElementById('top-blocked-content'),
    blockedEmpty: document.getElementById('top-blocked-empty'),
    blockedDisabled: document.getElementById('top-blocked-disabled'),
    blockedUnavailable: document.getElementById('top-blocked-unavailable'),
    trendLoading: document.getElementById('trend-loading'),
    trendChart: document.getElementById('trend-chart-wrap'),
    trendEmpty: document.getElementById('trend-empty'),
    trendDisabled: document.getElementById('trend-disabled'),
    trendUnavailable: document.getElementById('trend-unavailable'),
    trendMeta: document.getElementById('trend-meta'),
    logUnavailable: document.getElementById('log-unavailable'),
};
_stateEls.logCardBody = _stateEls.logUnavailable?.parentElement || null;

function _resetPageAbortController() {
    if (_pageAbort && !_pageAbort.signal.aborted) {
        _pageAbort.abort();
    }
    _pageAbort = new AbortController();
}

function _showChartEmpty(container) {
    if (!container) return;
    clearNode(container);
    container.appendChild(chartEmptyState());
    container.classList.remove('d-none');
}

function _setTrendMeta(text) {
    if (_stateEls.trendMeta) {
        _stateEls.trendMeta.textContent = text;
    }
}

function _fadeTopDomainCards(cards) {
    for (const card of cards) {
        card.classList.add('top-domain-card-fading');
    }
}

function _unfadeTopDomainCards(cards) {
    for (const card of cards) {
        card.classList.remove('top-domain-card-fading');
    }
}

function _getTopDomainCards() {
    return [
        document.getElementById('top-queried-content')?.parentElement,
        document.getElementById('top-blocked-content')?.parentElement,
    ].filter(Boolean);
}

function _wait(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function _onDocumentKeydown(ev) {
    if (ev.key === 'Escape') closeLogActionMenu();
}

function _onDocumentClick(ev) {
    const menu = document.getElementById('log-action-menu');
    if (!menu) return;
    if (!menu.contains(ev.target)) {
        closeLogActionMenu();
    }
}

function _attachDocumentListeners() {
    document.addEventListener('keydown', _onDocumentKeydown);
    document.addEventListener('click', _onDocumentClick);
}

function _detachDocumentListeners() {
    document.removeEventListener('keydown', _onDocumentKeydown);
    document.removeEventListener('click', _onDocumentClick);
}

function _onVisibilityChange() {
    if (document.hidden) {
        stopPolling();
        closeLogActionMenu();
        return;
    }

    _lastSlowPoll = 0;
    if (_pageAbort.signal.aborted) {
        _resetPageAbortController();
    }
    void _refreshScheduler.refresh().then(() => startPolling());
}

function _onPageHide() {
    stopPolling();
    _detachDocumentListeners();
    if (themeObserver) {
        themeObserver.disconnect();
    }
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
    if (_scrollRaf) {
        cancelAnimationFrame(_scrollRaf);
        _scrollRaf = null;
    }
    if (_restoreAbort) {
        _restoreAbort.abort();
        _restoreAbort = null;
    }
    _logsLoadPending = false;
    _logsLoadPendingShowLoading = false;
    _isInitialTopDomainsRender = true;
    _resetPageAbortController();
}

function _onPageShow(ev) {
    if (!ev?.persisted) {
        return;
    }
    if (_pageAbort.signal.aborted) {
        _resetPageAbortController();
    }
    if (themeObserver) {
        themeObserver.observe(document.documentElement, {
            attributes: true,
            attributeFilter: ['data-bs-theme'],
        });
    }
    _attachDocumentListeners();
    void _refreshScheduler.refresh().then(() => startPolling());
}

function _setHidden(el, hidden) {
    if (!el) return;
    el.classList.toggle('d-none', hidden);
}

function _showPanelState(prefix, activeSuffix) {
    const panelSuffixes = {
        queried: ['Loading', 'Content', 'Empty', 'Unavailable'],
        blocked: ['Loading', 'Content', 'Empty', 'Disabled', 'Unavailable'],
        trend: ['Loading', 'Chart', 'Empty', 'Disabled', 'Unavailable'],
    };

    for (const suffix of panelSuffixes[prefix] || []) {
        _setHidden(_stateEls[`${prefix}${suffix}`], suffix !== activeSuffix);
    }
}

/**
 * Small visibility state machine for DNS UI sections.
 * Priority: dnsUnavailable > adBlockerDisabled > active content/loading.
 */
function applyDnsVisibilityState() {
    const { logUnavailable, logCardBody } = _stateEls;

    if (_dnsUnavailable) {
        _showPanelState('queried', 'Unavailable');
        _showPanelState('blocked', 'Unavailable');
        _showPanelState('trend', 'Unavailable');

        if (logCardBody) logCardBody.classList.add('dns-log-unavailable');
        _setHidden(logUnavailable, false);
        return;
    }

    _showPanelState('queried', null);
    _showPanelState('blocked', null);
    _showPanelState('trend', null);
    if (logCardBody) logCardBody.classList.remove('dns-log-unavailable');
    _setHidden(logUnavailable, true);

    if (_adBlockerEnabled) {
        _setHidden(_stateEls.blockedDisabled, true);
        _setHidden(_stateEls.trendDisabled, true);
    } else {
        _showPanelState('blocked', 'Disabled');
        _showPanelState('trend', 'Disabled');
    }
}

const isAbortError = WBShared.isAbortError;

/**
 * Extract raw client IP from a formatted 'PeerName (IP)' string.
 * Returns the IP inside parentheses, or the original value if no parens found.
 * The backend formats q.client as "PeerName (10.13.13.3)" or just "10.13.13.3".
 */
function _extractClientIp(clientStr) {
    if (!clientStr) return '';
    const match = clientStr.match(/\(([^)]+)\)$/);
    return match ? match[1] : clientStr;
}

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
    return ips.join(',');
}

function _buildClientIpsParam() {
    const clientIps = getSelectedPeerClientIps();
    return clientIps ? `&client_ips=${encodeURIComponent(clientIps)}` : '';
}

function _activateLogRow(ev) {
    const target = ev.target instanceof Element ? ev.target : null;
    const row = target?.closest('tr.log-row-actionable');
    if (!row) return;
    const idx = parseInt(row.dataset.logIndex, 10);
    const q = _filteredData[idx];
    if (!q) return;
    ev.preventDefault();
    openLogActionMenu(q, ev);
}

function peerMapsEqual(a, b) {
    const aKeys = Object.keys(a);
    const bKeys = Object.keys(b);
    if (aKeys.length !== bKeys.length) return false;
    for (const key of aKeys) {
        if (a[key] !== b[key]) return false;
    }
    return true;
}

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
        client: _extractClientIp(q.client || ''),
        clientName: _peerMap[_extractClientIp(q.client || '').toLowerCase()] || '',
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

    if (scope === 'global') {
        const verb = action === 'block' ? 'Block' : 'Unblock';
        const confirmed = window.confirm(`${verb} "${state.domain}" for all clients?`);
        if (!confirmed) return;
    }

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

function getThemeColors() {
    const isDark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
    return {
        gridColor: isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)',
        textColor: isDark ? '#9ca3af' : '#6b7280',
    };
}

function applyTrendTheme() {
    if (!_trendChart) return;
    const { gridColor, textColor } = getThemeColors();
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

function setTextById(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
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
    const loadingEl = _stateEls.trendLoading;
    const trendWrap = _stateEls.trendChart;
    const emptyEl = _stateEls.trendEmpty;

    if (_dnsUnavailable) {
        applyDnsVisibilityState();
        return;
    }

    // Show disabled message when ad-blocker is disabled
    if (!_adBlockerEnabled) {
        applyDnsVisibilityState();
        if (_trendChart) {
            _trendChart.destroy();
            _trendChart = null;
        }
        return;
    }

    try {
        // 30 days = 720 hours, bucket size adapts to viewport
        const bucketMinutes = Math.min(1440, Math.max(5, getTrendBucketMinutes()));
        const clientIpsParam = _buildClientIpsParam();
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
            _showChartEmpty(emptyEl);
            return;
        }

        // Hide loading, show chart
        loadingEl.classList.add('d-none');
        trendWrap.classList.remove('d-none');
        emptyEl.classList.add('d-none');
        applyDnsVisibilityState();

        // Ensure canvas exists (may have been replaced by empty state)
        if (!trendWrap.querySelector('#dnsTrendChart')) {
            clearNode(trendWrap);
            const canvas = document.createElement('canvas');
            canvas.id = 'dnsTrendChart';
            trendWrap.appendChild(canvas);
            _trendChart = null;
        }

        const { gridColor, textColor } = getThemeColors();
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
            _trendChart.data.datasets.forEach(ds => {
                ds.pointRadius = pointRadius;
                ds.pointHoverRadius = pointHoverRadius;
            });
            _trendChart.update();
        }

        _setTrendMeta('');
    } catch (e) {
        if (isAbortError(e)) return;
        console.error('Trend load failed:', e);
        _setTrendMeta('Trend unavailable');
    }
}

async function loadStats() {
    try {
        const s = await api('GET', '/api/dns/status', null, { signal: _pageAbort.signal });

        const wasUnavailable = _dnsUnavailable;
        _dnsUnavailable = !!s.unavailable;

        // Update status using DOM APIs (safe from XSS)
        const statusEl = document.getElementById('stat-status');
        if (statusEl) {
            statusEl.textContent = s.is_running ? 'Active' : 'Off';
            statusEl.className = `dns-stat-value ${s.is_running ? 'text-success' : 'text-danger'}`;
        }

        setTextById('stat-queries', fmtNum(s.total_queries));
        setTextById('stat-blocked', fmtNum(s.blocked_queries));
        setTextById('stat-percent', s.block_percentage + '%');
        setTextById('stat-domains', fmtNum(s.unique_domains));
        setTextById('stat-blocklist', Number.isFinite(s.blocklist_size) ? s.blocklist_size.toLocaleString() : '0');

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

        applyDnsVisibilityState();

        if (wasUnavailable && !_dnsUnavailable) {
            void Promise.allSettled([loadTopDomains(), loadTrend(), loadLogsOnly()]);
        }
    } catch (e) {
        if (isAbortError(e)) return;
        // Update status for error state using DOM APIs
        const statusEl = document.getElementById('stat-status');
        if (statusEl) {
            statusEl.textContent = '?';
            statusEl.className = 'dns-stat-value text-muted';
        }
        setTextById('stat-queries', '–');
        setTextById('stat-blocked', '–');
        setTextById('stat-percent', '–');
        setTextById('stat-domains', '–');
        setTextById('stat-blocklist', '–');
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
    if (_dnsUnavailable) {
        applyDnsVisibilityState();
        return;
    }

    try {
        const clientIpsParam = _buildClientIpsParam();
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
            applyDnsVisibilityState();
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
        if (!isAbortError(e)) {
            console.error('Top domains error:', e);
        }
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

function getPaletteColors(labels, palette) {
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
    const chartColors = getPaletteColors(labels, colors);
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

/**
 * Create a full-width table row for empty/loading/error states.
 * @param {Node|string} content - Element or text to display
 * @param {string} [className=''] - Additional CSS class for the td
 * @returns {HTMLTableRowElement}
 */
function _createLogStatusRow(content, className = '') {
    const tr = document.createElement('tr');
    tr.className = 'log-empty-row';
    const td = document.createElement('td');
    td.colSpan = 3;
    if (className) td.className = className;
    if (typeof content === 'string') {
        td.textContent = content;
    } else {
        td.appendChild(content);
    }
    tr.appendChild(td);
    return tr;
}

function showLogsLoadingState() {
    const tbody = document.getElementById('log-body');
    if (!tbody) return;

    clearNode(tbody);
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
    tbody.appendChild(_createLogStatusRow(wrap, 'py-5'));
}

async function loadLogsOnly(showLoading = true) {
    if (_logsLoadInProgress) {
        _logsLoadPending = true;
        _logsLoadPendingShowLoading = _logsLoadPendingShowLoading || showLoading;
        return;
    }
    _logsLoadInProgress = true;

    if (_restoreAbort) {
        _restoreAbort.abort();
        _restoreAbort = null;
    }

    try {
        if (showLoading) {
            showLogsLoadingState();
        }
        const clientIpsParam = _buildClientIpsParam();
        const data = await api('GET', `/api/dns/logs?lines=${LOG_FETCH_LIMIT}${clientIpsParam}`, null, { signal: _pageAbort.signal });
        // NOTE: Backend already masks client/client_name to "*****" for non-admins
        // (see dns.py dns_logs: `if is_admin else masked`). The spread below is kept
        // as a defence-in-depth guard against accidental backend regressions.
        // PERF: Preprocess client IP to avoid repeated regex/toLowerCase in render
        const newData = (data.queries || []).map(q => {
            const base = isAdmin ? q : { ...q, client: undefined };
            base._clientIp = _extractClientIp(q.client || '').toLowerCase();
            return base;
        });

        // Lightweight change detection using first/last + sample from middle
        const sig = (arr) => {
            if (!arr.length) return '';
            const mid = Math.floor(arr.length / 2);
            // Lightweight change detection: may miss same-timestamp row updates.
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
        _logDataVersion += 1;
        _renderedCount = 0;
        renderLogs();

        // Re-render additional batches to restore scroll depth (yield to avoid UI blocking)
        if (!showLoading && prevRendered > LOG_BATCH_SIZE) {
            _restoreAbort = new AbortController();
            const signal = _restoreAbort.signal;
            const restoreScrollAsync = async () => {
                while (!signal.aborted && _renderedCount < Math.min(prevRendered, _filteredData.length)) {
                    renderLogs(true);
                    // Yield to allow UI updates
                    await new Promise(r => requestAnimationFrame(r));
                }
                // Restore scroll position (clamped to prevent overshoot if dataset shrunk)
                if (!signal.aborted && logContainer) {
                    logContainer.scrollTop = Math.min(scrollTop, logContainer.scrollHeight - logContainer.clientHeight);
                }
                if (_restoreAbort?.signal === signal) {
                    _restoreAbort = null;
                }
            };
            void restoreScrollAsync();
        }
    } catch (e) {
        if (isAbortError(e)) return;
        console.error('Failed to load logs:', e);
        if (showLoading) {
            const tbody = document.getElementById('log-body');
            if (!tbody) return;
            clearNode(tbody);
            tbody.appendChild(_createLogStatusRow('Failed to load logs', 'text-center text-danger'));
        }
    } finally {
        _logsLoadInProgress = false;
        if (_logsLoadPending && !_pageAbort.signal.aborted) {
            const nextShowLoading = _logsLoadPendingShowLoading;
            _logsLoadPending = false;
            _logsLoadPendingShowLoading = false;
            void loadLogsOnly(nextShowLoading);
        }
    }
}

async function loadPeers() {
    if (!isAdmin) {
        if (Object.keys(_peerMap).length > 0) {
            _peerMap = {};
            _peerMapVersion += 1;
            _lastFilterKey = '';
            renderLogs();
        } else {
            _peerMap = {};
        }
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
        const mapChanged = !peerMapsEqual(_peerMap, newMap);
        _peerMap = newMap;
        if (mapChanged) {
            _peerMapVersion += 1;
            _lastFilterKey = '';
            renderLogs();
        }

        const exists = Array.from(peerFilter.options).some(opt => opt.value === previousValue);
        peerFilter.value = exists ? previousValue : 'all';
    } catch (e) {
        if (!isAbortError(e)) {
            console.error('Failed to load peers:', e);
        }
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
        // PERF: Only recompute filter if inputs changed
        const filterKey = `${filter}|${peerFilter}|${search}|${_peerMapVersion}|${_logDataVersion}`;
        if (filterKey !== _lastFilterKey) {
            _filteredData = _logData.filter(q => {
                if (filter === 'blocked' && !q.blocked) return false;
                if (filter === 'allowed' && q.blocked) return false;
                // PERF: Use preprocessed _clientIp instead of runtime extraction
                if (peerFilter !== 'all' && (q.client_name || peerMapSnapshot[q._clientIp] || '') !== peerFilter) return false;
                if (search && !(q.domain || '').toLowerCase().includes(search)) return false;
                return true;
            });
            _lastFilterKey = filterKey;
        }
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
            tbody.appendChild(_createLogStatusRow(chartEmptyState(), 'log-empty-cell'));
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
        // PERF: Use preprocessed _clientIp instead of runtime extraction
        const peerName = peerMapSnapshot[q._clientIp];
        const clientInfo = document.createElement('span');
        clientInfo.className = 'text-muted log-domain-client';
        if (!isAdmin) {
            // NOTE: Backend already sends masked values; this is defence-in-depth
            clientInfo.textContent = `***** (*****)`;
        } else {
            clientInfo.textContent = peerName ? `${peerName} (${_extractClientIp(q.client)})` : (q.client || '');
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

    queueLogAutoFill();
}

function debouncedRenderLogs() {
    clearTimeout(_searchTimer);
    _searchTimer = setTimeout(renderLogs, SEARCH_DEBOUNCE_MS);
}

function loadMoreLogs() {
    if (_renderedCount >= _filteredData.length) return;  // All rendered
    renderLogs(true);  // Append mode
}

function queueLogAutoFill() {
    const logContainer = document.getElementById('log-table-wrap');
    if (!logContainer || _logAutoFillQueued || _renderedCount >= _filteredData.length) return;
    if (logContainer.scrollHeight > logContainer.clientHeight + 1) return;

    _logAutoFillQueued = true;
    requestAnimationFrame(() => {
        _logAutoFillQueued = false;
        if (!logContainer.isConnected) return;

        if (
            logContainer.scrollHeight <= logContainer.clientHeight + 1 &&
            _renderedCount < _filteredData.length
        ) {
            loadMoreLogs();
        }
    });
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
        applyDnsVisibilityState();
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
        if (isAbortError(e)) return;
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
    } catch (e) {
        wbToast('Failed to update Ad-Blocker: ' + e.message, 'danger');
    } finally {
        if (btn && isAdmin) btn.disabled = false;
        // Always close dropdown (even on error, to avoid stale open state)
        const dropdown = bootstrap.Dropdown.getInstance(btn);
        if (dropdown) dropdown.hide();
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
    autoRefreshMs: 30000,  // PERF: Reduced from 15s to 30s - less CPU/network usage
    maxBackoffMs: 300000,
    refreshFn: async () => {
        // Promise.allSettled never rejects - check results instead
        const results = await Promise.allSettled([loadStats(), loadLogsOnly(false)]);
        // Require at least one critical call to succeed (not just "any")
        const statsOk = results[0].status === 'fulfilled';
        const logsOk = results[1].status === 'fulfilled';
        const fastOk = statsOk || logsOk;

        if (Date.now() - _lastSlowPoll > SLOW_POLL_INTERVAL) {
            const now = Date.now();
            _lastSlowPoll = now;
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

const themeObserver = new MutationObserver(() => {
    applyTrendTheme();
});
themeObserver.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['data-bs-theme'],
});

_attachDocumentListeners();
document.addEventListener('visibilitychange', _onVisibilityChange);
window.addEventListener('pagehide', _onPageHide);
window.addEventListener('pageshow', _onPageShow);

// Infinite scroll for Query Log (throttled with RAF)
const logContainer = document.getElementById('log-table-wrap');
if (logContainer) {
    logContainer.addEventListener('scroll', function () {
        if (_scrollRaf) return;
        _scrollRaf = requestAnimationFrame(() => {
            const scrollBottom = logContainer.scrollHeight - logContainer.scrollTop - logContainer.clientHeight;
            if (scrollBottom < SCROLL_THRESHOLD_PX || logContainer.scrollHeight <= logContainer.clientHeight + 1) {
                loadMoreLogs();
            }
            _scrollRaf = null;
        });
    });
}

// Event delegation for log row actions with keyboard support
const logBody = document.getElementById('log-body');
if (logBody) {
    logBody.addEventListener('click', _activateLogRow);
    logBody.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter' || ev.key === ' ') {
            _activateLogRow(ev);
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
        const seq = ++_peerFilterFadeSeq;
        const cards = _getTopDomainCards();
        const shouldFade = !_isInitialTopDomainsRender && cards.length > 0;

        if (shouldFade) {
            _fadeTopDomainCards(cards);
            await _wait(150);
        }

        if (seq !== _peerFilterFadeSeq) return;

        await Promise.allSettled([loadLogsOnly(), loadTrend(), loadTopDomains()]);

        if (seq !== _peerFilterFadeSeq) return;
        if (shouldFade) {
            _unfadeTopDomainCards(cards);
        }
    });
}

const logSearchInput = document.getElementById('log-search');
if (logSearchInput) {
    // Only filter existing data on search (debounced)
    logSearchInput.addEventListener('input', debouncedRenderLogs);
}

applyDnsVisibilityState();


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
