//
// app/static/js/dns-page.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

(function () {
    'use strict';

    const dnsApp = document.getElementById('dns-app');
    const logRowTemplate = document.getElementById('log-row-template');
    if (!dnsApp || !logRowTemplate) {
        console.error('[dns] Required DOM roots are missing.');
        return;
    }

    const requiredGlobals = [
        ['api', window.api],
        ['wbToast', window.wbToast],
        ['Chart', window.Chart],
        ['bootstrap', window.bootstrap],
    ];
    for (const [name, value] of requiredGlobals) {
        if (!value) {
            console.error(`[dns] Required global "${name}" is not defined.`);
            return;
        }
    }

    // User permission check
    const isAdmin = dnsApp.dataset.isAdmin === 'true';
    const STAT_IDS = ['stat-queries', 'stat-blocked', 'stat-percent', 'stat-domains', 'stat-blocklist'];

    function chartEmptyState(text = 'No Data Available') {
        const wrapper = document.createElement('div');
        wrapper.className = 'chart-empty-state';
        wrapper.setAttribute('role', 'status');
        wrapper.setAttribute('aria-live', 'polite');
        const icon = document.createElement('span');
        icon.className = 'material-icons';
        icon.textContent = 'show_chart';
        icon.setAttribute('aria-hidden', 'true');
        const msg = document.createElement('span');
        msg.className = 'chart-empty-state-text';
        msg.textContent = text;
        wrapper.append(icon, msg);
        return wrapper;
    }

    let _logData = [];
    let _peerMap = {};
    let _trendChart = null;
    const LOG_BATCH_SIZE = 50;  // Items to render per batch
    const LOG_FETCH_LIMIT = 1000;  // Max items to fetch from API
    let _renderedCount = 0;  // How many items currently rendered
    let _filteredData = [];  // Filtered data for infinite scroll
    let _isLoadingMore = false;  // Prevent concurrent loads
    let _pollInterval = null;
    let _pollCount = 0;
    let _pollInProgress = false;
    let _logsLoadInProgress = false;  // Guard against concurrent loadLogsOnly calls
    let _searchTimer = null;  // Debounce timer for search
    let _scrollRaf = null;  // RAF handle for scroll throttle
    let _logAutoFillQueued = false;  // Prevent stacked auto-fill checks
    let _logActionState = null; // Active row action context

    /**
     * Extract raw client IP from a formatted "PeerName (IP)" string.
     * Returns an empty string for falsy input, the IP inside parentheses if present,
     * or the original value if no formatted suffix exists.
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

    function getClientIpsQueryParam() {
        const clientIps = getSelectedPeerClientIps();
        return clientIps ? `&client_ips=${encodeURIComponent(clientIps)}` : '';
    }

    function clearNode(el) {
        if (el) el.replaceChildren();
    }

    function setBusyState(el, busy) {
        if (!el) return;
        el.setAttribute('aria-busy', busy ? 'true' : 'false');
    }

    function resetStatCards(placeholder = '–') {
        for (const id of STAT_IDS) {
            const el = document.getElementById(id);
            if (el) el.textContent = placeholder;
        }
    }

    function createLogPlaceholderRow(content, className = 'log-empty-cell') {
        const tr = document.createElement('tr');
        tr.className = 'log-empty-row';
        const td = document.createElement('td');
        td.colSpan = 3;
        td.className = className;
        if (typeof content === 'string') {
            td.textContent = content;
        } else {
            td.appendChild(content);
        }
        tr.appendChild(td);
        return tr;
    }

    function formatYAxisTick(value) {
        return fmtNum(Number(value)).replace('k', 'K');
    }

    function closeLogActionMenu() {
        const menu = document.getElementById('log-action-menu');
        if (!menu) return;
        menu.classList.remove('show');
        _logActionState = null;
        // Reset ARIA expanded state on all rows
        for (const el of document.querySelectorAll('[aria-expanded="true"]')) {
            el.setAttribute('aria-expanded', 'false');
        }
    }

    function openLogActionMenu(q, clickEvent) {
        if (!isAdmin) return;
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

        const clientIp = _extractClientIp(q.client || '');
        _logActionState = {
            domain: q.domain || '',
            client: clientIp,
            clientName: _peerMap[clientIp.toLowerCase()] || '',
            blocked,
        };

        // Position the menu - handle both mouse and keyboard events
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;
        let x, y;

        if (clickEvent.clientX != null && clickEvent.clientX !== 0) {
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

        // Show menu first so we can measure its actual dimensions
        menu.classList.add('show');
        const menuRect = menu.getBoundingClientRect();

        // Position with viewport boundary checking using actual menu dimensions
        menu.style.left = `${Math.min(x, viewportWidth - menuRect.width - 8)}px`;
        menu.style.top = `${Math.min(y, viewportHeight - menuRect.height - 8)}px`;

        // Set ARIA expanded on the triggering row
        const row = clickEvent.target.closest('tr');
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
        if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
        if (n >= 10_000) return (n / 1_000).toFixed(0) + 'k';
        if (n >= 1_000) return (n / 1_000).toFixed(1) + 'k';
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

    // Client-side cache for DNS trend data (5-minute TTL)
    const TREND_CACHE_TTL_MS = 5 * 60 * 1000;
    const TREND_CACHE_KEY = 'wb_dns_trend_cache';

    function getTrendCache(cacheKey) {
        try {
            const raw = sessionStorage.getItem(TREND_CACHE_KEY);
            if (!raw) return null;
            const cache = JSON.parse(raw);
            if (cache.key !== cacheKey) return null;
            if (Date.now() - cache.ts > TREND_CACHE_TTL_MS) return null;
            return cache.data;
        } catch { return null; }
    }

    function setTrendCache(cacheKey, data) {
        try {
            sessionStorage.setItem(TREND_CACHE_KEY, JSON.stringify({
                key: cacheKey, ts: Date.now(), data
            }));
        } catch { /* quota exceeded or private mode */ }
    }

    function clearTrendCache() {
        try { sessionStorage.removeItem(TREND_CACHE_KEY); } catch { }
    }

    /**
     * Get hours for current time range selection.
     * Uses shared parseTimeRangeToHours for consistency across pages.
     */
    function getSelectedRangeHours() {
        const rangeEl = document.getElementById('dns-range');
        const value = rangeEl?.value || '7d';
        // Use shared function for consistency with other pages (Dashboard, Traffic)
        return window.WBShared?.parseTimeRangeToHours?.(value) ?? 168;
    }

    async function loadTrend() {
        // Skip trend loading if DNS is unavailable; preserve unavailable state.
        if (_dnsUnavailable) return;

        // Skip trend loading if ad-blocker is disabled (shows disabled state instead)
        if (!_adblockerEnabled) return;

        try {
            const rangeHours = getSelectedRangeHours();
            // Bucket size adapts to viewport and range
            const baseBucket = getTrendBucketMinutes();
            // Scale bucket size with range (larger ranges need bigger buckets)
            const rangeMultiplier = Math.max(1, Math.ceil(rangeHours / 720));
            const bucketMinutes = Math.min(1440 * rangeMultiplier, Math.max(5, baseBucket * rangeMultiplier));
            const clientIps = getSelectedPeerClientIps();
            const clientIpsParam = getClientIpsQueryParam();

            // Build cache key from parameters
            const cacheKey = `${rangeHours}|${bucketMinutes}|${clientIps || ''}`;
            let t = getTrendCache(cacheKey);

            if (!t) {
                t = await api('GET', `/api/dns/trend?hours=${rangeHours}&bucket_minutes=${bucketMinutes}${clientIpsParam}`);
                setTrendCache(cacheKey, t);
            }
            const labels = (t.labels || []).map(_fmtTrendLabel);
            const blocked = t.blocked || [];
            const total = t.total || [];
            const rate = t.block_rate || [];

            const loadingEl = document.getElementById('trend-loading');
            const trendWrap = document.getElementById('trend-chart-wrap');
            const emptyEl = document.getElementById('trend-empty');
            const unavailableEl = document.getElementById('trend-unavailable');

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
                                    callback: formatYAxisTick,
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
            document.getElementById('trend-meta').textContent = 'Trend unavailable';
        }
    }

    async function loadStats() {
        try {
            const rangeHours = getSelectedRangeHours();
            const clientIpsParam = getClientIpsQueryParam();
            const s = await api('GET', `/api/dns/status?hours=${rangeHours}${clientIpsParam}`);

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

            // Update adblocker button state (status is loaded separately for timer info)
            // Only update the enabled state from config; status endpoint handles timer
            const btn = document.getElementById('adblocker-btn');
            const btnText = document.getElementById('adblocker-btn-text');
            if (btn && isAdmin) {
                // Disable button if Unbound is not installed
                if (s.unavailable) {
                    btn.disabled = true;
                    btn.title = s.reason || 'DNS unavailable';
                    // Visual state: show as disabled (red)
                    btn.classList.remove('btn-adblocker-enabled');
                    btn.classList.add('btn-adblocker-disabled');
                    // Update button text to reflect unavailable state
                    if (btnText) btnText.textContent = 'Ad-Blocker: Unavailable';
                    // Show unavailable state for all DNS sections
                    updateDnsUnavailable(true);
                } else {
                    btn.disabled = false;
                    btn.title = '';
                    // Clear unavailable state if DNS becomes available
                    updateDnsUnavailable(false);
                }
            }
        } catch (e) {
            // Update status for error state using DOM APIs
            const statusEl = document.getElementById('stat-status');
            if (statusEl) {
                statusEl.textContent = '?';
                statusEl.className = 'dns-stat-value text-muted';
            }
            resetStatCards();
        }
    }

    async function loadTopDomains() {
        // Skip if DNS is unavailable; preserve unavailable state.
        if (_dnsUnavailable) return;

        try {
            const rangeHours = getSelectedRangeHours();
            const clientIpsParam = getClientIpsQueryParam();
            setBusyState(_stateEls.queriedContent, true);
            setBusyState(_stateEls.blockedContent, true);
            const data = await api('GET', `/api/dns/top-domains?limit=15&hours=${rangeHours}${clientIpsParam}`);
            const topQueried = data.top_queried || [];
            const topBlocked = data.top_blocked || [];

            // Both render as horizontal bar charts
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
            // Only render blocked domains if ad-blocker is enabled
            if (_adblockerEnabled) {
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
            } else {
                // Show disabled state for Top Blocked when ad-blocker is off
                const blockedLoading = document.getElementById('top-blocked-loading');
                const blockedContent = document.getElementById('top-blocked-content');
                const blockedEmpty = document.getElementById('top-blocked-empty');
                const blockedDisabled = document.getElementById('top-blocked-disabled');
                const blockedUnavailable = document.getElementById('top-blocked-unavailable');
                if (blockedLoading) blockedLoading.classList.add('d-none');
                if (blockedContent) blockedContent.classList.add('d-none');
                if (blockedEmpty) blockedEmpty.classList.add('d-none');
                if (blockedUnavailable) blockedUnavailable.classList.add('d-none');
                if (blockedDisabled) blockedDisabled.classList.remove('d-none');
                setBusyState(blockedContent, false);
            }
        } catch (e) {
            setBusyState(_stateEls.queriedContent, false);
            setBusyState(_stateEls.blockedContent, false);
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

    function prepareBarChartData(items, maxSlices = 9) {
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

        if (_dnsUnavailable) {
            if (loadingEl) loadingEl.classList.add('d-none');
            if (contentEl) contentEl.classList.add('d-none');
            if (emptyEl) emptyEl.classList.add('d-none');
            if (disabledEl) disabledEl.classList.add('d-none');
            if (unavailableEl) unavailableEl.classList.remove('d-none');
            setBusyState(contentEl, false);
            return;
        }

        if (loadingEl) loadingEl.classList.add('d-none');
        if (disabledEl) disabledEl.classList.add('d-none');
        if (unavailableEl) unavailableEl.classList.add('d-none');

        if (!items.length) {
            if (contentEl) contentEl.classList.add('d-none');
            if (emptyEl) emptyEl.classList.remove('d-none');
            setBusyState(contentEl, false);
            return;
        }

        if (contentEl) contentEl.classList.remove('d-none');
        if (emptyEl) emptyEl.classList.add('d-none');
        setBusyState(contentEl, false);

        const { labels, values, total } = prepareBarChartData(items, maxSlices);
        const chartColors = getChartColors(labels, colors);
        const maxVal = Math.max(...values, 1);

        clearNode(listEl);
        for (const [i, label] of labels.entries()) {
            const val = values[i];
            const pct = (val / maxVal) * 100;
            const totalPct = total > 0 ? (val / total * 100).toFixed(1) : 0;
            const color = chartColors[i] || defaultColor;

            const itemWrap = document.createElement('div');
            itemWrap.className = 'd-flex flex-column gap-1';
            itemWrap.setAttribute('role', 'listitem');
            itemWrap.setAttribute('aria-setsize', String(labels.length));
            itemWrap.setAttribute('aria-posinset', String(i + 1));

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
        }
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
        const hiddenText = document.createElement('span');
        hiddenText.className = 'visually-hidden';
        hiddenText.textContent = 'Loading query log…';
        spinner.appendChild(hiddenText);
        wrap.appendChild(spinner);
        tbody.appendChild(createLogPlaceholderRow(wrap, 'py-5'));
    }

    async function loadLogsOnly(showLoading = true) {
        // Skip if DNS is unavailable; preserve unavailable state.
        if (_dnsUnavailable) return;

        if (_logsLoadInProgress) return;
        _logsLoadInProgress = true;
        try {
            setBusyState(document.getElementById('log-table-wrap'), true);
            if (showLoading) {
                showLogsLoadingState();
            }
            const clientIpsParam = getClientIpsQueryParam();
            const data = await api('GET', `/api/dns/logs?lines=${LOG_FETCH_LIMIT}${clientIpsParam}`);
            _logData = data.queries || [];
            _renderedCount = 0;  // Reset for fresh render
            renderLogs();
            // Note: Scroll position restoration removed - with batched rendering,
            // restoring to a position beyond the initial batch is incorrect.
        } catch (e) {
            if (showLoading) {
                const tbody = document.getElementById('log-body');
                if (!tbody) return;
                clearNode(tbody);
                tbody.appendChild(createLogPlaceholderRow('Failed to load logs', 'text-center text-danger'));
            }
        } finally {
            setBusyState(document.getElementById('log-table-wrap'), false);
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
            const data = await api('GET', '/api/wireguard/stats/peers-enriched');
            const peers = data.peers || [];
            const peerFilter = document.getElementById('peer-filter');
            if (!peerFilter) return; // Guard against null

            const previousValue = peerFilter.value || 'all';
            _peerMap = {};

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
                    if (ip) _peerMap[ip] = name;
                }

                if (peer.name && !seenNames.has(name)) {
                    seenNames.add(name);
                    const opt = document.createElement('option');
                    opt.value = name;
                    opt.textContent = name;
                    peerFilter.appendChild(opt);
                }
            }

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

        // If not appending, reset and filter fresh
        if (!append) {
            _renderedCount = 0;
            // Always create a copy to avoid reference issues
            _filteredData = _logData.filter(q => {
                if (filter === 'blocked' && !q.blocked) return false;
                if (filter === 'allowed' && q.blocked) return false;
                if (peerFilter !== 'all' && (q.client_name || _peerMap[_extractClientIp(q.client || '').toLowerCase()] || '') !== peerFilter) return false;
                if (search && !(q.domain || '').toLowerCase().includes(search)) return false;
                return true;
            });
            clearNode(tbody);

            // Show empty message only on initial render
            if (!_filteredData.length) {
                tbody.appendChild(createLogPlaceholderRow(chartEmptyState()));
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
            const tr = logRowTemplate.content.firstElementChild.cloneNode(true);
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

            const tdTime = tr.querySelector('.log-col-time');
            const timeDate = tr.querySelector('.log-time-date');
            const timeClock = tr.querySelector('.log-time-clock');
            const timestamp = String(q.timestamp || '');
            const timeParts = timestamp.includes('T')
                ? timestamp.split('T')
                : timestamp.split(' ');
            if (timeParts.length >= 2) {
                timeDate.textContent = timeParts[0];
                timeClock.textContent = timeParts[1];
            } else {
                timeDate.textContent = timestamp;
                timeClock.remove();
            }

            // Domain with client/peer info below in gray
            const tdDomain = tr.querySelector('td[data-label="Domain"]');
            const domainWrap = tdDomain.querySelector('.log-domain-stack');
            const domainText = domainWrap.querySelector('.log-domain');
            domainText.textContent = q.domain || '';

            // Add Custom Rule badge if applicable
            if (q.custom_rule) {
                const badge = document.createElement('span');
                badge.className = 'badge dns-badge-custom-rule ms-2';
                badge.textContent = 'Custom Rule';
                domainWrap.appendChild(badge);
            }

            // Add client/peer info below domain
            const clientIp = _extractClientIp(q.client || '');
            const peerName = _peerMap[clientIp.toLowerCase()];
            const clientInfo = domainWrap.querySelector('.log-domain-client');
            if (!isAdmin) {
                clientInfo.textContent = 'Client hidden';
            } else {
                clientInfo.textContent = peerName ? `${peerName} (${clientIp})` : (q.client || '');
            }

            const tdType = tr.querySelector('.log-col-type');
            const typeCode = tdType.querySelector('code');
            typeCode.textContent = q.type || '';
            frag.appendChild(tr);
        }

        tbody.appendChild(frag);
        _renderedCount = endIdx;
        queueLogAutoFill();
    }

    function debouncedRenderLogs() {
        clearTimeout(_searchTimer);
        _searchTimer = setTimeout(renderLogs, 250);
    }

    function loadMoreLogs() {
        if (_isLoadingMore) return;
        if (_renderedCount >= _filteredData.length) return;  // All rendered

        _isLoadingMore = true;
        renderLogs(true);  // Append mode
        _isLoadingMore = false;
    }

    function queueLogAutoFill() {
        const logContainer = document.getElementById('log-table-wrap');
        if (!logContainer || _logAutoFillQueued || _renderedCount >= _filteredData.length) return;
        if (logContainer.scrollHeight > logContainer.clientHeight + 1) return;

        _logAutoFillQueued = true;
        requestAnimationFrame(() => {
            _logAutoFillQueued = false;
            const currentLogContainer = document.getElementById('log-table-wrap');
            if (!currentLogContainer) return;

            if (
                currentLogContainer.scrollHeight <= currentLogContainer.clientHeight + 1 &&
                _renderedCount < _filteredData.length
            ) {
                loadMoreLogs();
            }
        });
    }

    // Blocked sections visibility (Top Blocked Domains + Blockrate Trend)
    let _adblockerEnabled = dnsApp?.dataset.enableBlocklist === 'true';
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
        logUnavailable: document.getElementById('log-unavailable'),
    };
    _stateEls.logCardBody = _stateEls.logUnavailable?.parentElement || null;
    const _stateGroups = {
        queried: {
            loading: _stateEls.queriedLoading,
            content: _stateEls.queriedContent,
            empty: _stateEls.queriedEmpty,
            unavailable: _stateEls.queriedUnavailable,
        },
        blocked: {
            loading: _stateEls.blockedLoading,
            content: _stateEls.blockedContent,
            empty: _stateEls.blockedEmpty,
            disabled: _stateEls.blockedDisabled,
            unavailable: _stateEls.blockedUnavailable,
        },
        trend: {
            loading: _stateEls.trendLoading,
            content: _stateEls.trendChart,
            empty: _stateEls.trendEmpty,
            disabled: _stateEls.trendDisabled,
            unavailable: _stateEls.trendUnavailable,
        },
    };

    function hasVisibleState(...elements) {
        return elements.some(el => el && !el.classList.contains('d-none'));
    }

    function showExclusiveState(group, activeKey) {
        for (const [key, el] of Object.entries(group)) {
            if (!el) continue;
            el.classList.toggle('d-none', key !== activeKey);
        }
    }

    function showDnsLoadingState(options = {}) {
        const { stats = false, logs = false, trend = false, topDomains = false } = options;
        if (stats) resetStatCards();
        if (logs) showLogsLoadingState();
        if (trend && _adblockerEnabled) showExclusiveState(_stateGroups.trend, 'loading');
        if (topDomains) {
            showExclusiveState(_stateGroups.queried, 'loading');
            if (_adblockerEnabled) showExclusiveState(_stateGroups.blocked, 'loading');
        }
    }

    function updateBlockedSectionsVisibility(enabled) {
        _adblockerEnabled = enabled;  // Cache state for other functions

        if (enabled) {
            // Preserve already loaded chart/empty states; only show loading while data is unresolved.
            const blockedResolved = hasVisibleState(_stateGroups.blocked.content, _stateGroups.blocked.empty);
            const trendResolved = hasVisibleState(_stateGroups.trend.content, _stateGroups.trend.empty);

            if (blockedResolved) {
                if (_stateGroups.blocked.loading) _stateGroups.blocked.loading.classList.add('d-none');
            } else {
                showExclusiveState(_stateGroups.blocked, 'loading');
            }

            if (trendResolved) {
                if (_stateGroups.trend.loading) _stateGroups.trend.loading.classList.add('d-none');
            } else {
                showExclusiveState(_stateGroups.trend, 'loading');
            }
        } else {
            showExclusiveState(_stateGroups.blocked, 'disabled');
            showExclusiveState(_stateGroups.trend, 'disabled');
        }
    }

    // DNS unavailable state (Unbound not installed) - read initial state from server
    let _dnsUnavailable = dnsApp ? (dnsApp.dataset.dnsUnavailable === 'true') : false;

    function updateDnsUnavailable(unavailable) {
        _dnsUnavailable = unavailable;

        if (unavailable) {
            showExclusiveState(_stateGroups.queried, 'unavailable');
            showExclusiveState(_stateGroups.blocked, 'unavailable');
            showExclusiveState(_stateGroups.trend, 'unavailable');
            if (_stateEls.logCardBody) _stateEls.logCardBody.classList.add('dns-log-unavailable');
            if (_stateEls.logUnavailable) _stateEls.logUnavailable.classList.remove('d-none');
            setBusyState(_stateEls.queriedContent, false);
            setBusyState(_stateEls.blockedContent, false);
            setBusyState(_stateEls.trendChart, false);
            setBusyState(document.getElementById('log-table-wrap'), false);
        } else {
            // Hide unavailable states
            if (_stateGroups.queried.unavailable) _stateGroups.queried.unavailable.classList.add('d-none');
            if (_stateGroups.blocked.unavailable) _stateGroups.blocked.unavailable.classList.add('d-none');
            if (_stateGroups.trend.unavailable) _stateGroups.trend.unavailable.classList.add('d-none');
            if (_stateEls.logCardBody) _stateEls.logCardBody.classList.remove('dns-log-unavailable');
            if (_stateEls.logUnavailable) _stateEls.logUnavailable.classList.add('d-none');
        }
    }

    // Ad-Blocker dropdown state
    let _adblockerCountdownInterval = null;
    let _adblockerDisabledUntil = 0;

    function updateAdblockerButton(enabled, disabledUntil = 0) {
        const btn = document.getElementById('adblocker-btn');
        const btnText = document.getElementById('adblocker-btn-text');
        const countdown = document.getElementById('adblocker-countdown');
        if (!btn || !btnText || !countdown) return;

        _adblockerDisabledUntil = disabledUntil;

        // Update button color
        btn.classList.remove('btn-adblocker-enabled', 'btn-adblocker-disabled');
        btn.classList.add(enabled ? 'btn-adblocker-enabled' : 'btn-adblocker-disabled');

        // Update button text
        btnText.textContent = enabled ? 'Ad-Blocker: Enabled' : 'Ad-Blocker: Disabled';

        // Update Top Blocked Domains and Blockrate Trend visibility
        updateBlockedSectionsVisibility(enabled);

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
            const data = await api('GET', '/api/dns/adblocker/status');
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

            // If enabling, reload blocked sections (they were showing disabled state)
            if (data.enabled) {
                clearTrendCache();  // Force fresh data after ad-blocker toggle
                await Promise.allSettled([loadTopDomains(), loadTrend()]);
            }

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
    for (const item of document.querySelectorAll('[data-adblocker-mode]')) {
        item.addEventListener('click', function (e) {
            e.preventDefault();
            if (!isAdmin) return;
            const mode = this.getAttribute('data-adblocker-mode');
            setAdblockerMode(mode);
        });
    }

    async function pollTick() {
        if (_pollInProgress) return;
        _pollInProgress = true;
        try {
            _pollCount += 1;
            await Promise.allSettled([loadStats(), loadLogsOnly(false)]);
            if (_pollCount % 4 === 0) {
                await Promise.allSettled([loadTopDomains(), loadTrend(), loadPeers()]);
            }
        } finally {
            _pollInProgress = false;
        }
    }

    function startPolling() {
        stopPolling();
        _pollInterval = setInterval(pollTick, 15000);
    }

    function stopPolling() {
        if (_pollInterval) {
            clearInterval(_pollInterval);
            _pollInterval = null;
        }
    }

    document.addEventListener('visibilitychange', async () => {
        if (document.hidden) {
            stopPolling();
            closeLogActionMenu();
            if (_scrollRaf) {
                cancelAnimationFrame(_scrollRaf);
                _scrollRaf = null;
            }
        } else {
            // Load all data in parallel
            await Promise.allSettled([
                loadPeers(), loadStats(), loadTopDomains(),
                loadTrend(), loadLogsOnly(), loadAdblockerStatus()
            ]);
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

    const _themeObserver = new MutationObserver(() => {
        applyTrendTheme();
    });
    _themeObserver.observe(document.documentElement, {
        attributes: true,
        attributeFilter: ['data-bs-theme'],
    });

    window.addEventListener('pagehide', () => {
        stopPolling();
        _themeObserver.disconnect();
        if (_adblockerCountdownInterval) clearInterval(_adblockerCountdownInterval);
        if (_searchTimer) clearTimeout(_searchTimer);
        if (_scrollRaf) cancelAnimationFrame(_scrollRaf);
    }, { once: true });

    // Infinite scroll for Query Log (throttled with RAF)
    const logContainer = document.getElementById('log-table-wrap');
    if (logContainer) {
        logContainer.addEventListener('scroll', function () {
            if (_scrollRaf) return;
            _scrollRaf = requestAnimationFrame(() => {
                const scrollBottom = logContainer.scrollHeight - logContainer.scrollTop - logContainer.clientHeight;
                if (scrollBottom < 150 || logContainer.scrollHeight <= logContainer.clientHeight + 1) {
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
            const row = ev.target.closest('tr.log-row-actionable');
            if (!row) return;
            const idx = parseInt(row.dataset.logIndex, 10);
            const q = _filteredData[idx];
            if (q) {
                ev.preventDefault();
                ev.stopPropagation();
                openLogActionMenu(q, ev);
            }
        });

        logBody.addEventListener('keydown', (ev) => {
            if (ev.key !== 'Enter' && ev.key !== ' ') return;
            const row = ev.target.closest('tr.log-row-actionable');
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
        logFilterSelect.addEventListener('change', () => loadLogsOnly());
    }

    const peerFilterSelect = document.getElementById('peer-filter');
    if (peerFilterSelect) {
        // Load fresh data when peer filter changes - affects stats, logs, trend, and top domains
        peerFilterSelect.addEventListener('change', async () => {
            clearTrendCache();
            showDnsLoadingState({ stats: true, logs: true, trend: true, topDomains: true });
            await Promise.allSettled([loadStats(), loadLogsOnly(), loadTrend(), loadTopDomains()]);
        });
    }

    const dnsRangeSelect = document.getElementById('dns-range');
    if (dnsRangeSelect) {
        // Reload all range-aware DNS sections when time range changes
        dnsRangeSelect.addEventListener('change', async () => {
            clearTrendCache();
            showDnsLoadingState({ stats: true, trend: true, topDomains: true });
            await Promise.allSettled([loadStats(), loadTopDomains(), loadTrend()]);
        });
    }

    const logSearchInput = document.getElementById('log-search');
    if (logSearchInput) {
        // Only filter existing data on search (debounced)
        logSearchInput.addEventListener('input', debouncedRenderLogs);
    }


    // Initial load - wait for completion before starting polling to avoid race conditions
    (async () => {
        // If DNS is unavailable (Unbound not installed), show unavailable state immediately
        // and skip all API calls
        if (_dnsUnavailable) {
            updateDnsUnavailable(true);
            // Still load peers for the filter dropdown (doesn't require Unbound)
            await loadPeers();
            return; // Skip polling - nothing to poll
        }

        await Promise.allSettled([
            loadPeers(), loadStats(), loadTopDomains(),
            loadTrend(), loadLogsOnly(), loadAdblockerStatus()
        ]);
        startPolling(); // Only start polling after initial load completes
    })();
})();
