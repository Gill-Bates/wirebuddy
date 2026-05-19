//
// app/static/js/nodes.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

(function () {
    'use strict';

    // ========================================================================
    // CONSTANTS & STATE
    // ========================================================================
    const POLL_INTERVAL_MS = 30000;
    const MAX_POLL_FAILURES = 3;
    const POLL_BACKOFF_MS = 60000;
    const SPEEDTEST_STORAGE_KEY = 'wb_nodes_active_speedtests';
    const SPEEDTEST_LOCK_TIMEOUT_MS = 180000;
    const SPEEDTEST_STATUS_POLL_MS = 5000;
    const FLAG_ICON_BASE_URL = document.getElementById('nodesPageRoot')?.dataset.flagIconBaseUrl
        || '/static/vendor/flag-icons/flags/4x3';
    const HOVER_MEDIA = window.matchMedia('(hover: hover) and (pointer: fine)');

    let pollTimer = null;
    let speedtestStatusTimer = null;
    let pollFailureCount = 0;
    let nodeCreatedFlag = false;
    let pollController = null;
    let _pollSeq = 0; // Request versioning to guard against out-of-order responses
    const restartingNodes = new Map(); // node_id → { phase: 'sent'|'offline', timeout: number }
    const activeSpeedtests = new Map(); // node_id → { nodeName, baselineTs, startedAt, phase }
    const NODE_ROW_PREFIX = 'node-row-';

    // ========================================================================
    // DOM ELEMENT CACHE
    // ========================================================================
    const addNodeModalEl = document.getElementById('addNodeModal');
    const editNodeModalEl = document.getElementById('editNodeModal');
    const tokenModalEl = document.getElementById('tokenModal');
    const addNodeForm = document.getElementById('addNodeForm');
    const editNodeForm = document.getElementById('editNodeForm');
    let nodesTableBody = document.getElementById('nodesTableBody');
    const addNodeFqdnInput = document.getElementById('nodeFqdn');
    const editNodeFqdnInput = document.getElementById('editNodeFqdn');
    const addNodeSubmitBtn = document.getElementById('addNodeSubmitBtn');
    const nodeNameInput = document.getElementById('addNodeName');
    const enrollmentTokenDisplay = document.getElementById('enrollmentTokenDisplay');
    const regenTokenDisplay = document.getElementById('regenTokenDisplay');

    for (const dependency of ['api', 'wbToast', 'wbAlert', 'wbConfirm']) {
        if (typeof window[dependency] !== 'function') {
            console.error(`[nodes] Required global "${dependency}" is not defined. Page functionality disabled.`);
            return;
        }
    }

    // Local bandwidth formatting function (mirrors WBShared.formatBandwidthMetric)
    function formatBandwidthMbit(valueMbit, gbitDigits = 1, mbitDigits = gbitDigits) {
        const numericValue = Number(valueMbit);
        if (!Number.isFinite(numericValue)) return '–';
        const isGbit = numericValue >= 1000;
        const scaled = isGbit ? numericValue / 1000 : numericValue;
        const digits = Math.max(Number(isGbit ? gbitDigits : mbitDigits) || 0, 0);
        return `${scaled.toFixed(digits)} ${isGbit ? 'Gbit/s' : 'Mbit/s'}`;
    }

    const HOSTNAME_LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

    // ========================================================================
    // VALIDATION
    // ========================================================================
    function isValidIpv4(value) {
        const parts = value.split('.');
        if (parts.length !== 4) return false;
        return parts.every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
    }

    function isValidIpv6(value) {
        const raw = value.replace(/^\[|\]$/g, '');
        if (!raw || raw.includes('[') || raw.includes(']')) return false;
        if (raw.includes('%')) return false;

        // Use URL parsing for robust IPv6 validation
        try {
            const url = new URL(`http://[${raw}]`);
            return !!url.hostname;
        } catch {
            return false;
        }
    }

    function isValidHostname(value) {
        if (!value || value.length > 253) return false;
        // Hostnames never contain ':'; reject IPv6 literals and host:port input early.
        if (value.includes(':')) return false;
        if (value.includes('..') || value.startsWith('.') || value.endsWith('.')) return false;
        return value.split('.').every((label) => HOSTNAME_LABEL_RE.test(label));
    }

    function validateNodeAddressValue(value) {
        const trimmed = value.trim();
        if (!trimmed) {
            return { valid: false, message: 'FQDN / IP Address is required.' };
        }
        if (isValidIpv4(trimmed) || isValidIpv6(trimmed) || isValidHostname(trimmed)) {
            return { valid: true, message: '' };
        }
        return {
            valid: false,
            message: 'Enter a valid FQDN, IPv4, or IPv6 address without a port.',
        };
    }

    function validateNodeAddressField(input) {
        if (!(input instanceof HTMLInputElement)) return false;
        const result = validateNodeAddressValue(input.value);
        input.setCustomValidity(result.message);
        input.classList.toggle('is-invalid', !result.valid);
        input.classList.toggle('is-valid', result.valid && input.value.trim().length > 0);

        const feedbackId = `${input.id}Feedback`;
        const feedback = document.getElementById(feedbackId);
        if (feedback) {
            feedback.textContent = result.message || 'Enter a valid FQDN, IPv4, or IPv6 address without a port.';
        }
        return result.valid;
    }

    function resetNodeAddressFieldValidation(input) {
        if (!(input instanceof HTMLInputElement)) return;
        input.setCustomValidity('');
        input.classList.remove('is-invalid', 'is-valid');
    }

    function getValidatedPort(inputId) {
        const portInput = document.getElementById(inputId);
        if (!(portInput instanceof HTMLInputElement)) {
            console.error(`[nodes] Required port input "${inputId}" is missing.`);
            return null;
        }

        const port = Number(portInput.value);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            portInput.setCustomValidity('Enter a valid port number (1-65535).');
            portInput.reportValidity();
            return null;
        }

        portInput.setCustomValidity('');
        return port;
    }

    // ========================================================================
    // UI HELPERS
    // ========================================================================
    function createStatusBadge(status) {
        const span = document.createElement('span');
        span.classList.add('badge', 'node-status-badge');

        if (status === 'online') {
            span.classList.add('bg-success');
            span.textContent = 'Online';
        } else if (status === 'pending') {
            span.classList.add('bg-warning', 'text-dark');
            span.textContent = 'Pending';
        } else if (status === 'offline') {
            span.classList.add('bg-danger');
            span.textContent = 'Offline';
        } else if (status === 'restarting') {
            span.classList.add('bg-secondary');
            span.textContent = 'Restarting…';
        } else {
            span.classList.add('bg-secondary');
            span.textContent = status || '—';
        }

        return span;
    }

    function syncNodeStatusCell(row, node) {
        if (!row || !node) return;

        const nodeId = String(node.id || '');
        const statusCell = row.querySelector('td[data-label="Status"]');
        if (!statusCell) return;

        const rawStatus = node.status || '';
        row.dataset.nodeStatus = rawStatus;

        let effectiveStatus = rawStatus;
        const restartEntry = restartingNodes.get(nodeId);
        if (restartEntry) {
            if (rawStatus === 'offline') {
                restartEntry.phase = 'offline';
                effectiveStatus = 'restarting';
            } else if (rawStatus === 'online' && restartEntry.phase === 'offline') {
                if (restartEntry.timeout) clearTimeout(restartEntry.timeout);
                restartingNodes.delete(nodeId);
                effectiveStatus = 'online';
            } else {
                effectiveStatus = 'restarting';
            }
        }

        if (statusCell.dataset.status !== effectiveStatus) {
            statusCell.replaceChildren(createStatusBadge(effectiveStatus));
            statusCell.dataset.status = effectiveStatus;
        }
    }

    function setButtonLoading(button, isLoading, loadingText = 'Loading...', originalText = null) {
        if (!button) return;

        if (isLoading) {
            button.disabled = true;
            if (!button.dataset.originalText) {
                button.dataset.originalText = button.textContent?.trim() || 'Submit';
            }
            const spinner = document.createElement('span');
            spinner.className = 'spinner-border spinner-border-sm me-1';
            spinner.setAttribute('role', 'status');
            spinner.setAttribute('aria-hidden', 'true');
            button.replaceChildren(spinner, document.createTextNode(loadingText));
        } else {
            button.disabled = false;
            button.textContent = originalText ? originalText : (button.dataset.originalText || 'Submit');
        }
    }

    function normalizeCountryCode(value) {
        const code = String(value || '').trim().toLowerCase();
        return /^[a-z]{2}$/.test(code) ? code : '';
    }

    function normalizeSpeedtestTimestamp(value) {
        if (typeof value !== 'string') return '';
        const trimmed = value.trim();
        if (!trimmed) return '';
        const parsed = Date.parse(trimmed);
        return Number.isFinite(parsed) ? trimmed : '';
    }

    function getNodeMobileSummaryFingerprint(node) {
        return JSON.stringify([
            node?.node_version || '',
            node?.wg_port ?? '',
            node?.peer_count ?? 0,
            node?.last_seen_text || 'Never',
        ]);
    }

    function getSpeedtestFingerprint(speedtest) {
        if (!speedtest || speedtest.status !== 'ok') {
            return 'empty';
        }
        return JSON.stringify([
            speedtest.ts || '',
            speedtest.download_mbit ?? '',
            speedtest.upload_mbit ?? '',
            speedtest.server || '',
            speedtest.country_code || '',
        ]);
    }

    function disposeTooltips(root) {
        if (typeof bootstrap === 'undefined' || !bootstrap.Tooltip || !root?.querySelectorAll) {
            return;
        }
        for (const el of root.querySelectorAll('[data-bs-toggle="tooltip"]')) {
            bootstrap.Tooltip.getInstance(el)?.dispose();
        }
    }

    function clearRestartingNodeTimeouts() {
        for (const entry of restartingNodes.values()) {
            if (entry?.timeout) {
                clearTimeout(entry.timeout);
            }
        }
        restartingNodes.clear();
    }

    function persistActiveSpeedtests() {
        try {
            if (!activeSpeedtests.size) {
                localStorage.removeItem(SPEEDTEST_STORAGE_KEY);
                return;
            }

            const serialized = {};
            for (const [nodeId, entry] of activeSpeedtests.entries()) {
                serialized[nodeId] = {
                    nodeName: entry.nodeName || 'node',
                    baselineTs: entry.baselineTs || '',
                    startedAt: entry.startedAt,
                    phase: entry.phase === 'starting' ? 'starting' : 'running',
                };
            }
            localStorage.setItem(SPEEDTEST_STORAGE_KEY, JSON.stringify(serialized));
        } catch (err) {
            console.warn('[nodes] localStorage write failed:', err);
        }
    }

    function loadActiveSpeedtests() {
        let raw = '';
        try {
            raw = localStorage.getItem(SPEEDTEST_STORAGE_KEY) || '';
        } catch (err) {
            console.warn('[nodes] localStorage read failed:', err);
            return;
        }

        if (!raw) return;

        try {
            const parsed = JSON.parse(raw);
            const now = Date.now();
            for (const [nodeId, entry] of Object.entries(parsed || {})) {
                const startedAt = Number(entry?.startedAt);
                if (!nodeId || !Number.isFinite(startedAt)) continue;
                if (now - startedAt > SPEEDTEST_LOCK_TIMEOUT_MS) continue;

                activeSpeedtests.set(String(nodeId), {
                    nodeName: typeof entry?.nodeName === 'string' ? entry.nodeName : 'node',
                    baselineTs: normalizeSpeedtestTimestamp(entry?.baselineTs || ''),
                    startedAt,
                    phase: entry?.phase === 'starting' ? 'starting' : 'running',
                });
            }
            persistActiveSpeedtests();
        } catch (parseErr) {
            console.warn('[nodes] Failed to parse speedtest state from localStorage:', parseErr);
            try {
                localStorage.removeItem(SPEEDTEST_STORAGE_KEY);
            } catch (cleanupErr) {
                console.warn('[nodes] localStorage cleanup failed:', cleanupErr);
            }
        }
    }

    function setActiveSpeedtest(nodeId, entry) {
        activeSpeedtests.set(String(nodeId), {
            nodeName: entry.nodeName || 'node',
            baselineTs: normalizeSpeedtestTimestamp(entry.baselineTs || ''),
            startedAt: Number(entry.startedAt) || Date.now(),
            phase: entry.phase === 'starting' ? 'starting' : 'running',
        });
        persistActiveSpeedtests();
    }

    function clearActiveSpeedtest(nodeId) {
        activeSpeedtests.delete(String(nodeId));
        persistActiveSpeedtests();
    }

    function updateTooltipTitle(button, title) {
        if (!button) return;
        if (button.getAttribute('data-bs-title') === title) return;
        button.setAttribute('data-bs-title', title);
        const tooltip = bootstrap.Tooltip.getInstance(button);
        if (tooltip) {
            tooltip.setContent({ '.tooltip-inner': title });
        }
    }

    function applySpeedtestButtonState(button, isOnline, activeEntry = null) {
        if (!button) return;

        const locked = Boolean(activeEntry);
        const title = !isOnline
            ? 'Node is offline'
            : locked && activeEntry?.phase === 'starting'
                ? 'Starting Speedtest…'
                : locked
                    ? 'Speedtest running'
                    : 'Run Speedtest';

        button.disabled = !isOnline || locked;
        button.classList.toggle('btn-secondary', locked);
        button.classList.toggle('btn-outline-secondary', !locked);
        button.setAttribute('aria-busy', locked ? 'true' : 'false');
        updateTooltipTitle(button, title);
    }

    function syncSpeedtestButtonForRow(row, nodeStatus = null) {
        if (!row) return;
        const button = row.querySelector('button[data-action="run-speedtest"]');
        if (!button) return;

        // Only two authoritative sources: explicit parameter or row dataset
        const resolvedStatus = nodeStatus ?? row.dataset.nodeStatus ?? '';
        const entry = activeSpeedtests.get(String(button.dataset.nodeId || '')) || null;
        applySpeedtestButtonState(button, resolvedStatus === 'online', entry);
    }

    /**
     * Returns true if the speedtest for the given entry has completed.
        * Completion compares the latest result timestamp against the stored baseline.
        * If baselineTs is set, any different timestamp means the run finished. If it is
        * empty, any timestamp at or after startedAt (minus 5s skew tolerance) counts.
     * @param {object} entry - Active speedtest state from activeSpeedtests
        * @param {string} latestTs - Pre-normalized ISO timestamp of the latest result, or empty string
        * @returns {boolean}
     */
    function hasSpeedtestCompleted(entry, latestTs) {
        if (!latestTs) return false;

        if (entry.baselineTs) {
            return latestTs !== entry.baselineTs;
        }

        const latestMs = Date.parse(latestTs);
        return Number.isFinite(latestMs) && latestMs >= entry.startedAt - 5000;
    }

    function createFlagImage(countryCode, { altPrefix = 'Country flag' } = {}) {
        const code = normalizeCountryCode(countryCode);
        if (!code) return null;

        const img = document.createElement('img');
        img.className = 'node-country-flag';
        img.alt = `${altPrefix}: ${code.toUpperCase()}`;
        img.width = 16;
        img.height = 12;
        img.loading = 'lazy';
        img.decoding = 'async';
        img.src = `${FLAG_ICON_BASE_URL}/${code}.svg`;
        img.addEventListener('error', () => img.remove(), { once: true });
        return img;
    }

    /**
        * Attach error handlers and dimension guards to all .node-country-flag images in root.
        * Idempotent: already initialized images are skipped via data-flag-initialized.
        * Used for server-rendered rows; JS-built rows use createFlagImage() directly.
        * @param {Document|Element} [root=document]
     */
    function initFlagImages(root = document) {
        const scope = root && typeof root.querySelectorAll === 'function' ? root : document;
        for (const img of scope.querySelectorAll('img.node-country-flag')) {
            if (img.dataset.flagInitialized === 'true') continue;
            img.width ||= 16;
            img.height ||= 12;
            img.addEventListener('error', () => img.remove(), { once: true });
            if (img.complete && img.naturalWidth === 0) {
                img.remove();
                continue;
            }
            img.dataset.flagInitialized = 'true';
        }
    }

    async function fetchLatestSpeedtestByNode() {
        const payload = await api('GET', '/api/wireguard/speedtest/nodes');
        const nodes = Array.isArray(payload?.nodes) ? payload.nodes : [];
        const latestByNode = new Map();

        for (const node of nodes) {
            if (!node?.node_id) continue;
            latestByNode.set(String(node.node_id), node.last_speedtest || null);
        }

        return latestByNode;
    }

    async function checkActiveSpeedtests() {
        if (!activeSpeedtests.size) {
            stopSpeedtestStatusPolling();
            return;
        }

        let latestByNode;
        try {
            latestByNode = await fetchLatestSpeedtestByNode();
        } catch (_) {
            return;
        }

        const now = Date.now();
        // Map iteration is safe with delete per ECMAScript spec — no spread needed
        for (const [nodeId, entry] of activeSpeedtests) {
            const row = document.getElementById(`${NODE_ROW_PREFIX}${nodeId}`);
            if (!row) {
                clearActiveSpeedtest(nodeId);
                continue;
            }

            const latestSpeedtest = latestByNode.get(nodeId) || null;
            const latestTs = normalizeSpeedtestTimestamp(latestSpeedtest?.ts || '');

            if (latestTs) {
                row.dataset.lastSpeedtestTs = latestTs;
            }

            if (hasSpeedtestCompleted(entry, latestTs)) {
                clearActiveSpeedtest(nodeId);
                syncSpeedtestButtonForRow(row);
                continue;
            }

            if (now - entry.startedAt > SPEEDTEST_LOCK_TIMEOUT_MS) {
                clearActiveSpeedtest(nodeId);
                syncSpeedtestButtonForRow(row);
                wbToast(`Speedtest on "${entry.nodeName}" timed out or returned no result. Button re-enabled.`, 'warning');
                continue;
            }

            if (entry.phase !== 'running') {
                activeSpeedtests.set(nodeId, { ...entry, phase: 'running' });
                persistActiveSpeedtests();
            }
            syncSpeedtestButtonForRow(row);
        }

        if (!activeSpeedtests.size) {
            stopSpeedtestStatusPolling();
        }
    }

    function ensureSpeedtestStatusPolling() {
        if (!activeSpeedtests.size || document.hidden) return;
        if (speedtestStatusTimer) return;
        speedtestStatusTimer = setInterval(() => {
            void checkActiveSpeedtests();
        }, SPEEDTEST_STATUS_POLL_MS);
    }

    function stopSpeedtestStatusPolling() {
        if (!speedtestStatusTimer) return;
        clearInterval(speedtestStatusTimer);
        speedtestStatusTimer = null;
    }

    function syncAllSpeedtestButtons() {
        if (!nodesTableBody) return;
        for (const row of nodesTableBody.querySelectorAll(`tr[id^="${NODE_ROW_PREFIX}"]`)) {
            syncSpeedtestButtonForRow(row);
        }
    }

    function initTooltips(root = document) {
        if (!HOVER_MEDIA.matches) {
            return;
        }
        if (typeof bootstrap === 'undefined' || !bootstrap.Tooltip) {
            return;
        }

        const scope = root && typeof root.querySelectorAll === 'function' ? root : document;
        for (const el of scope.querySelectorAll('[data-bs-toggle="tooltip"]')) {
            if (el.dataset.tooltipInitialized === 'true') {
                continue;
            }
            bootstrap.Tooltip.getOrCreateInstance(el, {
                container: document.body,
                trigger: 'hover focus',
            });
            el.dataset.tooltipInitialized = 'true';
        }
    }

    function initNodeActionDropdowns(root = document) {
        if (typeof bootstrap === 'undefined' || !bootstrap.Dropdown) {
            return;
        }

        const scope = root && typeof root.querySelectorAll === 'function' ? root : document;
        for (const trigger of scope.querySelectorAll('.node-actions-more-toggle')) {
            if (trigger.dataset.dropdownInitialized === 'true') {
                continue;
            }

            trigger.dataset.dropdownInitialized = 'true';
            bootstrap.Dropdown.getOrCreateInstance(trigger);
            trigger.addEventListener('click', (event) => {
                event.preventDefault();
                event.stopPropagation();
                bootstrap.Dropdown.getOrCreateInstance(trigger).toggle();
            });
        }
    }

    /**
     * Update the mobile summary block inside the FQDN cell.
     * This keeps entity metadata close to the identity block instead of hiding it in a spare td.
     */
    function syncNodeMobileSummaryCell(container, node) {
        if (!container) return;

        const fingerprint = getNodeMobileSummaryFingerprint(node);
        if (container.dataset.summaryFingerprint === fingerprint) return;

        const fragments = [];
        if (node.node_version) {
            const versionSpan = document.createElement('span');
            versionSpan.className = 'node-mobile-summary-version';
            versionSpan.textContent = `v${node.node_version}`;
            fragments.push(versionSpan);
        }

        if (node.wg_port) {
            const portSpan = document.createElement('span');
            portSpan.className = 'node-mobile-summary-port';
            portSpan.textContent = `${node.wg_port}/udp`;
            fragments.push(portSpan);
        }

        const peerSpan = document.createElement('span');
        const peerCount = node.peer_count ?? 0;
        peerSpan.textContent = `${peerCount} Peer${peerCount !== 1 ? 's' : ''}`;
        fragments.push(peerSpan);

        const lastSeenSpan = document.createElement('span');
        lastSeenSpan.textContent = node.last_seen_text || 'Never';
        fragments.push(lastSeenSpan);

        container.replaceChildren(...fragments);
        container.dataset.summaryFingerprint = fingerprint;
    }

    function renderSpeedtestCell(cell, speedtest) {
        if (!cell) return;

        const fingerprint = getSpeedtestFingerprint(speedtest);
        if (cell.dataset.speedtestFingerprint === fingerprint) {
            return;
        }

        cell.className = 'node-speedtest-cell';
        const hasOkResult = speedtest && speedtest.status === 'ok';
        if (!hasOkResult) {
            const muted = document.createElement('span');
            muted.className = 'text-muted';
            muted.textContent = '—';
            cell.replaceChildren(muted);
            cell.dataset.speedtestFingerprint = fingerprint;
            return;
        }

        const wrap = document.createElement('div');
        wrap.className = 'd-flex gap-1 flex-wrap';
        const details = document.createElement('div');
        details.className = 'small text-muted mt-1 d-flex align-items-center flex-wrap gap-1';

        if (speedtest.download_mbit) {
            const dl = document.createElement('span');
            dl.className = 'badge bg-secondary';
            dl.setAttribute('title', 'Download');
            dl.setAttribute('data-bs-toggle', 'tooltip');
            dl.textContent = `↓ ${formatBandwidthMbit(speedtest.download_mbit, 1, 1)}`;
            wrap.appendChild(dl);
        }

        if (speedtest.upload_mbit) {
            const ul = document.createElement('span');
            ul.className = 'badge bg-secondary';
            ul.setAttribute('title', 'Upload');
            ul.setAttribute('data-bs-toggle', 'tooltip');
            ul.textContent = `↑ ${formatBandwidthMbit(speedtest.upload_mbit, 1, 1)}`;
            wrap.appendChild(ul);
        }

        if (speedtest.server) {
            const flag = createFlagImage(speedtest.country_code);
            if (flag) {
                details.appendChild(flag);
                details.appendChild(document.createTextNode(' '));
            }

            const serverSpan = document.createElement('span');
            serverSpan.className = 'text-truncate';
            serverSpan.style.maxWidth = '100%';
            serverSpan.title = speedtest.server;
            serverSpan.textContent = speedtest.server;
            details.appendChild(serverSpan);
        }

        if (!wrap.childElementCount && !details.childElementCount) {
            const muted = document.createElement('span');
            muted.className = 'text-muted';
            muted.textContent = '—';
            cell.replaceChildren(muted);
            cell.dataset.speedtestFingerprint = fingerprint;
            return;
        }

        const container = document.createElement('div');
        container.className = 'd-flex flex-column';
        container.appendChild(wrap);
        if (details.childElementCount) {
            container.appendChild(details);
        }

        cell.replaceChildren(container);
        cell.dataset.speedtestFingerprint = fingerprint;
    }

    /**
     * Create a styled action button for node operations.
     */
    function createActionButton({
        action,
        nodeId,
        nodeName,
        icon,
        ariaLabel,
        title,
        danger = false,
        disabled = false,
        extraData = {},
        className = '',
    }) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = className || `btn btn-sm ${danger ? 'btn-outline-danger' : 'btn-outline-secondary'} node-action-btn`;
        button.dataset.action = action;
        button.dataset.nodeId = String(nodeId || '');
        button.dataset.nodeName = nodeName;
        button.dataset.uiComponent = 'node-actions';
        button.dataset.uiDensity = 'compact';
        button.dataset.uiImportance = danger || action.startsWith('restart') || action.startsWith('delete') ? 'primary' : 'secondary';
        for (const [key, value] of Object.entries(extraData)) {
            if (value != null) button.dataset[key] = String(value);
        }
        button.setAttribute('aria-label', ariaLabel);
        button.setAttribute('data-bs-toggle', 'tooltip');
        button.setAttribute('data-bs-title', title);
        button.disabled = disabled;

        const iconSpan = document.createElement('span');
        iconSpan.className = 'material-icons icon-md';
        iconSpan.setAttribute('aria-hidden', 'true');
        iconSpan.textContent = icon;
        button.appendChild(iconSpan);
        return button;
    }

    function createMenuActionItem({
        action,
        nodeId,
        nodeName,
        icon,
        label,
        danger = false,
        disabled = false,
        extraData = {},
    }) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = `dropdown-item d-flex align-items-center gap-2 node-action-menu-item${danger ? ' text-danger' : ''}`;
        button.dataset.action = action;
        button.dataset.nodeId = String(nodeId || '');
        button.dataset.nodeName = nodeName;
        button.dataset.uiComponent = 'node-actions';
        button.dataset.uiDensity = 'compact';
        button.dataset.uiImportance = danger ? 'primary' : 'secondary';
        for (const [key, value] of Object.entries(extraData)) {
            if (value != null) button.dataset[key] = String(value);
        }
        button.setAttribute('aria-label', label);
        button.disabled = disabled;

        const iconSpan = document.createElement('span');
        iconSpan.className = 'material-icons icon-md';
        iconSpan.setAttribute('aria-hidden', 'true');
        iconSpan.textContent = icon;
        button.appendChild(iconSpan);

        const textSpan = document.createElement('span');
        textSpan.textContent = label;
        button.appendChild(textSpan);

        return button;
    }

    function createNodeActionsDropdown(node) {
        const wrapper = document.createElement('div');
        wrapper.className = 'dropdown node-actions-more d-md-none';
        wrapper.dataset.uiComponent = 'node-actions';
        wrapper.dataset.uiDensity = 'compact';

        const trigger = createActionButton({
            action: 'open-node-actions',
            nodeId: node.id,
            nodeName: node.name,
            icon: 'more_vert',
            ariaLabel: `More actions for ${node.name}`,
            title: 'More Actions',
            className: 'btn btn-sm btn-outline-secondary dropdown-toggle node-action-btn node-actions-more-toggle',
        });
        trigger.removeAttribute('data-action');
        trigger.setAttribute('data-bs-toggle', 'dropdown');
        trigger.setAttribute('aria-expanded', 'false');

        const menu = document.createElement('div');
        menu.className = 'dropdown-menu dropdown-menu-end node-actions-more-menu';

        menu.append(
            createMenuActionItem({
                action: 'regenerate-token',
                nodeId: node.id,
                nodeName: node.name,
                icon: 'vpn_key',
                label: 'Regenerate token',
                ariaLabel: `Regenerate token for ${node.name}`,
            }),
            createMenuActionItem({
                action: 'edit-node',
                nodeId: node.id,
                nodeName: node.name,
                icon: 'edit',
                label: 'Edit node',
                ariaLabel: `Edit ${node.name}`,
                extraData: {
                    nodeFqdn: node.fqdn,
                    nodePort: node.wg_port,
                    nodeShowOnDashboard: node.show_on_dashboard === false ? 'false' : 'true',
                },
            }),
            createMenuActionItem({
                action: 'delete-node',
                nodeId: node.id,
                nodeName: node.name,
                icon: 'delete',
                label: 'Delete node',
                ariaLabel: `Delete ${node.name}`,
                danger: true,
            }),
        );

        wrapper.append(trigger, menu);
        return wrapper;
    }

    /**
     * Create a version display element (code or muted dash).
     */
    function createVersionElement(version) {
        if (version) {
            const code = document.createElement('code');
            code.textContent = version;
            return code;
        }
        const span = document.createElement('span');
        span.className = 'text-muted';
        span.textContent = '—';
        return span;
    }

    /**
     * Create a last seen display element with appropriate styling.
     */
    function createLastSeenElement(text, className) {
        const span = document.createElement('span');
        span.className = className || 'text-muted';
        span.textContent = text || 'Never';
        return span;
    }

    /**
        * Programmatically build a node table row mirroring the Jinja structure,
        * including the hidden mobile-meta cell between Last Seen and Actions.
        * Used when adding new nodes without full page reload.
     */
    function buildNodeRow(node) {
        const tr = document.createElement('tr');
        tr.id = `${NODE_ROW_PREFIX}${node.id}`;
        tr.dataset.lastSpeedtestTs = normalizeSpeedtestTimestamp(node.last_speedtest?.ts || '');
        tr.dataset.nodeStatus = node.status || '';

        // Name cell
        const tdName = document.createElement('td');
        tdName.setAttribute('data-label', 'Name');
        const strong = document.createElement('strong');
        strong.textContent = node.name;
        tdName.appendChild(strong);
        if (node.show_on_dashboard === false) {
            const hiddenBadge = document.createElement('span');
            hiddenBadge.className = 'badge bg-secondary ms-1';
            hiddenBadge.style.fontSize = '0.65rem';
            hiddenBadge.title = 'Hidden from dashboard';
            hiddenBadge.setAttribute('data-bs-toggle', 'tooltip');
            hiddenBadge.textContent = 'Hidden';
            tdName.appendChild(hiddenBadge);
        }

        // FQDN cell with optional geo info
        const tdFqdn = document.createElement('td');
        tdFqdn.setAttribute('data-label', 'FQDN');
        tdFqdn.className = 'node-fqdn-cell';
        const fqdnStack = document.createElement('div');
        fqdnStack.className = 'node-fqdn-stack';
        const fqdnMain = document.createElement('div');
        fqdnMain.className = 'node-fqdn-main';
        const countryCode = normalizeCountryCode(node.geo_country_code);
        if (countryCode) {
            const flag = createFlagImage(countryCode);
            if (flag) fqdnMain.appendChild(flag);
        }
        const fqdnCode = document.createElement('code');
        fqdnCode.textContent = node.fqdn;
        fqdnMain.appendChild(fqdnCode);
        fqdnStack.appendChild(fqdnMain);
        if (node.geo_city || node.geo_as_org) {
            const fqdnMeta = document.createElement('div');
            fqdnMeta.className = 'node-fqdn-meta';
            if (node.geo_city) {
                const citySpan = document.createElement('span');
                citySpan.className = 'node-meta-city';
                citySpan.textContent = node.geo_city;
                fqdnMeta.appendChild(citySpan);
            }
            if (node.geo_city && node.geo_as_org) {
                const separatorSpan = document.createElement('span');
                separatorSpan.className = 'node-meta-separator';
                separatorSpan.setAttribute('aria-hidden', 'true');
                separatorSpan.textContent = '·';
                fqdnMeta.appendChild(separatorSpan);
            }
            if (node.geo_as_org) {
                const provSpan = document.createElement('span');
                provSpan.className = 'node-meta-provider';
                provSpan.textContent = node.geo_as_org;
                fqdnMeta.appendChild(provSpan);
            }
            fqdnStack.appendChild(fqdnMeta);
        }

        const mobileSummary = document.createElement('div');
        mobileSummary.className = 'node-mobile-summary d-none';
        syncNodeMobileSummaryCell(mobileSummary, node);
        fqdnStack.appendChild(mobileSummary);
        tdFqdn.appendChild(fqdnStack);

        // Port cell
        const tdPort = document.createElement('td');
        tdPort.setAttribute('data-label', 'Port');
        const portCode = document.createElement('code');
        portCode.textContent = `${node.wg_port}/udp`;
        tdPort.appendChild(portCode);

        // Status cell
        const tdStatus = document.createElement('td');
        tdStatus.setAttribute('data-label', 'Status');
        tdStatus.setAttribute('aria-live', 'polite');
        tdStatus.setAttribute('aria-atomic', 'true');
        tdStatus.setAttribute('aria-relevant', 'text');
        tdStatus.appendChild(createStatusBadge(node.status || 'pending'));

        // Version cell
        const tdVersion = document.createElement('td');
        tdVersion.setAttribute('data-label', 'Version');
        tdVersion.appendChild(createVersionElement(node.node_version));

        // Peers cell
        const tdPeers = document.createElement('td');
        tdPeers.setAttribute('data-label', 'Peers');
        tdPeers.textContent = node.peer_count ?? 0;

        // Speedtest cell
        const tdSpeedtest = document.createElement('td');
        tdSpeedtest.setAttribute('data-label', 'Speedtest');
        renderSpeedtestCell(tdSpeedtest, node.last_speedtest);

        // Last Seen cell
        const tdLastSeen = document.createElement('td');
        tdLastSeen.setAttribute('data-label', 'Last Seen');
        tdLastSeen.className = 'node-last-seen text-nowrap';
        tdLastSeen.appendChild(createLastSeenElement(node.last_seen_text, node.last_seen_class));

        // Actions cell
        const tdActions = document.createElement('td');
        tdActions.setAttribute('data-label', 'Actions');
        tdActions.className = 'text-end node-actions-cell';
        tdActions.dataset.uiComponent = 'node-actions';
        tdActions.dataset.uiDensity = 'compact';
        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'd-flex gap-1 justify-content-end';
        actionsDiv.dataset.uiComponent = 'node-actions';
        actionsDiv.dataset.uiDensity = 'compact';

        const isOnline = node.status === 'online';

        const restartBtn = createActionButton({
            action: 'restart-node',
            nodeId: node.id,
            nodeName: node.name,
            icon: 'restart_alt',
            ariaLabel: `Restart ${node.name}`,
            title: isOnline ? 'Restart Node' : 'Node is offline',
            disabled: !isOnline,
            extraData: { nodeStatus: node.status || '' },
        });

        const speedtestBtn = createActionButton({
            action: 'run-speedtest',
            nodeId: node.id,
            nodeName: node.name,
            icon: 'speed',
            ariaLabel: `Run speedtest on ${node.name}`,
            title: isOnline ? 'Run Speedtest' : 'Node is offline',
            extraData: { nodeStatus: node.status || '' },
        });
        applySpeedtestButtonState(speedtestBtn, isOnline, activeSpeedtests.get(String(node.id)) || null);

        const moreActions = createNodeActionsDropdown(node);

        const regenBtn = createActionButton({
            action: 'regenerate-token',
            nodeId: node.id,
            nodeName: node.name,
            icon: 'vpn_key',
            ariaLabel: `Regenerate token for ${node.name}`,
            title: 'Regenerate Token',
        });

        const editBtn = createActionButton({
            action: 'edit-node',
            nodeId: node.id,
            nodeName: node.name,
            icon: 'edit',
            ariaLabel: `Edit ${node.name}`,
            title: 'Edit Node',
            extraData: {
                nodeFqdn: node.fqdn,
                nodePort: node.wg_port,
                nodeShowOnDashboard: node.show_on_dashboard === false ? 'false' : 'true',
            },
        });

        const deleteBtn = createActionButton({
            action: 'delete-node',
            nodeId: node.id,
            nodeName: node.name,
            icon: 'delete',
            ariaLabel: `Delete ${node.name}`,
            title: 'Delete Node',
            danger: true,
            className: 'btn btn-sm btn-outline-danger node-action-btn node-action-secondary d-none d-md-inline-flex',
        });

        actionsDiv.append(restartBtn, speedtestBtn, moreActions, regenBtn, editBtn, deleteBtn);
        tdActions.appendChild(actionsDiv);

        tr.append(tdName, tdFqdn, tdPort, tdStatus, tdVersion, tdPeers, tdSpeedtest, tdLastSeen, tdActions);
        return tr;
    }

    function rowNeedsIdentityRefresh(row, node) {
        if (!row || !node) return false;

        const currentName = row.querySelector('td[data-label="Name"] strong')?.textContent || '';
        const currentFqdn = row.querySelector('.node-fqdn-cell code')?.textContent || '';
        const currentPort = row.querySelector('td[data-label="Port"] code')?.textContent || '';
        const editButton = row.querySelector('button[data-action="edit-node"]');
        const dashboardHidden = row.querySelector('td[data-label="Name"] .badge.bg-secondary') !== null;

        return (
            currentName !== String(node.name || '')
            || currentFqdn !== String(node.fqdn || '')
            || currentPort !== `${node.wg_port}/udp`
            || dashboardHidden !== (node.show_on_dashboard === false)
            || (editButton?.dataset.nodeName || '') !== String(node.name || '')
            || (editButton?.dataset.nodeFqdn || '') !== String(node.fqdn || '')
            || (editButton?.dataset.nodePort || '') !== String(node.wg_port || '')
            || (editButton?.dataset.nodeShowOnDashboard || 'true') !== (node.show_on_dashboard === false ? 'false' : 'true')
        );
    }

    function rebuildNodeRow(row, node) {
        disposeTooltips(row);
        const freshRow = buildNodeRow(node);
        row.replaceWith(freshRow);
        initTooltips(freshRow);
        return freshRow;
    }

    /**
        * Return the nodes tbody element, creating the full table structure if needed.
        * Uses a cached reference and falls back to getElementById if the cache is stale.
        * Returns null only if the .card-body container is missing from the DOM.
     */
    function ensureTableExists() {
        // Fast path: cached reference is valid
        if (nodesTableBody) return nodesTableBody;

        // Slow path: cache was cleared (e.g. by toggleEmptyState when last node was deleted)
        // Try to find an existing tbody before building a new table structure.
        const existing = document.getElementById('nodesTableBody');
        if (existing) {
            nodesTableBody = existing;
            return existing;
        }

        // Remove empty state and create table structure
        const cardBody = document.querySelector('.card-body');
        if (!cardBody) return null;

        const emptyState = cardBody.querySelector('.nodes-empty-state');
        if (emptyState) emptyState.remove();

        const tableResponsive = document.createElement('div');
        tableResponsive.className = 'table-responsive';

        const table = document.createElement('table');
        table.className = 'table table-hover mb-0 nodes-table';

        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        const headerConfig = [
            { text: 'Name' },
            { text: 'FQDN / IP' },
            { text: 'Port', dataLabel: 'Port' },
            { text: 'Status' },
            { text: 'Version' },
            { text: 'Peers' },
            { text: 'Speedtest' },
            { text: 'Last Seen' },
            { text: '', className: 'text-end', ariaHidden: 'true' },
        ];
        for (const header of headerConfig) {
            const th = document.createElement('th');
            th.textContent = header.text;
            if (header.dataLabel) th.setAttribute('data-label', header.dataLabel);
            if (header.className) th.className = header.className;
            if (header.ariaHidden) th.setAttribute('aria-hidden', header.ariaHidden);
            headerRow.appendChild(th);
        }
        thead.appendChild(headerRow);

        const tbody = document.createElement('tbody');
        tbody.id = 'nodesTableBody';

        table.append(thead, tbody);
        tableResponsive.appendChild(table);
        cardBody.appendChild(tableResponsive);
        nodesTableBody = tbody;

        return tbody;
    }

    function toggleEmptyState(hasNodes) {
        const cardBody = document.querySelector('.card-body');
        if (!cardBody) return;

        const tableResponsive = cardBody.querySelector('.table-responsive');
        const emptyState = cardBody.querySelector('.nodes-empty-state');

        if (hasNodes) {
            if (emptyState) emptyState.remove();
            if (!tableResponsive) {
                ensureTableExists();
            }
            return;
        }

        if (tableResponsive) {
            tableResponsive.remove();
            nodesTableBody = null;
        }
        if (!emptyState) {
            const empty = document.createElement('div');
            empty.className = 'nodes-empty-state text-center py-5';
            const icon = document.createElement('span');
            icon.className = 'material-icons text-muted mb-3 nodes-empty-icon';
            icon.setAttribute('aria-hidden', 'true');
            icon.textContent = 'hub';

            const heading = document.createElement('h3');
            heading.className = 'h5 mb-2';
            heading.textContent = 'No remote nodes configured yet';

            const paragraph = document.createElement('p');
            paragraph.className = 'text-muted mb-0';
            paragraph.append('Click ');
            const strong = document.createElement('strong');
            strong.textContent = 'Add Node';
            paragraph.append(strong, ' to register a remote VPN server.');

            empty.append(icon, heading, paragraph);
            cardBody.appendChild(empty);
        }
    }

    function removeStaleRows(nodeIds) {
        if (!nodesTableBody) return;
        const validIds = new Set((nodeIds || []).map((id) => String(id || '')));
        for (const row of nodesTableBody.querySelectorAll(`tr[id^="${NODE_ROW_PREFIX}"]`)) {
            const rowId = row.id.slice(NODE_ROW_PREFIX.length);
            if (!validIds.has(rowId)) {
                disposeTooltips(row);
                row.remove();
            }
        }
    }

    /**
     * Copy text content from an element to clipboard.
     * Trims whitespace — enrollment tokens should not have surrounding whitespace.
     */
    async function copyTextFromElement(elementId) {
        const element = document.getElementById(elementId);
        const text = element?.textContent?.trim() || '';
        if (!text) {
            wbToast('No token available to copy.', 'warning');
            return;
        }

        try {
            await navigator.clipboard.writeText(text);
            wbToast('Token copied to clipboard.', 'success');
        } catch (error) {
            wbToast('Failed to copy token: ' + error.message, 'danger');
        }
    }

    // ========================================================================
    // MODAL ACTIONS
    // ========================================================================
    function openEditNodeModal(id, name, fqdn, port, showOnDashboard) {
        if (!editNodeModalEl) return;
        document.getElementById('editNodeId').value = id;
        document.getElementById('editNodeName').value = name;
        document.getElementById('editNodeFqdn').value = fqdn;
        document.getElementById('editNodePort').value = port;
        const toggle = document.getElementById('editNodeShowOnDashboard');
        if (toggle) toggle.checked = showOnDashboard !== false && showOnDashboard !== 'false';
        bootstrap.Modal.getOrCreateInstance(editNodeModalEl).show();
    }

    async function submitAddNode() {
        // Guard against double-submit (Enter key can fire before button disables)
        if (!addNodeSubmitBtn || addNodeSubmitBtn.disabled) return;

        const name = nodeNameInput?.value.trim();
        const fqdn = addNodeFqdnInput?.value.trim();
        const port = getValidatedPort('nodePort');

        if (!name || !fqdn) {
            await wbAlert('Name and FQDN are required.', 'warning');
            return;
        }
        if (!validateNodeAddressField(addNodeFqdnInput)) {
            addNodeFqdnInput.classList.add('is-invalid');
            addNodeFqdnInput.focus();
            addNodeFqdnInput.reportValidity();
            return;
        }
        if (port === null) {
            return;
        }

        setButtonLoading(addNodeSubmitBtn, true, 'Creating...', 'Create Node');

        try {
            const data = await api('POST', '/api/nodes', { name, fqdn, wg_port: port });

            // Show token step and set flag
            nodeCreatedFlag = true;
            wbToast('Node created successfully', 'success');
            document.getElementById('addNodeStep1')?.classList.add('wb-step-hidden');
            document.getElementById('addNodeStep2')?.classList.remove('wb-step-hidden');
            if (enrollmentTokenDisplay) {
                enrollmentTokenDisplay.textContent = data.enrollment_token;
            }
            if (addNodeSubmitBtn) {
                addNodeSubmitBtn.style.display = 'none';
            }

        } catch (err) {
            await wbAlert(err.message || 'Failed to create node', 'danger');
            setButtonLoading(addNodeSubmitBtn, false);
        }
    }

    async function submitEditNode() {
        const id = document.getElementById('editNodeId')?.value;
        const name = document.getElementById('editNodeName')?.value.trim();
        const fqdn = editNodeFqdnInput?.value.trim();
        const port = getValidatedPort('editNodePort');
        const showOnDashboard = document.getElementById('editNodeShowOnDashboard')?.checked ?? true;

        if (!name || !fqdn) {
            await wbAlert('Name and FQDN are required.', 'warning');
            return;
        }
        if (!validateNodeAddressField(editNodeFqdnInput)) {
            editNodeFqdnInput.classList.add('is-invalid');
            editNodeFqdnInput.focus();
            editNodeFqdnInput.reportValidity();
            return;
        }
        if (port === null) {
            return;
        }

        try {
            await api('PATCH', `/api/nodes/${id}`, { name, fqdn, wg_port: port, show_on_dashboard: showOnDashboard });
            refreshNodes();
            bootstrap.Modal.getInstance(editNodeModalEl)?.hide();
        } catch (err) {
            await wbAlert(err.message, 'danger');
        }
    }

    async function deleteNode(id, name) {
        if (!await wbConfirm(`Delete node "${name}"? Assigned peers will be unassigned.`, 'danger')) return;

        try {
            const data = await api('DELETE', `/api/nodes/${id}`);
            wbToast(data.message || `Node "${name}" deleted`, 'success');
            const row = document.getElementById(`${NODE_ROW_PREFIX}${id}`);
            if (row) {
                disposeTooltips(row);
                row.remove();
            }

            const remainingRows = nodesTableBody?.querySelectorAll(`tr[id^="${NODE_ROW_PREFIX}"]`).length || 0;
            if (remainingRows === 0) {
                toggleEmptyState(false);
            }
        } catch (err) {
            await wbAlert(err.message, 'danger');
        }
    }

    async function regenerateToken(id, name) {
        if (!await wbConfirm(`Regenerate enrollment token for "${name}"? The node must re-enroll.`, 'warning')) return;

        try {
            const data = await api('POST', `/api/nodes/${id}/token`);
            if (tokenModalEl && regenTokenDisplay) {
                regenTokenDisplay.textContent = data.enrollment_token;
                bootstrap.Modal.getOrCreateInstance(tokenModalEl).show();
            }
        } catch (err) {
            await wbAlert(err.message, 'danger');
        }
    }

    async function restartNode(id, name) {
        const nodeId = String(id || '');
        if (!nodeId) return;

        if (!await wbConfirm(`Restart node "${name}"? The node will disconnect briefly and reconnect.`, 'warning')) return;

        // Find the row and button for immediate UI feedback
        const row = document.getElementById(`${NODE_ROW_PREFIX}${nodeId}`);
        const restartBtn = row?.querySelector('button[data-action="restart-node"]');

        try {
            await api('POST', `/api/nodes/${id}/restart`);

            // Immediately update badge to "Restarting"
            const statusCell = row?.querySelector('td[data-label="Status"]');
            if (statusCell) {
                statusCell.replaceChildren(createStatusBadge('restarting'));
                statusCell.dataset.status = 'restarting';
            }

            // Disable the restart button while restarting
            if (restartBtn) {
                restartBtn.disabled = true;
            }

            // Track this node as restarting so polling doesn't overwrite the badge
            // Clear any existing timeout to prevent stale deletes on repeated restarts
            const existing = restartingNodes.get(nodeId);
            if (existing?.timeout) clearTimeout(existing.timeout);
            const timeout = setTimeout(() => restartingNodes.delete(nodeId), 120000);
            restartingNodes.set(nodeId, { phase: 'sent', timeout });

            wbToast(`Node restart initiated. "${name}" will reconnect shortly.`, 'success');
        } catch (err) {
            // Show as toast instead of alert to avoid blocking reconnect modal
            wbToast(err.message || `Failed to restart "${name}"`, 'danger');
        }
    }

    async function runNodeSpeedtest(id, name) {
        const nodeId = String(id || '');
        if (!nodeId || activeSpeedtests.has(nodeId)) return;

        const row = document.getElementById(`${NODE_ROW_PREFIX}${nodeId}`);
        const baselineTs = normalizeSpeedtestTimestamp(row?.dataset.lastSpeedtestTs || '');

        setActiveSpeedtest(nodeId, {
            nodeName: name,
            baselineTs,
            startedAt: Date.now(),
            phase: 'starting',
        });
        syncSpeedtestButtonForRow(row, row?.dataset.nodeStatus || 'online');

        try {
            await api('POST', `/api/nodes/${nodeId}/speedtest`);
            setActiveSpeedtest(nodeId, {
                nodeName: name,
                baselineTs,
                startedAt: Date.now(),
                phase: 'running',
            });
            ensureSpeedtestStatusPolling();
            void checkActiveSpeedtests();
            wbToast(`Speedtest triggered on "${name}". Results will appear on the Speedtest page.`, 'success');
        } catch (err) {
            clearActiveSpeedtest(nodeId);
            syncSpeedtestButtonForRow(row, row?.dataset.nodeStatus || 'online');
            wbToast(err.message || `Failed to trigger speedtest on "${name}"`, 'danger');
        }
    }

    // ========================================================================
    // POLLING LOGIC
    // ========================================================================
    async function refreshNodes() {
        const seq = ++_pollSeq; // Stamp this request to detect stale responses
        pollController?.abort();
        pollController = new AbortController();

        try {
            // api() forwards opts.signal to fetch(); abort + _pollSeq together prevent stale updates.
            const nodes = await api('GET', '/api/nodes', null, { signal: pollController.signal });

            // Ignore stale response if a newer request was issued
            if (seq !== _pollSeq) return;

            // Show empty state or ensure table exists based on result
            toggleEmptyState(nodes.length > 0);

            // If no nodes, we're done (empty state is shown)
            if (nodes.length === 0) return;

            // Ensure table exists for rendering nodes
            const tbody = ensureTableExists();
            if (!tbody) return;

            removeStaleRows(nodes.map((node) => String(node.id || '')));

            for (const node of nodes) {
                const nodeId = String(node.id || '');
                let row = document.getElementById(`${NODE_ROW_PREFIX}${nodeId}`);
                const latestSpeedtestTs = normalizeSpeedtestTimestamp(node.last_speedtest?.ts || '');

                // Handle NEW nodes: build row and insert into table
                if (!row) {
                    row = buildNodeRow(node);
                    tbody.appendChild(row);
                    initTooltips(row);
                    continue; // Skip update logic for newly created row
                }

                if (rowNeedsIdentityRefresh(row, node)) {
                    row = rebuildNodeRow(row, node);
                }

                // Update status badge (secure DOM manipulation)
                syncNodeStatusCell(row, node);

                // Update peer count
                const peersCell = row.querySelector('td[data-label="Peers"]');
                if (peersCell) {
                    const newCount = node.peer_count ?? '—';
                    if (peersCell.textContent !== String(newCount)) {
                        peersCell.textContent = newCount;
                    }
                }

                // Update version (secure DOM manipulation)
                const versionCell = row.querySelector('td[data-label="Version"]');
                if (versionCell) {
                    const currentVersion = versionCell.querySelector('code')?.textContent || '';
                    const newVersion = node.node_version || '';

                    if (currentVersion !== newVersion) {
                        versionCell.replaceChildren(createVersionElement(node.node_version));
                    }
                }

                // Update last seen (secure DOM manipulation)
                const lastSeenCell = row.querySelector('td[data-label="Last Seen"]');
                if (lastSeenCell) {
                    const currentSpan = lastSeenCell.querySelector('span');
                    const currentText = currentSpan?.textContent || '';
                    const newText = node.last_seen_text || 'Never';

                    if (currentText !== newText) {
                        lastSeenCell.replaceChildren(createLastSeenElement(node.last_seen_text, node.last_seen_class));
                    }
                }

                initNodeActionDropdowns(row);

                syncNodeMobileSummaryCell(row.querySelector('.node-mobile-summary'), node);

                // Update restart button state based on node status
                const restartBtn = row.querySelector('button[data-action="restart-node"]');
                if (restartBtn) {
                    const isOnline = node.status === 'online';
                    restartBtn.disabled = !isOnline;
                    restartBtn.dataset.nodeStatus = node.status || ''; // Keep in sync
                    const title = isOnline ? 'Restart Node' : 'Node is offline';
                    updateTooltipTitle(restartBtn, title);
                }

                const speedtestBtn = row.querySelector('button[data-action="run-speedtest"]');
                if (speedtestBtn) {
                    speedtestBtn.dataset.nodeStatus = node.status || '';
                    syncSpeedtestButtonForRow(row, node.status || '');
                }

                row.dataset.lastSpeedtestTs = latestSpeedtestTs;
                renderSpeedtestCell(row.querySelector('td[data-label="Speedtest"]'), node.last_speedtest);
            }

            // Reset failure count on success
            if (pollFailureCount >= MAX_POLL_FAILURES) {
                pollFailureCount = 0;
                startPolling(); // Restore normal interval
            } else {
                pollFailureCount = 0;
            }
        } catch (err) {
            if (err instanceof DOMException && err.name === 'AbortError') return;
            // Restart with backoff interval at the threshold only; subsequent failures
            // keep the existing backoff timer without disrupting it.
            const wasUnderThreshold = pollFailureCount < MAX_POLL_FAILURES;
            pollFailureCount++;
            if (wasUnderThreshold && pollFailureCount >= MAX_POLL_FAILURES) {
                startPolling(); // Transition to backoff interval
            }
        }
    }

    function startPolling() {
        stopPolling();

        // Use backoff if too many failures
        const interval = pollFailureCount >= MAX_POLL_FAILURES ? POLL_BACKOFF_MS : POLL_INTERVAL_MS;
        pollTimer = setInterval(refreshNodes, interval);
    }

    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    // ========================================================================
    // EVENT LISTENERS
    // ========================================================================
    addNodeForm?.addEventListener('submit', (event) => {
        event.preventDefault();
        submitAddNode().catch((err) => {
            console.error('[nodes] submitAddNode threw unexpectedly:', err);
        });
    });

    editNodeForm?.addEventListener('submit', (event) => {
        event.preventDefault();
        submitEditNode().catch((err) => {
            console.error('[nodes] submitEditNode threw unexpectedly:', err);
        });
    });

    document.getElementById('copyEnrollmentTokenBtn')?.addEventListener('click', () => {
        copyTextFromElement('enrollmentTokenDisplay').catch((err) => {
            console.error('[nodes] copyTextFromElement threw unexpectedly:', err);
        });
    });

    document.getElementById('copyRegeneratedTokenBtn')?.addEventListener('click', () => {
        copyTextFromElement('regenTokenDisplay').catch((err) => {
            console.error('[nodes] copyTextFromElement threw unexpectedly:', err);
        });
    });

    for (const input of [addNodeFqdnInput, editNodeFqdnInput]) {
        if (!input) continue;
        input.addEventListener('input', () => {
            const hasValue = input.value.trim().length > 0;
            if (!hasValue) {
                resetNodeAddressFieldValidation(input);
                return;
            }
            validateNodeAddressField(input);
        });
        input.addEventListener('blur', () => {
            validateNodeAddressField(input);
        });
    }

    async function handleNodeActionClick(event) {
        const button = event.target.closest('button[data-action]');
        if (!button || button.disabled) return;
        if (!button.closest('#nodesTableBody')) return;

        const action = button.dataset.action;
        const nodeId = button.dataset.nodeId || '';
        const nodeName = button.dataset.nodeName || 'node';

        // Use switch to avoid allocating closures on every click
        switch (action) {
            case 'edit-node':
                openEditNodeModal(
                    nodeId,
                    nodeName,
                    button.dataset.nodeFqdn || '',
                    Number(button.dataset.nodePort) || 51820,
                    button.dataset.nodeShowOnDashboard,
                );
                break;
            case 'delete-node':
                await deleteNode(nodeId, nodeName);
                break;
            case 'regenerate-token':
                await regenerateToken(nodeId, nodeName);
                break;
            case 'restart-node':
                await restartNode(nodeId, nodeName);
                break;
            case 'run-speedtest':
                await runNodeSpeedtest(nodeId, nodeName);
                break;
        }
    }

    document.addEventListener('click', (event) => {
        handleNodeActionClick(event).catch((err) => {
            console.error('[nodes] Unhandled error in action handler:', err);
        });
    });

    // Reset modal state when closed (with explicit state check)
    addNodeModalEl?.addEventListener('hidden.bs.modal', function () {
        document.getElementById('addNodeStep1')?.classList.remove('wb-step-hidden');
        document.getElementById('addNodeStep2')?.classList.add('wb-step-hidden');
        if (nodeNameInput) nodeNameInput.value = '';
        if (addNodeFqdnInput) addNodeFqdnInput.value = '';
        resetNodeAddressFieldValidation(addNodeFqdnInput);
        const nodePortInput = document.getElementById('nodePort');
        if (nodePortInput) nodePortInput.value = nodePortInput.dataset.default || '51820';
        setButtonLoading(addNodeSubmitBtn, false);
        if (addNodeSubmitBtn) addNodeSubmitBtn.style.display = '';

        // Refresh datatable instead of full reload if a node was created
        if (nodeCreatedFlag) {
            nodeCreatedFlag = false;
            refreshNodes();
        }
    });

    // Focus first input when modal opens
    addNodeModalEl?.addEventListener('shown.bs.modal', () => {
        nodeNameInput?.focus();
    });

    editNodeModalEl?.addEventListener('shown.bs.modal', () => {
        document.getElementById('editNodeName')?.focus();
    });

    editNodeModalEl?.addEventListener('hidden.bs.modal', () => {
        resetNodeAddressFieldValidation(editNodeFqdnInput);
    });

    // Pause polling when tab is hidden
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            stopPolling();
            stopSpeedtestStatusPolling();
        } else {
            refreshNodes(); // Refresh immediately when tab becomes visible
            startPolling();
            ensureSpeedtestStatusPolling();
            void checkActiveSpeedtests();
        }
    });

    // Cleanup on page unload (navigation, bfcache eviction)
    window.addEventListener('pagehide', () => {
        stopPolling();
        stopSpeedtestStatusPolling();
        pollController?.abort();
        clearRestartingNodeTimeouts();
    });

    // ========================================================================
    // INITIALIZATION
    // ========================================================================
    loadActiveSpeedtests();
    syncAllSpeedtestButtons();
    initTooltips();
    initNodeActionDropdowns();
    initFlagImages();
    void refreshNodes();
    startPolling();
    ensureSpeedtestStatusPolling();
    void checkActiveSpeedtests();
})();
