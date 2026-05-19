//
// app/static/js/peers.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

'use strict';

const peersApp = document.getElementById('peers-app');

if (!peersApp) {
    console.warn('peers.js loaded without #peers-app context');
} else {
    const canManagePeers = peersApp.dataset.canManagePeers === '1';
    const flagIconBaseUrl = peersApp.dataset.flagIconBaseUrl || 'https://cdn.jsdelivr.net/npm/flag-icons@7.3.2/flags/4x3';

    const ALLOWED_IPS_PRESETS = {
        full: '0.0.0.0/0, ::/0',
        split: '0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1',
    };

    const ALLOWED_IPS_HINTS = {
        full: 'All IPv4/IPv6 traffic is routed through the VPN',
        split: 'VPN traffic routed, local network remains directly accessible',
        custom: 'Enter custom CIDR ranges below',
    };

    const PEER_STATS_INTERVAL_MS = 30000;
    const PEER_STATS_MAX_BACKOFF_MS = 300000;
    const MAX_LAST_SEEN_CACHE = 500;
    const QR_FETCH_TIMEOUT_MS = 15000;
    const DOWNLOAD_FETCH_TIMEOUT_MS = 15000;
    const BLOB_REVOKE_DELAY_MS = 10000;
    const CONNECTED_THRESHOLD_SEC = 180;
    const HIDE_NODES_KEY = 'wb_peers_hide_nodes';

    const state = {
        addPeerModalAbort: null,
        blocklistRegistry: [],
        globalDnsLoggingEnabled: { add: true, edit: true },
        lastSeenCache: new Map(),
        peerCards: [],
        peerRows: [],
        peerSeenCache: new Map(),
        peerStatsAbortController: null,
        peerStatsBackoffMs: PEER_STATS_INTERVAL_MS,
        peerStatsRequestSeq: 0,
        peerStatsTimer: null,
        qrAbortController: null,
        qrBlobUrl: null,
        qrRequestSeq: 0,
        searchDebounceTimer: null,
        visibilityTimeout: null,
    };

    const qrModalEl = document.getElementById('qrModal');
    const qrModal = qrModalEl ? new bootstrap.Modal(qrModalEl) : null;
    const searchInput = document.getElementById('peers-search-input');
    const searchClearBtn = document.getElementById('peers-search-clear');
    const visibleCountEl = document.getElementById('peers-visible-count');
    const noResultsEl = document.getElementById('peers-no-results');
    const peersTableEl = document.getElementById('peers-table');
    const peersTableWrapperEl = document.getElementById('peers-table-wrapper');
    const peerCardListEl = document.getElementById('peer-card-list');
    const peersEmptyStateEl = document.getElementById('peers-empty-state');
    const hideNodesCheckbox = document.getElementById('peers-hide-nodes');
    const rootEl = document.documentElement;

    function safeErrorMessage(error, fallback = 'Request failed') {
        if (!error) return fallback;
        const msg = (typeof error?.message === 'string' && error.message) ? error.message : String(error);
        return msg.replace(/[\r\n\t]/g, ' ').trim() || fallback;
    }

    function reloadSoon(delay = 600) {
        setTimeout(() => window.location.reload(), delay);
    }

    function reportAsyncError(context, error) {
        console.error(`peers.js: ${context}`, error);
    }

    function queuePeerStatsReload(context) {
        loadPeerStats().catch((error) => reportAsyncError(context, error));
    }

    function revokeQrBlobUrl() {
        if (state.qrBlobUrl) {
            URL.revokeObjectURL(state.qrBlobUrl);
            state.qrBlobUrl = null;
        }
    }

    function disposeTooltips(root = document) {
        root.querySelectorAll?.('[data-bs-toggle="tooltip"]').forEach((el) => {
            const instance = bootstrap.Tooltip.getInstance(el);
            if (instance) instance.dispose();
            delete el.dataset.tooltipInitialized;
        });
    }

    function initTooltips(root = document) {
        root.querySelectorAll?.('[data-bs-toggle="tooltip"]').forEach((el) => {
            if (el.dataset.tooltipInitialized || !el.isConnected || !el.getAttribute) return;
            const existingInstance = bootstrap.Tooltip.getInstance(el);
            if (existingInstance) existingInstance.dispose();
            try {
                new bootstrap.Tooltip(el, {
                    container: document.body,
                    trigger: 'hover focus',
                });
                el.dataset.tooltipInitialized = 'true';
            } catch (err) {
                console.error('Failed to initialize tooltip:', err, el);
            }
        });
    }

    function appendSafeText(parent, tagName, text, className = '') {
        const element = document.createElement(tagName);
        if (className) {
            element.className = className;
        }
        element.textContent = text;
        parent.appendChild(element);
        return element;
    }

    function extractPeerIps(peerAddress) {
        let ipv4 = null;
        let ipv6 = null;
        if (!peerAddress) return { ipv4, ipv6 };
        for (const part of String(peerAddress).split(',')) {
            const addr = part.trim().split('/')[0];
            if (!addr) continue;
            if (addr.includes(':')) {
                if (!ipv6) ipv6 = addr;
            } else if (!ipv4) {
                ipv4 = addr;
            }
        }
        return { ipv4, ipv6 };
    }

    function getRoutingLabel(peer) {
        const mode = peer?.allowed_ips_mode || detectAllowedIpsMode(peer?.allowed_ips || '');
        return { full: 'Full Tunnel', split: 'Split Tunnel' }[mode] || 'Custom';
    }

    function lookupNodeName(nodeId) {
        const candidate = String(nodeId || '').trim();
        if (!candidate) return '';

        const selects = [
            document.getElementById('peer-node'),
            document.getElementById('edit-peer-node'),
        ];
        for (const select of selects) {
            const option = Array.from(select?.options || []).find((entry) => entry.value === candidate);
            const label = option?.textContent?.trim() || '';
            if (label) return label;
        }
        return '';
    }

    async function hydratePeerRowData(peer) {
        if (!peer || !Number.isFinite(Number(peer.id))) return peer;

        const basePeer = {
            ...peer,
            node_name: peer.node_name || lookupNodeName(peer.node_id),
        };

        try {
            const response = await api('GET', `/api/wireguard/peers/${peer.id}`);
            const enrichedPeer = response?.data && typeof response.data === 'object'
                ? response.data
                : response;
            if (!enrichedPeer) return basePeer;
            return {
                ...basePeer,
                ...enrichedPeer,
                node_name: basePeer.node_name || enrichedPeer.node_name || lookupNodeName(basePeer.node_id || enrichedPeer.node_id),
            };
        } catch (_) {
            return basePeer;
        }
    }

    function computeSearchText(container) {
        if (!container) return '';

        const selectors = container.classList.contains('peer-card')
            ? [
                '.peer-card-title',
                '.peer-card-subline',
                '.peer-card-routing',
                '.peer-card-addresses',
                '.peer-card-status',
            ]
            : [
                '.peer-name-cell',
                '.peer-vpn-address',
                '.peer-routing',
                '.peer-interface',
                '.peer-status-cell',
                '.peer-client-ip',
            ];

        return selectors
            .map((selector) => container.querySelector(selector)?.textContent || '')
            .join(' ')
            .toLowerCase();
    }

    function updateRowSearchText(container) {
        if (!container) return;
        container.dataset.searchText = computeSearchText(container);
    }

    function refreshPeerRows() {
        state.peerRows = Array.from(document.querySelectorAll('#peers-table tr[data-peer-id]'));
        state.peerCards = Array.from(document.querySelectorAll('#peer-card-list .peer-card[data-peer-id]'));
        state.peerRows.forEach(updateRowSearchText);
        state.peerCards.forEach(updateRowSearchText);
    }

    function createPeerActionButton(peerId, action, label, icon, btnClass, options = {}) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = `btn btn-sm ${btnClass}`;
        btn.dataset.action = action;
        btn.dataset.peerId = String(peerId);
        btn.dataset.uiComponent = options.uiComponent || 'peer-actions';
        btn.dataset.uiDensity = options.uiDensity || 'compact';
        btn.dataset.uiImportance = options.uiImportance || (action.startsWith('delete') ? 'primary' : 'secondary');
        btn.setAttribute('aria-label', label);
        btn.setAttribute('data-bs-toggle', 'tooltip');
        btn.setAttribute('data-bs-title', label);
        if (options.disabled) {
            btn.disabled = true;
        }

        const iconEl = document.createElement('span');
        iconEl.className = 'material-icons';
        iconEl.setAttribute('aria-hidden', 'true');
        iconEl.textContent = icon;
        btn.appendChild(iconEl);
        return btn;
    }

    function createPeerMenuButton(peerId, action, label, icon, danger = false) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = `dropdown-item d-flex align-items-center gap-2${danger ? ' text-danger' : ''}`;
        button.dataset.action = action;
        button.dataset.peerId = String(peerId);
        button.dataset.uiComponent = 'peer-actions';
        button.dataset.uiDensity = 'compact';
        button.dataset.uiImportance = danger ? 'primary' : 'secondary';
        button.setAttribute('aria-label', label);

        const iconEl = document.createElement('span');
        iconEl.className = 'material-icons';
        iconEl.setAttribute('aria-hidden', 'true');
        iconEl.textContent = icon;
        button.appendChild(iconEl);

        const labelEl = document.createElement('span');
        labelEl.textContent = label;
        button.appendChild(labelEl);

        return button;
    }

    function createPeerMoreActions(peer) {
        const wrapper = document.createElement('div');
        wrapper.className = 'dropdown peer-card-more-actions';
        wrapper.dataset.uiComponent = 'peer-actions';
        wrapper.dataset.uiDensity = 'compact';

        const toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.className = 'btn btn-sm btn-outline-secondary peer-card-action-btn';
        toggle.dataset.uiComponent = 'peer-actions';
        toggle.dataset.uiDensity = 'compact';
        toggle.dataset.uiImportance = 'tertiary';
        toggle.setAttribute('data-bs-toggle', 'dropdown');
        toggle.setAttribute('aria-expanded', 'false');
        toggle.setAttribute('aria-label', `More actions for ${peer.name || 'peer'}`);

        const iconEl = document.createElement('span');
        iconEl.className = 'material-icons';
        iconEl.setAttribute('aria-hidden', 'true');
        iconEl.textContent = 'more_vert';
        toggle.appendChild(iconEl);

        const menu = document.createElement('div');
        menu.className = 'dropdown-menu dropdown-menu-end';
        menu.append(
            createPeerMenuButton(peer.id, 'edit-peer', 'Edit', 'edit'),
            createPeerMenuButton(peer.id, 'delete-peer', 'Delete', 'delete', true),
        );

        wrapper.append(toggle, menu);
        return wrapper;
    }

    function createCountryFlagElement(countryCode) {
        const code = String(countryCode || '').trim().toLowerCase();
        if (!/^[a-z]{2}$/.test(code)) return null;

        const img = document.createElement('img');
        img.className = 'peer-country-flag';
        img.alt = `${code.toUpperCase()} flag`;
        img.decoding = 'async';
        img.src = `${flagIconBaseUrl}/${code}.svg`;
        img.dataset.countryCode = code;
        img.addEventListener('error', () => img.remove(), { once: true });
        return img;
    }

    function ensureClientIpCellStructure(cell) {
        let stack = cell.querySelector('.peer-client-ip-stack');
        let main = stack?.querySelector('.peer-client-ip-main');
        let code = main?.querySelector('code.ipv6');
        let meta = stack?.querySelector('.peer-client-ip-meta');
        let city = meta?.querySelector('.peer-meta-city');
        let provider = meta?.querySelector('.peer-meta-provider');

        if (stack && main && code && meta && city && provider) {
            return { stack, main, code, meta, city, provider };
        }

        cell.textContent = '';
        stack = document.createElement('div');
        stack.className = 'peer-client-ip-stack';

        main = document.createElement('div');
        main.className = 'peer-client-ip-main';
        code = document.createElement('code');
        code.className = 'ipv6';
        main.appendChild(code);

        meta = document.createElement('div');
        meta.className = 'peer-client-ip-meta d-none';
        city = document.createElement('span');
        city.className = 'peer-meta-city';
        provider = document.createElement('span');
        provider.className = 'peer-meta-provider text-muted';
        meta.append(city, provider);

        stack.append(main, meta);
        cell.appendChild(stack);
        return { stack, main, code, meta, city, provider };
    }

    function updateClientIpCell(cell, endpointIp, country, city, asOrg) {
        const normalizedIp = String(endpointIp || '').trim();
        const normalizedCity = String(city || '').trim();
        const normalizedAsOrg = String(asOrg || '').trim();

        if (!normalizedIp) {
            cell.classList.add('peer-client-ip--empty');
            if (cell.dataset.emptyRendered !== '1') {
                cell.textContent = '';
                const dashSpan = document.createElement('span');
                dashSpan.className = 'text-muted';
                dashSpan.textContent = '—';
                cell.appendChild(dashSpan);
                cell.dataset.emptyRendered = '1';
            }
            return;
        }

        cell.classList.remove('peer-client-ip--empty');
        delete cell.dataset.emptyRendered;

        const { main, code, meta, city: cityEl, provider: providerEl } = ensureClientIpCellStructure(cell);
        const formattedIp = normalizedIp.replace(/:/g, ':\u200b').replace(/\//g, '/\u200b');

        if (code.textContent !== formattedIp) {
            code.textContent = formattedIp;
        }

        const flagCode = String(country || '').trim().toLowerCase();
        const currentFlag = main.querySelector('img.peer-country-flag');
        if (/^[a-z]{2}$/.test(flagCode)) {
            if (!currentFlag || currentFlag.dataset.countryCode !== flagCode) {
                currentFlag?.remove();
                const nextFlag = createCountryFlagElement(flagCode);
                if (nextFlag) main.prepend(nextFlag);
            }
        } else {
            currentFlag?.remove();
        }

        if (normalizedCity || normalizedAsOrg) {
            meta.classList.remove('d-none');
            if (cityEl.textContent !== normalizedCity) {
                cityEl.textContent = normalizedCity;
            }
            const providerText = normalizedAsOrg ? `(${normalizedAsOrg})` : '';
            if (providerEl.textContent !== providerText) {
                providerEl.textContent = providerText;
            }
            cityEl.classList.toggle('d-none', !normalizedCity);
            providerEl.classList.toggle('d-none', !providerText);
        } else {
            cityEl.textContent = '';
            providerEl.textContent = '';
            meta.classList.add('d-none');
        }
    }

    function updateLastSeenDisplay(row, epochSeconds) {
        const lastSeenCell = row.querySelector('.peer-last-seen');
        const connectionBadges = row.querySelectorAll('.peer-connection-badge-mobile');
        if (!lastSeenCell) return;

        const rel = epochSeconds
            ? formatRelativeTime(epochSeconds)
            : { text: 'Never', cls: 'text-muted', active: false };

        connectionBadges.forEach((badge) => {
            badge.classList.toggle('bg-success', rel.active);
            badge.classList.toggle('bg-secondary', !rel.active);
            badge.textContent = rel.active ? 'Online' : 'Offline';
            if (!rel.active && rel.text && rel.text !== 'Never') {
                const timeSpan = document.createElement('span');
                timeSpan.className = 'peer-badge-time';
                timeSpan.textContent = ` · ${rel.text}`;
                badge.appendChild(timeSpan);
            }
        });

        const existingSpan = lastSeenCell.querySelector('span');
        const nextText = rel.active ? '' : rel.text;
        if (existingSpan && existingSpan.className === rel.cls && existingSpan.textContent === nextText) {
            return;
        }

        lastSeenCell.textContent = '';
        const span = document.createElement('span');
        span.className = rel.cls;
        span.textContent = nextText;
        lastSeenCell.appendChild(span);

        return rel;
    }

    function syncPeerCardLiveState(card, rel) {
        if (!card || !rel) return;

        const onlineBadge = card.querySelector('.peer-card-online-badge');
        if (onlineBadge) {
            onlineBadge.classList.toggle('bg-success', Boolean(rel.active));
            onlineBadge.classList.toggle('bg-secondary', !rel.active);
            onlineBadge.textContent = rel.active ? 'Online' : 'Offline';
        }

        const subline = card.querySelector('.peer-card-subline');
        let lastSeen = card.querySelector('.peer-card-last-seen');
        if (rel.text) {
            if (!lastSeen && subline) {
                lastSeen = document.createElement('span');
                lastSeen.className = 'peer-card-last-seen';
                subline.appendChild(lastSeen);
            }
            if (lastSeen) {
                lastSeen.textContent = rel.text;
            }
        } else {
            lastSeen?.remove();
        }
    }

    function buildPeerRow(peer) {
        const routingLabel = getRoutingLabel(peer);
        const { ipv4, ipv6 } = extractPeerIps(peer.peer_address);
        const name = peer.name || 'Unnamed';
        const iface = peer.interface || '';
        const isNodeTunnel = !!peer.is_node_tunnel;
        const nodeName = peer.node_name || lookupNodeName(peer.node_id);
        const hasClientIsolation = peer.client_isolation === true;
        const lastHandshake = toEpochSeconds(peer.latest_handshake || peer.last_handshake_at);
        const endpointIp = String(peer.endpoint_ip || peer.last_client_ip || '').trim();
        const endpointCountry = peer.country || peer.last_client_country_code || null;
        const endpointCity = peer.city || peer.last_client_city || null;
        const endpointAsOrg = peer.as_org || peer.last_client_as_org || null;

        const tr = document.createElement('tr');
        tr.dataset.peerId = peer.id;
        tr.dataset.peerPublicKey = peer.public_key || '';
        tr.dataset.lastHandshake = lastHandshake ? String(lastHandshake) : '';
        tr.dataset.lastClientIp = endpointIp;
        tr.dataset.lastClientCountry = endpointCountry || '';
        tr.dataset.lastClientCity = endpointCity || '';
        tr.dataset.lastClientAsOrg = endpointAsOrg || '';
        if (isNodeTunnel) {
            tr.dataset.nodeTunnel = 'true';
            tr.classList.add('peer-row-node-tunnel');
        }

        const tdName = document.createElement('td');
        tdName.className = 'peer-name-cell';
        const nameStack = document.createElement('div');
        nameStack.className = 'peer-name-stack';
        const nameMain = document.createElement('div');
        nameMain.className = 'peer-name-main';
        appendSafeText(nameMain, 'span', name, 'peer-name-text');
        nameStack.appendChild(nameMain);
        tdName.appendChild(nameStack);

        const tdVpn = document.createElement('td');
        tdVpn.className = 'peer-vpn-address';
        if (ipv4) {
            appendSafeText(tdVpn, 'code', ipv4, 'ipv6');
        }
        if (ipv4 && ipv6) {
            tdVpn.appendChild(document.createElement('br'));
        }
        if (ipv6) {
            appendSafeText(tdVpn, 'code', ipv6.replace(/:/g, ':\u200b'), 'ipv6');
        }
        if (!ipv4 && !ipv6) {
            appendSafeText(tdVpn, 'code', '—', 'ipv6');
        }

        const tdRouting = document.createElement('td');
        tdRouting.className = 'peer-routing';
        const routingBadges = document.createElement('div');
        routingBadges.className = 'peer-routing-badges';
        tdRouting.appendChild(routingBadges);
        if (nodeName) {
            const nodeBadge = document.createElement('span');
            nodeBadge.className = 'badge bg-secondary';
            nodeBadge.textContent = nodeName;
            routingBadges.appendChild(nodeBadge);
        }
        const routingBadge = document.createElement('span');
        routingBadge.className = 'badge bg-secondary';
        routingBadge.textContent = routingLabel;
        routingBadges.appendChild(routingBadge);
        if (hasClientIsolation) {
            const isolationBadge = document.createElement('span');
            isolationBadge.className = 'badge bg-secondary';
            isolationBadge.textContent = 'Client Isolation';
            routingBadges.appendChild(isolationBadge);
        }

        const tdIface = document.createElement('td');
        tdIface.className = 'peer-interface';
        tdIface.textContent = iface;

        const tdLastSeen = document.createElement('td');
        tdLastSeen.className = 'd-none d-xl-table-cell peer-last-seen text-nowrap';

        const tdClientIp = document.createElement('td');
        tdClientIp.className = 'd-none d-xl-table-cell peer-client-ip';
        tdClientIp.setAttribute('aria-live', 'polite');
        tdClientIp.setAttribute('aria-atomic', 'true');
        updateClientIpCell(tdClientIp, endpointIp, endpointCountry, endpointCity, endpointAsOrg);

        const tdStatus = document.createElement('td');
        tdStatus.className = 'peer-status-cell text-nowrap';
        tdStatus.setAttribute('aria-label', `Status: ${peer.is_enabled ? 'Enabled' : 'Disabled'}`);
        const connBadge = document.createElement('span');
        connBadge.className = 'badge bg-secondary peer-connection-badge peer-connection-badge-mobile';
        connBadge.setAttribute('role', 'status');
        const enabledBadge = document.createElement('span');
        enabledBadge.className = `badge ${peer.is_enabled ? 'bg-success' : 'bg-secondary'} peer-enabled-badge`;
        enabledBadge.setAttribute('role', 'status');
        enabledBadge.textContent = peer.is_enabled ? 'Enabled' : 'Disabled';
        tdStatus.append(connBadge, enabledBadge);

        const tdActions = document.createElement('td');
        tdActions.className = 'peer-actions-cell';
        tdActions.dataset.uiComponent = 'peer-actions';
        tdActions.dataset.uiDensity = 'compact';
        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'd-flex gap-1 justify-content-end';
        actionsDiv.dataset.uiComponent = 'peer-actions';
        actionsDiv.dataset.uiDensity = 'compact';
        if (isNodeTunnel) {
            const managedLabel = document.createElement('span');
            managedLabel.className = 'text-muted small';
            managedLabel.textContent = 'Managed by wirebuddy';
            actionsDiv.appendChild(managedLabel);
        } else if (canManagePeers) {
            actionsDiv.append(
                createPeerActionButton(peer.id, 'show-qr', 'Show QR code', 'qr_code', 'btn-outline-secondary'),
                createPeerActionButton(peer.id, 'download-config', 'Download config', 'download', 'btn-outline-secondary'),
                createPeerActionButton(peer.id, 'edit-peer', 'Edit peer', 'edit', 'btn-outline-secondary'),
                createPeerActionButton(peer.id, 'delete-peer', 'Delete peer', 'delete', 'btn-outline-danger'),
            );
        }
        tdActions.appendChild(actionsDiv);

        tr.append(tdName, tdVpn, tdRouting, tdIface, tdLastSeen, tdClientIp, tdStatus, tdActions);
        updateLastSeenDisplay(tr, lastHandshake);
        updateRowSearchText(tr);
        return tr;
    }

    function buildPeerCard(peer) {
        const routingLabel = getRoutingLabel(peer);
        const { ipv4, ipv6 } = extractPeerIps(peer.peer_address);
        const name = peer.name || 'Unnamed';
        const nodeName = peer.node_name || lookupNodeName(peer.node_id);
        const hasClientIsolation = peer.client_isolation === true;
        const isNodeTunnel = !!peer.is_node_tunnel;
        const lastHandshake = toEpochSeconds(peer.latest_handshake || peer.last_handshake_at);
        const rel = formatRelativeTime(lastHandshake);

        const article = document.createElement('article');
        article.className = `peer-card${isNodeTunnel ? ' peer-row-node-tunnel' : ''}`;
        article.dataset.peerId = peer.id;
        article.dataset.peerPublicKey = peer.public_key || '';
        article.dataset.lastHandshake = lastHandshake ? String(lastHandshake) : '';
        article.dataset.lastClientIp = String(peer.last_client_ip || '').trim();
        article.dataset.lastClientCountry = String(peer.last_client_country_code || '').trim();
        article.dataset.lastClientCity = String(peer.last_client_city || '').trim();
        article.dataset.lastClientAsOrg = String(peer.last_client_as_org || '').trim();
        if (isNodeTunnel) {
            article.dataset.nodeTunnel = 'true';
        }

        const header = document.createElement('div');
        header.className = 'peer-card-header';

        const identity = document.createElement('div');
        identity.className = 'peer-card-identity';
        const title = document.createElement('div');
        title.className = 'peer-card-title';
        title.textContent = name;
        identity.appendChild(title);

        const subline = document.createElement('div');
        subline.className = 'peer-card-subline';
        if (nodeName) {
            const nodeSpan = document.createElement('span');
            nodeSpan.textContent = nodeName;
            subline.appendChild(nodeSpan);
        }
        if (rel.text) {
            const seenSpan = document.createElement('span');
            seenSpan.className = 'peer-card-last-seen';
            seenSpan.textContent = rel.text;
            subline.appendChild(seenSpan);
        }
        identity.appendChild(subline);

        const status = document.createElement('div');
        status.className = 'peer-card-status';
        const onlineBadge = document.createElement('span');
        onlineBadge.className = `badge ${rel.active ? 'bg-success' : 'bg-secondary'} peer-card-online-badge`;
        onlineBadge.setAttribute('role', 'status');
        onlineBadge.textContent = rel.active ? 'Online' : 'Offline';
        status.appendChild(onlineBadge);

        const enabledBadge = document.createElement('span');
        enabledBadge.className = `badge ${peer.is_enabled ? 'bg-success' : 'bg-secondary'} peer-card-enabled-badge`;
        enabledBadge.setAttribute('role', 'status');
        enabledBadge.textContent = peer.is_enabled ? 'Enabled' : 'Disabled';
        status.appendChild(enabledBadge);

        header.append(identity, status);

        const meta = document.createElement('div');
        meta.className = 'peer-card-meta';

        const routing = document.createElement('div');
        routing.className = 'peer-card-routing';
        const routingLabelSpan = document.createElement('span');
        routingLabelSpan.className = 'badge peer-card-routing-badge';
        routingLabelSpan.textContent = routingLabel;
        routing.appendChild(routingLabelSpan);
        if (hasClientIsolation) {
            const isolatedSpan = document.createElement('span');
            isolatedSpan.className = 'badge peer-card-routing-badge';
            isolatedSpan.textContent = 'Isolated';
            routing.appendChild(isolatedSpan);
        }

        const addresses = document.createElement('div');
        addresses.className = 'peer-card-addresses';
        if (ipv4) {
            appendSafeText(addresses, 'code', ipv4, 'ipv6');
        }
        if (ipv6) {
            appendSafeText(addresses, 'code', ipv6.replace(/:/g, ':\u200b'), 'ipv6');
        }
        if (!ipv4 && !ipv6) {
            appendSafeText(addresses, 'code', '—', 'ipv6');
        }

        meta.append(routing, addresses);

        const actions = document.createElement('div');
        actions.className = 'peer-card-actions';
        actions.dataset.uiComponent = 'peer-actions';
        actions.dataset.uiDensity = 'compact';
        if (isNodeTunnel) {
            const managedLabel = document.createElement('span');
            managedLabel.className = 'text-muted small';
            managedLabel.textContent = 'Managed by wirebuddy';
            actions.appendChild(managedLabel);
        } else if (canManagePeers) {
            actions.append(
                createPeerActionButton(peer.id, 'show-qr', 'Show QR code', 'qr_code', 'btn-outline-secondary peer-card-action-btn'),
                createPeerActionButton(peer.id, 'download-config', 'Download config', 'download', 'btn-outline-secondary peer-card-action-btn'),
                createPeerMoreActions(peer),
            );
        } else {
            actions.append(
                createPeerActionButton(peer.id, 'show-qr', 'Show QR code', 'qr_code', 'btn-outline-secondary peer-card-action-btn peer-inert-button', { disabled: true }),
                createPeerActionButton(peer.id, 'download-config', 'Download config', 'download', 'btn-outline-secondary peer-card-action-btn peer-inert-button', { disabled: true }),
            );
        }

        article.append(header, meta, actions);
        article.dataset.searchText = computeSearchText(article);
        return article;
    }

    function updateTotalPeerCount(delta) {
        const totalEl = document.getElementById('peers-total-count');
        if (totalEl) {
            const current = parseInt(totalEl.textContent, 10) || 0;
            totalEl.textContent = String(Math.max(0, current + delta));
        }
        filterPeers(searchInput?.value || '');
    }

    function removeEmptyRow() {
        peersEmptyStateEl?.remove();
        peersTableWrapperEl?.classList.remove('d-none');
        peerCardListEl?.classList.remove('d-none');
        const tbody = document.getElementById('peers-table');
        const emptyRow = tbody?.querySelector('tr:not([data-peer-id])');
        if (emptyRow) emptyRow.remove();
    }

    function setSelectPlaceholder(select, text, disabled = true) {
        select.replaceChildren();
        const opt = document.createElement('option');
        opt.value = '';
        opt.disabled = disabled;
        opt.selected = true;
        opt.textContent = text;
        select.appendChild(opt);
    }

    function syncNodePicker(selectId) {
        const select = document.getElementById(selectId);
        const picker = document.querySelector(`.peer-node-picker[data-target-select="${selectId}"]`);
        if (!select || !picker) return;

        const selectedValue = select.value || '';
        const selectedOption = Array.from(picker.querySelectorAll('.peer-node-option')).find(
            (option) => option.dataset.value === selectedValue,
        ) || picker.querySelector('.peer-node-option[data-value=""]');
        const label = picker.querySelector('.peer-node-picker-label');

        if (selectedOption && label) {
            label.textContent = selectedOption.querySelector('.peer-node-option-label')?.textContent?.trim()
                || selectedOption.textContent?.trim()
                || '';
        }

        picker.querySelectorAll('.peer-node-option').forEach((option) => {
            const active = option.dataset.value === selectedValue;
            option.classList.toggle('active', active);
            option.setAttribute('aria-pressed', active ? 'true' : 'false');
        });
    }

    function initNodePickers() {
        document.querySelectorAll('.peer-node-picker[data-target-select]').forEach((picker) => {
            const selectId = picker.dataset.targetSelect || '';
            const select = document.getElementById(selectId);
            if (!select) return;

            picker.querySelectorAll('.peer-node-option').forEach((option) => {
                option.addEventListener('click', () => {
                    select.value = option.dataset.value || '';
                    syncNodePicker(selectId);
                    select.dispatchEvent(new Event('change', { bubbles: true }));
                });
            });

            syncNodePicker(selectId);
        });
    }

    function isValidIpv4(ip) {
        const parts = ip.split('.');
        if (parts.length !== 4) return false;
        return parts.every((part) => {
            if (!/^\d{1,3}$/.test(part)) return false;
            const n = Number(part);
            return n >= 0 && n <= 255;
        });
    }

    function isValidIpv6(ip) {
        if (!ip.includes(':') || ip.length > 39) return false;
        const groups = ip.split(':');
        if (groups.length < 2 || groups.length > 8) return false;
        return /^[0-9a-fA-F:]+$/.test(ip);
    }

    function isValidCidrEntry(entry) {
        const value = entry.trim();
        if (!value) return false;
        const match = value.match(/^(.+)\/(\d{1,3})$/);
        if (!match) return false;
        const ip = match[1].trim();
        const prefix = Number(match[2]);
        if (ip.includes(':')) {
            return isValidIpv6(ip) && prefix >= 0 && prefix <= 128;
        }
        return isValidIpv4(ip) && prefix >= 0 && prefix <= 32;
    }

    function validateAllowedIpsList(value) {
        const entries = value.split(',').map((s) => s.trim()).filter(Boolean);
        return entries.length > 0 && entries.every(isValidCidrEntry);
    }

    function validatePeerName(name, feedbackElementId = 'peer-name-feedback') {
        const feedbackEl = document.getElementById(feedbackElementId);
        if (feedbackEl) {
            if (!name || !name.trim()) {
                feedbackEl.textContent = 'Peer name is required';
            } else if (!name.match(/^[a-zA-Z0-9._\-# ']+$/)) {
                feedbackEl.textContent = "Peer name contains invalid characters (allowed: alphanumeric, '.', '_', '-', '#', space, apostrophe)";
            } else {
                feedbackEl.textContent = '';
            }
        }
        return Boolean(name && name.trim() && name.match(/^[a-zA-Z0-9._\-# ']+$/));
    }

    function parseEndpointIp(endpoint) {
        if (!endpoint || typeof endpoint !== 'string') return '';
        const trimmed = endpoint.trim();
        const bracketed = trimmed.match(/^\[([^\]]+)\](?::\d+)?$/);
        if (bracketed) return bracketed[1];
        const lastColon = trimmed.lastIndexOf(':');
        if (lastColon > -1 && trimmed.indexOf(':') === lastColon) {
            const port = trimmed.slice(lastColon + 1);
            if (/^\d+$/.test(port)) return trimmed.slice(0, lastColon);
        }
        return trimmed;
    }

    function formatRelativeTime(epochSeconds) {
        const date = typeof epochSeconds === 'number'
            ? new Date(epochSeconds * 1000)
            : new Date(epochSeconds);
        if (Number.isNaN(date.getTime())) {
            return { text: 'Never', cls: 'text-muted', active: false };
        }

        const diffSec = Math.floor((Date.now() - date.getTime()) / 1000);
        const diffMins = Math.floor(diffSec / 60);
        if (diffSec < CONNECTED_THRESHOLD_SEC) return { text: '', cls: '', active: true };
        if (diffMins < 60) return { text: `${diffMins}m ago`, cls: 'text-muted', active: false };
        if (diffMins < 1440) return { text: `${Math.floor(diffMins / 60)}h ago`, cls: 'text-muted', active: false };
        return { text: `${Math.floor(diffMins / 1440)}d ago`, cls: 'text-muted', active: false };
    }

    function toEpochSeconds(value) {
        if (value === null || value === undefined || value === '') return 0;
        const n = Number(value);
        return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
    }

    function trimCache(map) {
        while (map.size > MAX_LAST_SEEN_CACHE) {
            const oldestKey = map.keys().next().value;
            if (oldestKey === undefined) break;
            map.delete(oldestKey);
        }
    }

    function updateLastSeenCache(peerId, value) {
        const next = toEpochSeconds(value);
        if (!next) return 0;
        const current = toEpochSeconds(state.lastSeenCache.get(peerId));
        if (next > current) {
            state.lastSeenCache.set(peerId, next);
            trimCache(state.lastSeenCache);
            return next;
        }
        return current;
    }

    function updatePeerSeenCache(peerId, handshakeValue, endpointIp, country, city, asOrg) {
        const handshake = toEpochSeconds(handshakeValue);
        const ip = String(endpointIp || '').trim();
        const current = state.peerSeenCache.get(peerId);

        if (!current) {
            if (!ip && !handshake) return;
            state.peerSeenCache.set(peerId, {
                handshake,
                endpointIp: ip,
                country: country || null,
                city: city || null,
                asOrg: asOrg || null,
            });
            trimCache(state.peerSeenCache);
            return;
        }

        if (handshake > (current.handshake || 0)) {
            current.handshake = handshake;
            if (ip) current.endpointIp = ip;
            if (country) current.country = country;
            if (city) current.city = city;
            if (asOrg) current.asOrg = asOrg;
            state.peerSeenCache.set(peerId, current);
            return;
        }

        if (!current.endpointIp && ip) current.endpointIp = ip;
        if (!current.country && country) current.country = country;
        if (!current.city && city) current.city = city;
        if (!current.asOrg && asOrg) current.asOrg = asOrg;
        state.peerSeenCache.set(peerId, current);
    }

    async function fetchPeersEnriched(signal) {
        const payload = await api(
            'GET',
            '/api/wireguard/stats/peers-enriched',
            null,
            { signal, timeoutMs: 15000 },
        );
        if (Array.isArray(payload?.peers)) return payload.peers;
        if (Array.isArray(payload?.data?.peers)) return payload.data.peers;
        return Array.isArray(payload) ? payload : [];
    }

    async function loadBlocklistRegistry() {
        try {
            const res = await api('GET', '/api/dns/blocklist/sources');
            const sources = Array.isArray(res?.sources)
                ? res.sources
                : (Array.isArray(res?.data?.sources) ? res.data.sources : []);

            const enabledSources = sources.filter((source) => {
                const enabled = source?.enabled;
                return enabled === true || enabled === 1 || String(enabled).toLowerCase() === 'true';
            });

            state.blocklistRegistry = enabledSources.length ? enabledSources : sources;
        } catch (e) {
            console.warn('Failed to load blocklist sources:', e);
            state.blocklistRegistry = [];
        }
    }

    function renderBlocklistOptions(containerId, selectedIds = null) {
        const container = document.getElementById(containerId);
        if (!container) return;
        container.innerHTML = '';

        if (!state.blocklistRegistry.length) {
            const empty = document.createElement('small');
            empty.className = 'text-muted';
            empty.textContent = 'No global blocklists enabled in Settings -> DNS.';
            container.appendChild(empty);
            return;
        }

        const allSelected = selectedIds === null;

        state.blocklistRegistry.forEach((source) => {
            const col = document.createElement('div');
            col.className = 'col-6';

            const wrapper = document.createElement('div');
            wrapper.className = 'form-check';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'form-check-input';
            checkbox.id = `${containerId}-${source.id}`;
            checkbox.value = source.id;
            checkbox.checked = allSelected || (Array.isArray(selectedIds) && selectedIds.includes(source.id));

            const label = document.createElement('label');
            label.className = 'form-check-label d-inline-flex align-items-center flex-wrap';
            label.htmlFor = checkbox.id;
            label.title = source.description || '';

            const labelText = document.createElement('span');
            labelText.textContent = source.name;
            label.appendChild(labelText);

            const level = source.level || '';
            const levelBadgeLabel = {
                'Moderat': 'Moderate',
                'Ausgewogen': 'Balanced',
                'Extrem': '🔥Extreme',
                '18+': '❤️ 18+',
            }[level] || (level ? level : '');

            if (levelBadgeLabel) {
                const badge = document.createElement('span');
                badge.className = 'badge text-bg-secondary ms-1';
                badge.style.cssText = 'font-size: 0.65rem; line-height: 1.2; vertical-align: middle;';
                badge.textContent = levelBadgeLabel;
                label.appendChild(badge);
            }

            wrapper.append(checkbox, label);
            col.appendChild(wrapper);
            container.appendChild(col);
        });
    }

    function getSelectedBlocklistIds(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return null;

        const checkboxes = container.querySelectorAll('input[type="checkbox"]');
        if (!checkboxes.length) return [];

        const selected = [];
        let allChecked = true;
        checkboxes.forEach((cb) => {
            if (cb.checked) selected.push(cb.value);
            else allChecked = false;
        });
        return allChecked ? null : selected;
    }

    function toggleBlocklistSection(checkboxId, sectionId) {
        const checkbox = document.getElementById(checkboxId);
        const section = document.getElementById(sectionId);
        const hintId = checkboxId.replace('use-adblocker', 'fallback-dns-hint');
        const hint = document.getElementById(hintId);
        const dnsLoggingWrapperId = checkboxId.replace('use-adblocker', 'dns-logging-wrapper');
        const dnsLoggingWrapper = document.getElementById(dnsLoggingWrapperId);
        const isAdblockingEnabled = checkbox?.checked ?? true;
        const isEditModal = checkboxId.startsWith('edit-');
        const globalDnsLogging = isEditModal
            ? state.globalDnsLoggingEnabled.edit
            : state.globalDnsLoggingEnabled.add;

        if (checkbox && section) {
            section.style.display = isAdblockingEnabled ? 'block' : 'none';
        }
        if (hint) {
            hint.classList.toggle('d-none', isAdblockingEnabled);
        }
        if (dnsLoggingWrapper) {
            dnsLoggingWrapper.style.display = (isAdblockingEnabled && globalDnsLogging) ? 'block' : 'none';
        }
    }

    function toggleDnsLoggingControl(wrapperId, enabled, updateCache = false) {
        const wrapper = document.getElementById(wrapperId);
        if (!wrapper) return;
        if (updateCache) {
            const isEditModal = wrapperId.startsWith('edit-');
            if (isEditModal) state.globalDnsLoggingEnabled.edit = enabled;
            else state.globalDnsLoggingEnabled.add = enabled;
        }
        wrapper.style.display = enabled ? 'block' : 'none';
    }

    function toggleAllowedIpsCustom(prefix = '') {
        const modeEl = document.getElementById(`${prefix}peer-allowed-ips-mode`);
        const customWrapper = document.getElementById(`${prefix}peer-allowed-ips-custom-wrapper`);
        const customInput = document.getElementById(`${prefix}peer-allowed-ips-custom`);
        const hint = document.getElementById(`${prefix}allowed-ips-hint`);
        if (!modeEl || !customWrapper || !customInput || !hint) return;
        const mode = modeEl.value;

        if (mode === 'custom') {
            customWrapper.classList.remove('d-none');
        } else {
            customWrapper.classList.add('d-none');
            customInput.value = '';
        }
        hint.textContent = ALLOWED_IPS_HINTS[mode] || '';
    }

    function getAllowedIps(prefix = '') {
        const mode = document.getElementById(`${prefix}peer-allowed-ips-mode`)?.value || 'full';
        if (mode === 'custom') {
            return (document.getElementById(`${prefix}peer-allowed-ips-custom`)?.value || '').trim();
        }
        return ALLOWED_IPS_PRESETS[mode] || ALLOWED_IPS_PRESETS.full;
    }

    function validateAndGetAllowedIps(prefix = '') {
        const ips = getAllowedIps(prefix);
        if (!ips) {
            wbAlert('Please enter allowed IPs', 'warning');
            return null;
        }
        if (!validateAllowedIpsList(ips)) {
            wbAlert('Invalid Allowed IPs format. Use CIDR entries like 10.0.0.0/24, 2001:db8::/64', 'warning');
            return null;
        }
        return ips;
    }

    function detectAllowedIpsMode(allowedIps) {
        if (!allowedIps) return 'full';
        const normalize = (s) => s.replace(/\s/g, '').split(',').sort().join(',');
        const normalized = normalize(allowedIps);
        for (const [mode, preset] of Object.entries(ALLOWED_IPS_PRESETS)) {
            if (normalize(preset) === normalized) return mode;
        }
        return 'custom';
    }

    function scheduleNextPeerStatsPoll(delay = state.peerStatsBackoffMs) {
        if (state.peerStatsTimer) {
            clearTimeout(state.peerStatsTimer);
            state.peerStatsTimer = null;
        }
        if (document.hidden || document.querySelector('.modal.show')) return;
        state.peerStatsTimer = setTimeout(() => {
            queuePeerStatsReload('scheduled peer stats poll failed');
        }, Math.max(0, delay));
    }

    function stopPeerStatsPolling() {
        if (state.peerStatsTimer) {
            clearTimeout(state.peerStatsTimer);
            state.peerStatsTimer = null;
        }
        if (state.peerStatsAbortController) {
            state.peerStatsAbortController.abort();
            state.peerStatsAbortController = null;
        }
    }

    function startPeerStatsPolling(immediate = false) {
        if (document.hidden || document.querySelector('.modal.show')) return;
        scheduleNextPeerStatsPoll(immediate ? 0 : state.peerStatsBackoffMs);
    }

    function syncHideNodesRootClass(enabled) {
        rootEl?.classList.toggle('wb-peers-hide-nodes', Boolean(enabled));
    }

    async function loadPeerStats() {
        if (document.hidden || document.querySelector('.modal.show')) return;
        if (state.peerStatsAbortController) state.peerStatsAbortController.abort();

        const controller = new AbortController();
        state.peerStatsAbortController = controller;
        const requestSeq = ++state.peerStatsRequestSeq;

        if (!state.peerRows.length || !state.peerCards.length) refreshPeerRows();

        try {
            const peers = await fetchPeersEnriched(controller.signal);
            if (controller.signal.aborted || requestSeq !== state.peerStatsRequestSeq) return;
            if (document.querySelector('.modal.show')) return;

            const byId = new Map(peers.map((p) => [String(p.id), p]));
            const byPublicKey = new Map(
                peers
                    .filter((p) => typeof p?.public_key === 'string' && p.public_key.trim())
                    .map((p) => [p.public_key.trim(), p]),
            );

            state.peerRows.forEach((row) => {
                const peerId = String(row.dataset.peerId);
                const peerPublicKey = String(row.dataset.peerPublicKey || '').trim();
                const stats = byId.get(peerId) || (peerPublicKey ? byPublicKey.get(peerPublicKey) : null) || {};
                const persistedHandshake = toEpochSeconds(row.dataset.lastHandshake);
                const persistedEndpointIp = String(row.dataset.lastClientIp || '').trim();
                const persistedCountry = String(row.dataset.lastClientCountry || '').trim() || null;
                const persistedCity = String(row.dataset.lastClientCity || '').trim() || null;
                const persistedAsOrg = String(row.dataset.lastClientAsOrg || '').trim() || null;

                const liveHandshake = toEpochSeconds(stats.latest_handshake);
                if (persistedHandshake) updateLastSeenCache(peerId, persistedHandshake);
                const cachedHandshake = liveHandshake
                    ? updateLastSeenCache(peerId, liveHandshake)
                    : toEpochSeconds(state.lastSeenCache.get(peerId));
                const rel = updateLastSeenDisplay(row, cachedHandshake);

                const liveEndpointIp = String(stats.endpoint_ip || parseEndpointIp(stats.endpoint || '') || '').trim();
                updatePeerSeenCache(
                    peerId,
                    liveHandshake || cachedHandshake,
                    liveEndpointIp || persistedEndpointIp,
                    stats.country || persistedCountry,
                    stats.city || persistedCity,
                    stats.as_org || persistedAsOrg,
                );
                const cachedSeen = state.peerSeenCache.get(peerId);
                const endpointIp = liveEndpointIp || cachedSeen?.endpointIp || persistedEndpointIp || '';
                const country = stats.country || cachedSeen?.country || persistedCountry || null;
                const city = stats.city || cachedSeen?.city || persistedCity || null;
                const asOrg = stats.as_org || cachedSeen?.asOrg || persistedAsOrg || null;

                if (liveHandshake > persistedHandshake) row.dataset.lastHandshake = String(liveHandshake);
                row.dataset.lastClientIp = endpointIp;
                row.dataset.lastClientCountry = country || '';
                row.dataset.lastClientCity = city || '';
                row.dataset.lastClientAsOrg = asOrg || '';

                const clientIpCell = row.querySelector('.peer-client-ip');
                if (clientIpCell) {
                    updateClientIpCell(clientIpCell, endpointIp, country, city, asOrg);
                }
                const card = document.querySelector(`#peer-card-list .peer-card[data-peer-id="${peerId}"]`);
                syncPeerCardLiveState(card, rel);
                updateRowSearchText(row);
                if (card) updateRowSearchText(card);
            });

            state.peerStatsBackoffMs = PEER_STATS_INTERVAL_MS;
        } catch (error) {
            if (error?.name === 'AbortError' || error?.code === 'ABORTED') return;
            state.peerStatsBackoffMs = Math.min(state.peerStatsBackoffMs * 2, PEER_STATS_MAX_BACKOFF_MS);
        } finally {
            if (state.peerStatsAbortController === controller) {
                state.peerStatsAbortController = null;
            }
            if (!document.hidden && !document.querySelector('.modal.show')) {
                scheduleNextPeerStatsPoll(state.peerStatsBackoffMs);
            }
        }
    }

    async function showQR(peerId) {
        if (!qrModal) return;
        const loading = document.getElementById('qr-loading');
        const image = document.getElementById('qr-image');
        const requestId = ++state.qrRequestSeq;
        if (state.qrAbortController) state.qrAbortController.abort();
        state.qrAbortController = new AbortController();

        revokeQrBlobUrl();
        image.removeAttribute('src');
        image.classList.add('d-none');
        loading.classList.remove('d-none');
        qrModal.show();

        const qrTimeoutId = setTimeout(() => state.qrAbortController?.abort(), QR_FETCH_TIMEOUT_MS);
        try {
            const response = await fetch(`/api/wireguard/peers/${peerId}/qrcode`, {
                signal: state.qrAbortController.signal,
                credentials: 'same-origin',
            });

            if (!response.ok) {
                let detail = 'Failed to load QR code';
                try {
                    const body = await response.json();
                    if (body?.detail) detail = body.detail;
                } catch (_) {
                    // Ignore JSON parse failures for non-JSON error responses.
                }
                throw new Error(detail);
            }
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            if (requestId !== state.qrRequestSeq) {
                URL.revokeObjectURL(url);
                return;
            }

            state.qrBlobUrl = url;
            image.src = url;
            loading.classList.add('d-none');
            image.classList.remove('d-none');
        } catch (error) {
            if (error?.name === 'AbortError') return;
            qrModal.hide();
            wbAlert('Failed to generate QR code: ' + safeErrorMessage(error), 'danger');
        } finally {
            clearTimeout(qrTimeoutId);
        }
    }

    async function downloadConfig(peerId) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), DOWNLOAD_FETCH_TIMEOUT_MS);
        try {
            const response = await fetch(`/api/wireguard/peers/${peerId}/config`, {
                signal: controller.signal,
                credentials: 'same-origin',
            });

            if (!response.ok) {
                let detail = 'Failed to download config';
                try {
                    const body = await response.json();
                    if (body?.detail) detail = body.detail;
                } catch (_) {
                    // Ignore JSON parse failures for non-JSON error responses.
                }
                throw new Error(detail);
            }

            const blob = await response.blob();
            const cd = response.headers.get('Content-Disposition');
            const match = cd?.match(/filename="?([^"]+)"?/);
            const rawFilename = match?.[1] || 'peer.conf';
            const filename = rawFilename.replace(/[^\w.\-]/g, '_');

            const a = document.createElement('a');
            const url = URL.createObjectURL(blob);
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();

            setTimeout(() => URL.revokeObjectURL(url), BLOB_REVOKE_DELAY_MS);
            wbToast('Config downloaded: ' + filename, 'success');
        } catch (error) {
            wbAlert('Failed to download config: ' + safeErrorMessage(error), 'danger');
        } finally {
            clearTimeout(timeoutId);
        }
    }

    async function deletePeer(peerId) {
        if (!canManagePeers) {
            wbAlert('Only administrators can delete peers', 'warning');
            return;
        }
        if (!await wbConfirm('Are you sure you want to delete this peer?', 'danger')) return;

        try {
            await api('DELETE', `/api/wireguard/peers/${peerId}`);
            wbToast('Peer deleted successfully', 'success');
            const row = document.querySelector(`#peers-table tr[data-peer-id="${peerId}"]`);
            const card = document.querySelector(`#peer-card-list .peer-card[data-peer-id="${peerId}"]`);
            if (row) {
                disposeTooltips(row);
                row.remove();
            }
            if (card) {
                disposeTooltips(card);
                card.remove();
            }
            if (row || card) {
                refreshPeerRows();
                updateTotalPeerCount(-1);
            } else {
                reloadSoon();
            }
        } catch (error) {
            wbAlert('Failed to delete peer: ' + safeErrorMessage(error), 'danger');
        }
    }

    async function editPeer(peerId) {
        if (!canManagePeers) {
            wbAlert('Only administrators can edit peers', 'warning');
            return;
        }
        const modal = bootstrap.Modal.getOrCreateInstance(document.getElementById('editPeerModal'));
        document.getElementById('edit-peer-name')?.classList.remove('is-invalid');

        try {
            const [peer, dnsConfig] = await Promise.all([
                api('GET', `/api/wireguard/peers/${peerId}`),
                api('GET', '/api/dns/config'),
            ]);

            document.getElementById('edit-peer-id').value = peerId;
            document.getElementById('edit-peer-name').value = peer.name || '';
            const editNodeSelect = document.getElementById('edit-peer-node');
            if (editNodeSelect) {
                editNodeSelect.value = peer.node_id || '';
                syncNodePicker('edit-peer-node');
            }

            const mode = detectAllowedIpsMode(peer.allowed_ips);
            document.getElementById('edit-peer-allowed-ips-mode').value = mode;
            document.getElementById('edit-peer-allowed-ips-custom').value = mode === 'custom' ? (peer.allowed_ips || '') : '';
            toggleAllowedIpsCustom('edit-');

            document.getElementById('edit-peer-use-adblocker').checked = peer.use_adblocker !== false;
            document.getElementById('edit-peer-dns-logging').checked = peer.dns_logging_enabled !== false;
            document.getElementById('edit-peer-enabled').checked = peer.is_enabled;
            document.getElementById('edit-peer-client-isolation').checked = peer.client_isolation === true;
            const editAllowAllNodes = document.getElementById('edit-peer-allow-all-nodes');
            if (editAllowAllNodes) editAllowAllNodes.checked = peer.allow_all_nodes === true;
            toggleDnsLoggingControl('edit-peer-dns-logging-wrapper', dnsConfig?.enable_logging !== false, true);

            await loadBlocklistRegistry();
            renderBlocklistOptions('edit-peer-blocklist-options', peer.blocklist_ids);
            toggleBlocklistSection('edit-peer-use-adblocker', 'edit-peer-blocklist-section');
            modal.show();
        } catch (error) {
            wbAlert('Failed to load peer details: ' + safeErrorMessage(error), 'danger');
        }
    }

    function filterPeers(query) {
        const searchTerm = (query || '').toLowerCase().trim();
        const hideNodes = hideNodesCheckbox?.checked || false;
        let visibleCount = 0;

        const applyVisibility = (items) => {
            items.forEach((item) => {
                const isNodeTunnel = item.hasAttribute('data-node-tunnel');
                if (hideNodes && isNodeTunnel) {
                    item.classList.add('peer-row-hidden');
                    return;
                }

                if (!searchTerm || String(item.dataset.searchText || '').includes(searchTerm)) {
                    item.classList.remove('peer-row-hidden');
                } else {
                    item.classList.add('peer-row-hidden');
                }
            });
        };

        applyVisibility(state.peerRows);
        applyVisibility(state.peerCards);
        visibleCount = state.peerRows.reduce((count, row) => count + (row.classList.contains('peer-row-hidden') ? 0 : 1), 0);

        if (visibleCountEl) {
            visibleCountEl.textContent = String(visibleCount);
        }

        if (noResultsEl && peersTableEl) {
            const hasPeers = state.peerRows.length > 0 || state.peerCards.length > 0;
            const peersTableWrap = peersTableWrapperEl;
            const mobileListWrap = peerCardListEl;
            if (visibleCount === 0 && state.peerRows.length > 0) {
                noResultsEl.classList.remove('d-none');
                peersTableWrap?.classList.add('d-none');
                mobileListWrap?.classList.add('d-none');
            } else {
                noResultsEl.classList.add('d-none');
                if (hasPeers) {
                    peersTableWrap?.classList.remove('d-none');
                    mobileListWrap?.classList.remove('d-none');
                }
            }
        }

        if (searchClearBtn) {
            searchClearBtn.classList.toggle('d-none', !searchTerm);
        }
    }

    function cleanupPeersPageState() {
        stopPeerStatsPolling();
        disposeTooltips(document);
        if (state.qrAbortController) state.qrAbortController.abort();
        revokeQrBlobUrl();
    }

    function initModalPollingGuards() {
        document.querySelectorAll('.modal').forEach((modal) => {
            modal.addEventListener('show.bs.modal', stopPeerStatsPolling);
            modal.addEventListener('hidden.bs.modal', () => {
                if (!document.hidden) startPeerStatsPolling(true);
            });
        });
    }

    function bindAdminHandlers() {
        if (!canManagePeers) return;

        const addPeerModalEl = document.getElementById('addPeerModal');
        if (addPeerModalEl) {
            addPeerModalEl.addEventListener('show.bs.modal', async () => {
                document.getElementById('peer-name')?.classList.remove('is-invalid');

                if (state.addPeerModalAbort) state.addPeerModalAbort.abort();
                state.addPeerModalAbort = new AbortController();
                const signal = state.addPeerModalAbort.signal;

                const select = document.getElementById('peer-interface');
                select.disabled = false;
                setSelectPlaceholder(select, 'Loading...');

                const submitBtn = document.getElementById('add-peer-submit-btn');
                const submitText = submitBtn?.querySelector('.submit-text');
                const submitSpinner = submitBtn?.querySelector('.spinner-border');
                if (submitBtn && submitText && submitSpinner) {
                    submitBtn.disabled = false;
                    submitText.textContent = 'Create Device';
                    submitText.classList.remove('d-none');
                    submitSpinner.classList.add('d-none');
                }

                const fqdnWarning = document.getElementById('peer-fqdn-warning');
                try {
                    const settings = await api('GET', '/api/wireguard/settings', null, { signal });
                    if (signal.aborted) return;
                    const wgFqdn = settings?.wg_fqdn;
                    if (!wgFqdn || wgFqdn.trim() === '' || wgFqdn === 'vpn.example.com') {
                        fqdnWarning?.classList.remove('d-none');
                        if (submitBtn) submitBtn.disabled = true;
                    } else {
                        fqdnWarning?.classList.add('d-none');
                    }
                } catch (e) {
                    if (e?.name !== 'AbortError') {
                        console.warn('Could not check WireGuard settings:', e);
                    }
                }

                try {
                    const dnsConfig = await api('GET', '/api/dns/config', null, { signal });
                    if (signal.aborted) return;
                    toggleDnsLoggingControl('peer-dns-logging-wrapper', dnsConfig?.enable_logging !== false, true);
                } catch (e) {
                    if (e?.name !== 'AbortError') {
                        console.warn('Could not check DNS config:', e);
                    }
                    toggleDnsLoggingControl('peer-dns-logging-wrapper', true, true);
                }

                try {
                    await loadBlocklistRegistry();
                    if (signal.aborted) return;
                } catch (e) {
                    if (e?.name === 'AbortError') return;
                }

                renderBlocklistOptions('peer-blocklist-options', null);
                toggleBlocklistSection('peer-use-adblocker', 'peer-blocklist-section');

                try {
                    const res = await api('GET', '/api/wireguard/interfaces', null, { signal });
                    if (signal.aborted) return;
                    select.replaceChildren();

                    const activeInterfaces = res.interfaces.filter((iface) => iface.is_active);
                    if (activeInterfaces.length === 0) {
                        select.disabled = true;
                        setSelectPlaceholder(select, 'No active interfaces', false);
                        return;
                    }

                    activeInterfaces.forEach((iface, idx) => {
                        const opt = document.createElement('option');
                        opt.value = iface.name;
                        opt.textContent = iface.name;
                        if (idx === 0) opt.selected = true;
                        select.appendChild(opt);
                    });
                } catch (e) {
                    if (e?.name === 'AbortError') return;
                    select.disabled = true;
                    setSelectPlaceholder(select, 'Failed to load interfaces', false);
                }
            });

            addPeerModalEl.addEventListener('hidden.bs.modal', () => {
                if (state.addPeerModalAbort) {
                    state.addPeerModalAbort.abort();
                    state.addPeerModalAbort = null;
                }
            });
        }

        document.getElementById('peer-name')?.addEventListener('input', function () {
            this.classList.remove('is-invalid');
        });
        document.getElementById('peer-name')?.addEventListener('blur', function () {
            if (this.value) {
                validatePeerName(this.value, 'peer-name-feedback');
                this.classList.toggle('is-invalid', !this.value.match(/^[a-zA-Z0-9._\-# ']+$/));
            }
        });

        document.getElementById('edit-peer-name')?.addEventListener('input', function () {
            this.classList.remove('is-invalid');
        });
        document.getElementById('edit-peer-name')?.addEventListener('blur', function () {
            if (this.value) {
                validatePeerName(this.value, 'edit-peer-name-feedback');
                this.classList.toggle('is-invalid', !this.value.match(/^[a-zA-Z0-9._\-# ']+$/));
            }
        });

        document.getElementById('add-peer-form')?.addEventListener('submit', async (e) => {
            e.preventDefault();

            const submitBtn = document.getElementById('add-peer-submit-btn');
            const submitText = submitBtn.querySelector('.submit-text');
            const submitSpinner = submitBtn.querySelector('.spinner-border');
            const peerNameInput = document.getElementById('peer-name');
            const peerName = peerNameInput.value.trim();

            if (!validatePeerName(peerName, 'peer-name-feedback')) {
                peerNameInput.classList.add('is-invalid');
                peerNameInput.focus();
                return;
            }

            const allowedIpsMode = document.getElementById('peer-allowed-ips-mode').value;
            const allowedIps = validateAndGetAllowedIps();
            if (!allowedIps) return;

            const data = {
                name: peerName,
                allowed_ips: allowedIps,
                allowed_ips_mode: allowedIpsMode,
                interface: document.getElementById('peer-interface').value,
                use_adblocker: document.getElementById('peer-use-adblocker').checked,
                dns_logging_enabled: document.getElementById('peer-dns-logging').checked,
                blocklist_ids: getSelectedBlocklistIds('peer-blocklist-options'),
                client_isolation: document.getElementById('peer-client-isolation').checked,
            };

            const nodeSelect = document.getElementById('peer-node');
            if (nodeSelect && nodeSelect.value) {
                data.node_id = nodeSelect.value;
            }
            const allowAllNodesCheckbox = document.getElementById('peer-allow-all-nodes');
            if (allowAllNodesCheckbox) {
                data.allow_all_nodes = allowAllNodesCheckbox.checked;
            }

            if (!data.interface) {
                wbAlert('No active interface available', 'warning');
                return;
            }

            submitBtn.disabled = true;
            submitText.textContent = 'Creating...';
            submitSpinner.classList.remove('d-none');

            try {
                const createdPeer = await api('POST', '/api/wireguard/peers', data);
                document.activeElement?.blur();
                bootstrap.Modal.getInstance(document.getElementById('addPeerModal')).hide();
                wbToast('Peer created successfully', 'success');

                try {
                    const newPeer = await hydratePeerRowData(createdPeer);
                    if (newPeer) {
                        removeEmptyRow();
                        const tbody = document.getElementById('peers-table');
                        const cardList = document.getElementById('peer-card-list');
                        const row = buildPeerRow(newPeer);
                        const card = buildPeerCard(newPeer);
                        tbody.appendChild(row);
                        cardList?.appendChild(card);
                        refreshPeerRows();
                        updateTotalPeerCount(1);
                        initTooltips(row);
                        initTooltips(card);
                        queuePeerStatsReload('peer create follow-up stats refresh failed');
                    } else {
                        reloadSoon();
                    }
                } catch {
                    reloadSoon();
                }
            } catch (error) {
                wbAlert('Failed to create peer: ' + safeErrorMessage(error), 'danger');
            } finally {
                submitBtn.disabled = false;
                submitText.textContent = 'Create Device';
                submitText.classList.remove('d-none');
                submitSpinner.classList.add('d-none');
            }
        });

        document.getElementById('edit-peer-form')?.addEventListener('submit', async (e) => {
            e.preventDefault();

            const submitBtn = document.getElementById('edit-peer-submit-btn');
            const submitText = submitBtn.querySelector('.submit-text');
            const submitSpinner = submitBtn.querySelector('.spinner-border');
            const peerId = Number(document.getElementById('edit-peer-id').value);

            if (!Number.isFinite(peerId) || peerId <= 0) {
                wbAlert('Invalid peer ID', 'danger');
                return;
            }

            const editPeerNameInput = document.getElementById('edit-peer-name');
            const name = editPeerNameInput.value.trim();
            if (!validatePeerName(name, 'edit-peer-name-feedback')) {
                editPeerNameInput.classList.add('is-invalid');
                editPeerNameInput.focus();
                return;
            }

            const allowedIpsMode = document.getElementById('edit-peer-allowed-ips-mode').value;
            const allowedIps = validateAndGetAllowedIps('edit-');
            if (!allowedIps) return;

            const data = {
                name,
                allowed_ips: allowedIps,
                allowed_ips_mode: allowedIpsMode,
                is_enabled: document.getElementById('edit-peer-enabled').checked,
                use_adblocker: document.getElementById('edit-peer-use-adblocker').checked,
                dns_logging_enabled: document.getElementById('edit-peer-dns-logging').checked,
                blocklist_ids: getSelectedBlocklistIds('edit-peer-blocklist-options'),
                client_isolation: document.getElementById('edit-peer-client-isolation').checked,
            };

            const editNodeSelect = document.getElementById('edit-peer-node');
            if (editNodeSelect) {
                data.node_id = editNodeSelect.value || null;
            }
            const editAllowAllNodesCheckbox = document.getElementById('edit-peer-allow-all-nodes');
            if (editAllowAllNodesCheckbox) {
                data.allow_all_nodes = editAllowAllNodesCheckbox.checked;
            }

            submitBtn.disabled = true;
            submitText.classList.add('d-none');
            submitSpinner.classList.remove('d-none');

            try {
                const updatedPeerResponse = await api('PATCH', `/api/wireguard/peers/${peerId}`, data);
                document.activeElement?.blur();
                bootstrap.Modal.getInstance(document.getElementById('editPeerModal')).hide();
                wbToast('Peer updated successfully', 'success');

                try {
                    const updatedPeer = await hydratePeerRowData(updatedPeerResponse);
                    if (updatedPeer) {
                        const oldRow = document.querySelector(`#peers-table tr[data-peer-id="${peerId}"]`);
                        if (oldRow) {
                            disposeTooltips(oldRow);
                            const newRow = buildPeerRow(updatedPeer);
                            const oldCard = document.querySelector(`#peer-card-list .peer-card[data-peer-id="${peerId}"]`);
                            const newCard = buildPeerCard(updatedPeer);
                            oldRow.replaceWith(newRow);
                            oldCard?.replaceWith(newCard);
                            refreshPeerRows();
                            initTooltips(newRow);
                            initTooltips(newCard);
                            filterPeers(searchInput?.value || '');
                            queuePeerStatsReload('peer update follow-up stats refresh failed');
                        } else {
                            reloadSoon();
                        }
                    } else {
                        reloadSoon();
                    }
                } catch {
                    reloadSoon();
                }
            } catch (error) {
                wbAlert('Failed to update peer: ' + safeErrorMessage(error), 'danger');
            } finally {
                submitBtn.disabled = false;
                submitText.classList.remove('d-none');
                submitSpinner.classList.add('d-none');
            }
        });
    }

    qrModalEl?.addEventListener('hidden.bs.modal', () => {
        if (state.qrAbortController) {
            state.qrAbortController.abort();
        }
        state.qrAbortController = null;
        revokeQrBlobUrl();
        const image = document.getElementById('qr-image');
        image.removeAttribute('src');
        image.classList.add('d-none');
        document.getElementById('qr-loading').classList.remove('d-none');
    });

    document.addEventListener('visibilitychange', () => {
        clearTimeout(state.visibilityTimeout);
        if (document.hidden) {
            stopPeerStatsPolling();
        } else {
            state.visibilityTimeout = setTimeout(() => {
                startPeerStatsPolling(true);
            }, 300);
        }
    });

    window.addEventListener('pagehide', cleanupPeersPageState);

    if (hideNodesCheckbox) {
        try {
            hideNodesCheckbox.checked = window.localStorage.getItem(HIDE_NODES_KEY) === 'true';
        } catch (_) {
            hideNodesCheckbox.checked = false;
        }
        syncHideNodesRootClass(hideNodesCheckbox.checked);
        hideNodesCheckbox.addEventListener('change', () => {
            syncHideNodesRootClass(hideNodesCheckbox.checked);
            try {
                localStorage.setItem(HIDE_NODES_KEY, hideNodesCheckbox.checked ? 'true' : 'false');
            } catch (_) {
                // Ignore storage failures.
            }
            filterPeers(searchInput?.value || '');
        });
    }

    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            clearTimeout(state.searchDebounceTimer);
            state.searchDebounceTimer = setTimeout(() => {
                filterPeers(e.target.value);
            }, 100);
        });

        searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                searchInput.value = '';
                filterPeers('');
                searchInput.blur();
            }
        });
    }

    searchClearBtn?.addEventListener('click', () => {
        if (searchInput) {
            searchInput.value = '';
            filterPeers('');
            searchInput.focus();
        }
    });

    document.addEventListener('click', async (event) => {
        const button = event.target.closest('button[data-action][data-peer-id]');
        if (!button || button.disabled) return;
        if (!button.closest('#peers-table') && !button.closest('#peer-card-list')) return;

        const peerId = Number(button.dataset.peerId);
        if (!Number.isFinite(peerId) || peerId <= 0) return;

        switch (button.dataset.action) {
            case 'show-qr':
                await showQR(peerId);
                break;
            case 'download-config':
                await downloadConfig(peerId);
                break;
            case 'edit-peer':
                await editPeer(peerId);
                break;
            case 'delete-peer':
                await deletePeer(peerId);
                break;
            default:
                break;
        }
    });

    document.getElementById('peer-allowed-ips-mode')?.addEventListener('change', () => toggleAllowedIpsCustom(''));
    document.getElementById('edit-peer-allowed-ips-mode')?.addEventListener('change', () => toggleAllowedIpsCustom('edit-'));
    document.getElementById('peer-use-adblocker')?.addEventListener('change', () => toggleBlocklistSection('peer-use-adblocker', 'peer-blocklist-section'));
    document.getElementById('edit-peer-use-adblocker')?.addEventListener('change', () => toggleBlocklistSection('edit-peer-use-adblocker', 'edit-peer-blocklist-section'));

    refreshPeerRows();
    toggleAllowedIpsCustom('');
    toggleAllowedIpsCustom('edit-');
    initTooltips(document);
    initNodePickers();
    initModalPollingGuards();
    bindAdminHandlers();
    filterPeers(searchInput?.value || '');
    startPeerStatsPolling(true);
}
