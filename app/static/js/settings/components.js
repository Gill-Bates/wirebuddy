//
// app/static/js/settings/components.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Reusable UI components for settings pages using el() builder.
// Replaces HTML string concatenation with XSS-safe DOM construction.
//

(function () {
    'use strict';

    const { el } = window.WB?.dom || window.WBDom || {};
    if (!el) {
        console.error('[SettingsComponents] WB.dom not available');
        return;
    }

    const BLOCKED_DATA_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

    function sanitizeDataset(data) {
        if (!data || typeof data !== 'object') {
            return undefined;
        }

        const sanitized = {};
        for (const [key, value] of Object.entries(data)) {
            if (BLOCKED_DATA_KEYS.has(key) || value == null) {
                continue;
            }
            sanitized[key] = String(value);
        }

        return Object.keys(sanitized).length ? sanitized : undefined;
    }

    function stableDomId(value) {
        const encoded = new TextEncoder().encode(String(value ?? ''));
        let binary = '';

        for (const byte of encoded) {
            binary += String.fromCharCode(byte);
        }

        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');
    }

    /**
     * Create a badge element.
     * @param {string} text - Badge text
     * @param {string} variant - Bootstrap variant (success, danger, warning, secondary, etc.)
     * @param {Object} [options] - Additional options
     * @param {boolean} [options.textDark] - Use dark text (for warning badges)
     * @returns {HTMLElement}
     */
    function badge(text, variant, options = {}) {
        const classes = ['badge', `bg-${variant}`];
        if (options.textDark) classes.push('text-dark');
        if (options.className) classes.push(options.className);
        if (options.class) classes.push(options.class);
        return el('span', { class: classes.join(' '), text });
    }

    /**
     * Create a Material icon element.
     * @param {string} name - Icon name
     * @param {Object} [options] - Additional options
     * @param {string} [options.class] - Additional CSS classes
     * @param {string} [options.size] - Font size (e.g., '18px')
     * @returns {HTMLElement}
     */
    function icon(name, options = {}) {
        const classes = ['material-icons', 'align-middle'];
        if (options.className) classes.push(options.className);
        if (options.class) classes.push(options.class);
        if (options.size) {
            const sizeClass = {
                '14px': 'icon-xs',
                '16px': 'icon-sm',
                '18px': 'icon-md',
                '24px': 'icon-lg',
                '32px': 'icon-xl',
                '48px': 'icon-xxl',
            }[options.size];
            if (sizeClass) classes.push(sizeClass);
        }
        return el('span', {
            class: classes.join(' '),
            text: name,
            attrs: {
                'aria-hidden': 'true',
            },
        });
    }

    /**
     * Create an action button with icon.
     * @param {Object} opts - Button options
     * @param {string} opts.icon - Material icon name
     * @param {string} opts.variant - Bootstrap outline variant
     * @param {string} opts.title - Button title/tooltip
     * @param {string} [opts.ariaLabel] - Aria label (defaults to title)
     * @param {boolean} [opts.disabled] - Disabled state
     * @param {Object} [opts.data] - Data attributes
     * @param {string} [opts.class] - Additional CSS classes
     * @param {Function} [opts.onClick] - Click handler
     * @returns {HTMLElement}
     */
    function actionButton(opts) {
        const classes = ['btn', 'btn-sm', `btn-outline-${opts.variant}`, 'text-nowrap'];
        if (opts.className) classes.push(opts.className);
        if (opts.class) classes.push(opts.class);

        const attrs = {
            title: opts.title,
            'aria-label': opts.ariaLabel || opts.title,
        };

        if (opts.disabled) {
            attrs.disabled = true;
        }

        return el('button', {
            class: classes.join(' '),
            attrs,
            data: sanitizeDataset(opts.data),
            on: opts.onClick ? { click: opts.onClick } : undefined,
            children: [icon(opts.icon, { class: 'icon-md' })],
        });
    }

    /**
     * Create interface action buttons group.
     * @param {string} ifaceName - Interface name
     * @param {Object} state - Button states
     * @param {boolean} state.isAdmin - User is admin
     * @param {boolean} state.isActive - Interface is active
     * @param {boolean} state.isConfigured - Interface has config
     * @returns {HTMLElement}
     */
    function interfaceActionButtons(ifaceName, state) {
        const { isAdmin, isActive, isConfigured } = state;
        const children = [];

        // Start button
        children.push(actionButton({
            icon: 'play_arrow',
            variant: 'success',
            title: isAdmin ? 'Start' : 'Admin privileges required',
            class: 'iface-action-btn',
            disabled: !isAdmin || isActive,
            data: { iface: ifaceName, action: 'up' },
        }));

        // Stop button
        children.push(actionButton({
            icon: 'stop',
            variant: 'danger',
            title: isAdmin ? 'Stop' : 'Admin privileges required',
            class: 'iface-action-btn',
            disabled: !isAdmin || !isActive,
            data: { iface: ifaceName, action: 'down' },
        }));

        // Restart button
        children.push(actionButton({
            icon: 'restart_alt',
            variant: 'warning',
            title: isAdmin ? 'Restart' : 'Admin privileges required',
            class: 'iface-action-btn',
            disabled: !isAdmin || !isActive,
            data: { iface: ifaceName, action: 'restart' },
        }));

        // Edit button (admin + configured only)
        if (isAdmin && isConfigured) {
            children.push(actionButton({
                icon: 'edit',
                variant: 'secondary',
                title: 'Edit',
                class: 'iface-edit-btn',
                data: { iface: ifaceName },
            }));
        }

        // Delete button (admin only)
        if (isAdmin) {
            children.push(actionButton({
                icon: 'delete',
                variant: 'danger',
                title: 'Delete',
                class: 'iface-delete-btn',
                disabled: isActive,
                data: { iface: ifaceName },
            }));
        }

        return el('div', {
            class: 'settings-interface-actions',
            children,
        });
    }

    /**
     * Create an interface row element.
     * @param {Object} iface - Interface data
     * @param {boolean} isAdmin - User is admin
     * @returns {HTMLElement}
     */
    function interfaceRow(iface, isAdmin) {
        const statusBadge = badge(
            iface.is_active ? 'Active' : 'Inactive',
            iface.is_active ? 'success' : 'secondary'
        );

        const isConfigured = !!(iface.is_configured ?? (iface.in_database || iface.has_config_file));

        return el('div', {
            class: 'settings-interface-row',
            children: [
                el('div', {
                    children: [
                        el('strong', { text: iface.name }),
                        el('span', { class: 'ms-2', children: [statusBadge] }),
                    ],
                }),
                interfaceActionButtons(iface.name, {
                    isAdmin,
                    isActive: !!iface.is_active,
                    isConfigured,
                }),
            ],
        });
    }

    /**
     * Create a certificate row element.
     * @param {Object} cert - Certificate data
     * @returns {HTMLElement}
     */
    function certificateRow(cert) {
        const isExpired = cert.days_until_expiry !== null && cert.days_until_expiry < 0;
        const needsRenewal = cert.needs_renewal && !isExpired;

        // Status badge
        let statusBadge;
        if (isExpired) {
            statusBadge = badge('Expired', 'danger');
        } else if (needsRenewal) {
            statusBadge = badge('Renew', 'warning', { textDark: true });
        } else {
            statusBadge = badge('Valid', 'success');
        }

        // Staging badge
        const stagingBadge = cert.is_staging
            ? badge('Staging', 'warning', { textDark: true, class: 'ms-1' })
            : null;

        // Expiry info
        const expiresDate = cert.expires_at ? new Date(cert.expires_at) : null;
        const expiresStr = expiresDate
            ? expiresDate.toLocaleDateString('en-GB', {
                timeZone: 'UTC',
                year: 'numeric',
                month: 'short',
                day: '2-digit',
            })
            : 'Unknown';
        const daysStr = cert.days_until_expiry !== null ? ` (${cert.days_until_expiry}d)` : '';

        // Action buttons
        const actions = [];
        if (needsRenewal) {
            actions.push(actionButton({
                icon: 'refresh',
                variant: 'warning',
                title: 'Renew',
                class: 'cert-renew-btn',
                data: { domain: cert.domain, staging: String(!!cert.is_staging) },
            }));
        }
        actions.push(actionButton({
            icon: 'delete',
            variant: 'danger',
            title: 'Delete',
            class: 'cert-delete-btn',
            data: { domain: cert.domain, staging: String(!!cert.is_staging) },
        }));

        const badgeChildren = [statusBadge];
        if (stagingBadge) badgeChildren.push(stagingBadge);

        return el('div', {
            class: 'd-flex justify-content-between align-items-center py-2 border-bottom',
            children: [
                el('div', {
                    children: [
                        el('strong', { text: cert.domain }),
                        ...badgeChildren,
                        el('br'),
                        el('small', {
                            class: 'text-muted',
                            text: `Expires: ${expiresStr}${daysStr} • Issuer: ${cert.issuer || 'Unknown'}`,
                        }),
                    ],
                }),
                el('div', { class: 'd-flex gap-1', children: actions }),
            ],
        });
    }

    /**
     * Create a blocklist item element.
     * @param {Object} source - Blocklist source data
     * @param {number} index - Source index
     * @param {Object} state - Render state
     * @param {boolean} state.rebuildInProgress - Rebuild in progress
     * @param {boolean} state.isAdmin - User is admin
     * @param {boolean} state.dnsUnavailable - DNS unavailable
     * @returns {HTMLElement}
     */
    function blocklistItem(source, index, state) {
        const { rebuildInProgress, isAdmin, dnsUnavailable } = state;
        const domainsValue = source.domains;
        const isPending = source.enabled && rebuildInProgress && Number(domainsValue) === 0;

        const domains = isPending
            ? 'Pending'
            : (Number.isFinite(Number(domainsValue))
                ? Number(domainsValue).toLocaleString()
                : (String(domainsValue ?? '').trim() || '—'));

        const updated = source.last_updated || '—';
        const level = source.level || '';

        // Level badge mapping
        const levelLabels = {
            'Moderat': 'Moderate',
            'Ausgewogen': 'Balanced',
            'Extrem': '🔥Extreme',
            '18+': '❤️ 18+',
        };
        const levelLabel = levelLabels[level] || level || '';

        // Unique ID for checkbox
        const sourceKey = `${String(source.url ?? '').trim()}|${String(source.name ?? '').trim()}|${index}`;
        const sourceId = `blocklist-${stableDomId(sourceKey)}`;

        const titleChildren = [el('span', { text: source.name })];
        if (levelLabel) {
            titleChildren.push(badge(levelLabel, 'secondary', { class: 'blocklist-level-badge' }));
        }

        return el('article', {
            class: `blocklist-item${source.enabled ? ' enabled' : ''}`,
            children: [
                el('div', {
                    class: 'blocklist-row',
                    children: [
                        el('div', {
                            class: 'flex-grow-1',
                            children: [
                                el('label', {
                                    class: 'blocklist-title',
                                    attrs: { for: sourceId },
                                    children: titleChildren,
                                }),
                                el('div', { class: 'blocklist-desc', text: source.description }),
                                el('div', {
                                    class: 'blocklist-meta',
                                    children: [
                                        el('span', { class: 'blocklist-meta-mono', text: `${domains} domains` }),
                                        el('span', {
                                            class: 'blocklist-meta-separator',
                                            attrs: { 'aria-hidden': 'true' },
                                            text: '·',
                                        }),
                                        el('span', { class: 'blocklist-meta-mono', text: `Updated ${updated}` }),
                                    ],
                                }),
                            ],
                        }),
                        el('div', {
                            class: 'form-check form-switch m-0',
                            children: [
                                (() => {
                                    const checkboxAttrs = {
                                        type: 'checkbox',
                                        id: sourceId,
                                    };

                                    if (source.enabled) {
                                        checkboxAttrs.checked = true;
                                    }

                                    if (!isAdmin || dnsUnavailable) {
                                        checkboxAttrs.disabled = true;
                                    }

                                    return el('input', {
                                        class: 'form-check-input',
                                        attrs: checkboxAttrs,
                                        data: sanitizeDataset({ url: source.url, name: source.name }),
                                    });
                                })(),
                            ],
                        }),
                    ],
                }),
            ],
        });
    }

    /**
     * Create an empty state message.
     * @param {string} message - Message text
     * @param {string} [variant] - Text color variant (muted, danger)
     * @returns {HTMLElement}
     */
    function emptyState(message, variant = 'muted') {
        return el('p', {
            class: `text-${variant} mb-0`,
            text: message,
        });
    }

    /**
     * Create a spinner with text.
     * @param {string} text - Loading text
     * @returns {HTMLElement}
     */
    function spinner(text) {
        return el('span', {
            children: [
                el('span', {
                    class: 'spinner-border spinner-border-sm align-middle me-1',
                    attrs: { role: 'status' },
                }),
                text,
            ],
        });
    }

    /**
     * Create a status indicator with icon and text.
     * @param {Object} opts - Options
     * @param {string} opts.icon - Material icon name
     * @param {string} opts.text - Status text
     * @param {string} opts.variant - Bootstrap color variant
     * @returns {HTMLElement}
     */
    function statusIndicator(opts) {
        return el('span', {
            children: [
                icon(opts.icon, { class: `text-${opts.variant} icon-sm` }),
                ' ' + opts.text,
            ],
        });
    }

    // Export
    window.WB = window.WB || {};
    window.WB.settingsComponents = {
        badge,
        icon,
        actionButton,
        interfaceRow,
        interfaceActionButtons,
        certificateRow,
        blocklistItem,
        emptyState,
        spinner,
        statusIndicator,
    };

})();
