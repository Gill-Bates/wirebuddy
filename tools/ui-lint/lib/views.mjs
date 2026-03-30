//
// tools/ui-lint/lib/views.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { THEMES } from './constants.mjs';

export const LOGIN_FAILURE_VIEW_DEFS = [
    { name: 'login-error', url: '/login', scope: 'login' },
];

export const VIEW_DEFS = [
    { name: 'dashboard', url: '/ui/dashboard', scope: 'dashboard' },
    { name: 'peers', url: '/ui/peers', scope: 'peers' },
    { name: 'nodes', url: '/ui/nodes', scope: 'nodes' },
    { name: 'users', url: '/ui/users', scope: 'users' },
    { name: 'dns', url: '/ui/dns', scope: 'dns' },
    { name: 'traffic', url: '/ui/traffic', scope: 'traffic' },
    { name: 'status', url: '/status', scope: 'status' },
    { name: 'about', url: '/ui/about', scope: 'about' },
    { name: 'settings-general', url: '/ui/settings', scope: 'settings', tab: '#general-tab' },
    { name: 'settings-wireguard', url: '/ui/settings', scope: 'settings', tab: '#wireguard-tab' },
    { name: 'settings-dns', url: '/ui/settings', scope: 'settings', tab: '#dns-tab' },
    { name: 'settings-letsencrypt', url: '/ui/settings', scope: 'settings', tab: '#letsencrypt-tab' },
    { name: 'settings-logs', url: '/ui/settings', scope: 'settings', tab: '#logs-tab' },
    { name: 'settings-backup', url: '/ui/settings', scope: 'settings', tab: '#backup-tab' },
];

export function expandViewDefinitions(viewDefs) {
    return viewDefs.flatMap((def) =>
        THEMES.flatMap((theme) => [
            { ...def, name: `desktop-${def.name}-${theme}`, device: 'desktop', theme },
            { ...def, name: `large-desktop-${def.name}-${theme}`, device: 'large-desktop', theme },
            { ...def, name: `tablet-${def.name}-${theme}`, device: 'tablet', theme },
            { ...def, name: `mobile-${def.name}-${theme}`, device: 'mobile', theme },
        ])
    );
}

export const VIEWS = expandViewDefinitions(VIEW_DEFS);
export const LOGIN_FAILURE_VIEWS = expandViewDefinitions(LOGIN_FAILURE_VIEW_DEFS);
