//
// tools/ui-lint/lib/view-orchestration/catalog.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { THEMES } from '../config/themes/themes.mjs';

export const VIEW_RUNTIME_VERSION = '2026.05';

const DEVICE_ORDER = Object.freeze(['desktop', 'large-desktop', 'tablet', 'mobile']);
const LOGIN_DEVICE_ORDER = Object.freeze(['desktop', 'mobile']);
const DEFAULT_EXECUTION_MODES = Object.freeze(['smoke', 'regression', 'accessibility', 'mobile-only']);
const DEFAULT_THEME_COVERAGE = Object.freeze({
    light: 'required',
    dark: 'critical',
    highContrast: 'required',
});
const DEFAULT_DEVICE_COVERAGE = Object.freeze({
    desktop: true,
    'large-desktop': true,
    tablet: true,
    mobile: true,
});

function freezeShallow(value) {
    return Object.freeze({ ...value });
}

function createViewDefinition(definition) {
    const family = definition.family || definition.scope;

    return Object.freeze({
        id: definition.id,
        name: definition.name,
        family,
        url: definition.url,
        scope: definition.scope,
        tab: definition.tab || null,
        description: definition.description || null,
        executionModes: Object.freeze([...new Set(definition.executionModes || DEFAULT_EXECUTION_MODES)]),
        coverage: freezeShallow(definition.coverage || DEFAULT_DEVICE_COVERAGE),
        themeCoverage: freezeShallow(definition.themeCoverage || DEFAULT_THEME_COVERAGE),
        requires: freezeShallow(definition.requires || {}),
        browserPolicies: freezeShallow(definition.browserPolicies || {}),
        metadata: freezeShallow({
            owner: 'ui-team',
            introducedIn: VIEW_RUNTIME_VERSION,
            ...definition.metadata,
        }),
        auth: freezeShallow({
            required: true,
            strategy: 'session',
            ...definition.auth,
        }),
        navigation: freezeShallow({
            waitUntil: 'networkidle',
            timeout: 15_000,
            ...definition.navigation,
        }),
        heuristics: freezeShallow({
            flaky: false,
            heavyDom: false,
            ...definition.heuristics,
        }),
        retryPolicy: freezeShallow({
            maxRetries: 3,
            backoff: 'linear',
            ...definition.retryPolicy,
        }),
        estimatedRuntimeMs: definition.estimatedRuntimeMs || 750,
        snapshots: freezeShallow({
            fullPage: true,
            stablePair: true,
            ...definition.snapshots,
        }),
        resourceBudget: freezeShallow({
            memoryMb: 512,
            ...definition.resourceBudget,
        }),
        requiredFeatures: Object.freeze([...(definition.requiredFeatures || [])]),
        preconditions: Object.freeze([...(definition.preconditions || [])]),
        cleanup: freezeShallow({
            resetFilters: true,
            ...definition.cleanup,
        }),
        tags: Object.freeze([...(definition.tags || [])]),
        isolation: freezeShallow({
            retryIndependently: true,
            ...definition.isolation,
        }),
        criticalPath: Boolean(definition.criticalPath),
        risk: definition.risk || 'medium',
        priority: definition.priority ?? 50,
        performanceProfile: definition.performanceProfile || 'medium',
        failureCategory: definition.failureCategory || 'layout',
        dependsOn: Object.freeze([...(definition.dependsOn || [])]),
        environments: Object.freeze([...(definition.environments || ['ci', 'nightly', 'local'])]),
        condition: definition.condition || null,
        skipIf: definition.skipIf || null,
        parallelGroup: definition.parallelGroup || family,
    });
}

function createDashboardDefinitions() {
    return [
        createViewDefinition({
            id: 'dashboard-main',
            name: 'dashboard',
            family: 'dashboard',
            url: '/ui/dashboard',
            scope: 'dashboard',
            risk: 'critical',
            priority: 100,
            criticalPath: true,
            executionModes: ['smoke', 'regression', 'accessibility'],
            dependsOn: ['auth-session', 'seed-data-loaded'],
            requiredFeatures: ['dashboard-ui-v2'],
            preconditions: ['userLoggedIn', 'seedDataLoaded'],
            tags: ['critical-path', 'heavy-dom', 'layout-sensitive'],
            browserPolicies: { webkit: { retries: 2 } },
            heuristics: { heavyDom: true, flaky: false },
            retryPolicy: { maxRetries: 2, backoff: 'linear' },
            estimatedRuntimeMs: 1400,
            resourceBudget: { memoryMb: 768 },
            failureCategory: 'rendering',
            performanceProfile: 'heavy',
            metadata: { owner: 'ui-team', introducedIn: VIEW_RUNTIME_VERSION },
            condition: (ctx) => ctx.features?.dashboardEnabled !== false,
        }),
        createViewDefinition({
            id: 'peers-main',
            name: 'peers',
            family: 'peers',
            url: '/ui/peers',
            scope: 'peers',
            risk: 'medium',
            priority: 80,
            dependsOn: ['auth-session'],
            tags: ['network-heavy'],
            heuristics: { heavyDom: false, flaky: false },
            estimatedRuntimeMs: 1100,
            failureCategory: 'network',
            performanceProfile: 'medium',
            condition: (ctx) => ctx.features?.peersEnabled !== false,
        }),
        createViewDefinition({
            id: 'nodes-main',
            name: 'nodes',
            family: 'nodes',
            url: '/ui/nodes',
            scope: 'nodes',
            risk: 'critical',
            priority: 92,
            criticalPath: true,
            dependsOn: ['auth-session', 'seed-data-loaded'],
            tags: ['network-heavy', 'scroll-sensitive'],
            heuristics: { heavyDom: true, flaky: false },
            estimatedRuntimeMs: 1300,
            failureCategory: 'layout',
            performanceProfile: 'heavy',
            preconditions: ['seedDataLoaded'],
            condition: (ctx) => ctx.features?.nodesEnabled !== false,
        }),
        createViewDefinition({
            id: 'users-main',
            name: 'users',
            family: 'users',
            url: '/ui/users',
            scope: 'users',
            risk: 'medium',
            priority: 72,
            dependsOn: ['auth-session'],
            tags: ['admin', 'table-heavy'],
            estimatedRuntimeMs: 1000,
            failureCategory: 'auth',
            performanceProfile: 'medium',
            condition: (ctx) => ctx.features?.usersEnabled !== false,
        }),
        createViewDefinition({
            id: 'dns-main',
            name: 'dns',
            family: 'dns',
            url: '/ui/dns',
            scope: 'dns',
            risk: 'critical',
            priority: 95,
            criticalPath: true,
            dependsOn: ['auth-session', 'dns-loaded'],
            requiredFeatures: ['dns-ui-v2'],
            tags: ['network-heavy', 'critical-path'],
            heuristics: { heavyDom: false, flaky: true },
            retryPolicy: { maxRetries: 3, backoff: 'linear' },
            estimatedRuntimeMs: 1250,
            failureCategory: 'network',
            performanceProfile: 'heavy',
            condition: (ctx) => ctx.features?.dnsEnabled !== false,
        }),
        createViewDefinition({
            id: 'traffic-main',
            name: 'traffic',
            family: 'traffic',
            url: '/ui/traffic',
            scope: 'traffic',
            risk: 'medium',
            priority: 84,
            criticalPath: true,
            dependsOn: ['dashboard-main'],
            tags: ['network-heavy', 'analytics', 'scroll-sensitive'],
            heuristics: { heavyDom: true, flaky: false },
            estimatedRuntimeMs: 1500,
            failureCategory: 'network',
            performanceProfile: 'heavy',
            condition: (ctx) => ctx.features?.trafficEnabled !== false,
        }),
        createViewDefinition({
            id: 'status-main',
            name: 'status',
            family: 'status',
            url: '/status',
            scope: 'status',
            risk: 'low',
            priority: 60,
            criticalPath: true,
            dependsOn: ['auth-session'],
            tags: ['health', 'smoke'],
            estimatedRuntimeMs: 500,
            failureCategory: 'layout',
            performanceProfile: 'light',
            condition: (ctx) => ctx.features?.statusEnabled !== false,
        }),
        createViewDefinition({
            id: 'about-main',
            name: 'about',
            family: 'about',
            url: '/ui/about',
            scope: 'about',
            risk: 'low',
            priority: 20,
            tags: ['static', 'documentation'],
            auth: { required: false, strategy: 'anonymous' },
            estimatedRuntimeMs: 300,
            failureCategory: 'layout',
            performanceProfile: 'light',
            condition: (ctx) => ctx.features?.aboutEnabled !== false,
        }),
    ];
}

function createSettingsDefinitions() {
    const shared = {
        family: 'settings',
        url: '/ui/settings',
        scope: 'settings',
        risk: 'medium',
        priority: 66,
        criticalPath: false,
        dependsOn: ['auth-session', 'settings-general-main'],
        tags: ['settings', 'stateful'],
        heuristics: { heavyDom: false, flaky: false },
        estimatedRuntimeMs: 900,
        failureCategory: 'layout',
        performanceProfile: 'medium',
        preconditions: ['userLoggedIn'],
        condition: (ctx) => ctx.features?.settingsEnabled !== false,
    };

    return [
        createViewDefinition({
            id: 'settings-general-main',
            name: 'settings-general',
            tab: '#general-tab',
            ...shared,
            dependsOn: ['auth-session'],
            priority: 70,
            tags: ['settings', 'critical-path'],
        }),
        createViewDefinition({
            id: 'settings-wireguard-main',
            name: 'settings-wireguard',
            tab: '#wireguard-tab',
            ...shared,
            dependsOn: ['settings-general-main'],
            tags: ['settings', 'wireguard'],
            requiredFeatures: ['wireguard-ui-v2'],
            estimatedRuntimeMs: 950,
        }),
        createViewDefinition({
            id: 'settings-dns-main',
            name: 'settings-dns',
            tab: '#dns-tab',
            ...shared,
            dependsOn: ['settings-general-main', 'dns-main'],
            tags: ['settings', 'dns'],
            requiredFeatures: ['dns-ui-v2'],
            estimatedRuntimeMs: 980,
            condition: (ctx) => ctx.features?.settingsDnsEnabled !== false && ctx.features?.dnsEnabled !== false,
        }),
        createViewDefinition({
            id: 'settings-letsencrypt-main',
            name: 'settings-letsencrypt',
            tab: '#letsencrypt-tab',
            ...shared,
            dependsOn: ['settings-general-main'],
            tags: ['settings', 'tls'],
            requiredFeatures: ['acme-ui-v2'],
            estimatedRuntimeMs: 920,
        }),
        createViewDefinition({
            id: 'settings-logs-main',
            name: 'settings-logs',
            tab: '#logs-tab',
            ...shared,
            dependsOn: ['settings-general-main'],
            tags: ['settings', 'logs'],
            estimatedRuntimeMs: 840,
        }),
        createViewDefinition({
            id: 'settings-backup-main',
            name: 'settings-backup',
            tab: '#backup-tab',
            ...shared,
            dependsOn: ['settings-general-main'],
            tags: ['settings', 'backup'],
            requiredFeatures: ['backup-ui-v2'],
            estimatedRuntimeMs: 960,
        }),
    ];
}

function createLoginFailureDefinitions() {
    return [
        createViewDefinition({
            id: 'login-error-main',
            name: 'login-error',
            family: 'auth',
            url: '/login',
            scope: 'login',
            risk: 'critical',
            priority: 100,
            criticalPath: true,
            coverage: { desktop: true, 'large-desktop': false, tablet: false, mobile: true },
            themeCoverage: {
                light: 'required',
                dark: 'required',
                highContrast: 'required',
            },
            dependsOn: ['auth-session'],
            auth: { required: true, strategy: 'session' },
            tags: ['auth', 'security', 'retry-sensitive'],
            heuristics: { heavyDom: false, flaky: true },
            retryPolicy: { maxRetries: 3, backoff: 'linear' },
            estimatedRuntimeMs: 400,
            failureCategory: 'auth',
            performanceProfile: 'light',
            preconditions: ['userLoggedOut'],
            condition: (ctx) => ctx.features?.loginEnabled !== false,
        }),
    ];
}

export const VIEW_DEFS = Object.freeze([...createDashboardDefinitions(), ...createSettingsDefinitions()]);
export const LOGIN_FAILURE_VIEW_DEFS = Object.freeze([...createLoginFailureDefinitions()]);

export const VIEW_FAMILIES = Object.freeze([...new Set([...VIEW_DEFS, ...LOGIN_FAILURE_VIEW_DEFS].map((definition) => definition.family))]);

export {
    DEVICE_ORDER,
    DEFAULT_DEVICE_COVERAGE,
    DEFAULT_EXECUTION_MODES,
    DEFAULT_THEME_COVERAGE,
    LOGIN_DEVICE_ORDER,
    THEMES,
};
