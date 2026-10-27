//
// app/static/js/theme.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Safe localStorage access for iOS/Safari privacy mode compatibility
function safeStorageGet(key) {
    try {
        return window.localStorage.getItem(key);
    } catch {
        return null;
    }
}

function safeStorageSet(key, value) {
    try {
        window.localStorage.setItem(key, value);
    } catch {
        // Ignore storage failures (private browsing, quota exceeded, etc.)
    }
}

// Theme management
//
// Three modes, cycled by the toggle button: auto (default, follows the OS/browser
// preference and reacts to its changes) -> light -> dark -> auto. The stored value is
// the mode; `data-bs-theme` on <html> always carries the resolved light/dark value,
// because Bootstrap, the charts and the map tiles key off that.
const THEME_MODES = ['auto', 'light', 'dark'];
const THEME_MODE_META = {
    auto: { icon: 'brightness_auto', label: 'Auto' },
    light: { icon: 'light_mode', label: 'Light' },
    dark: { icon: 'dark_mode', label: 'Dark' },
};
const themeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

function getThemeMode() {
    const stored = safeStorageGet('theme');
    return stored === 'dark' || stored === 'light' ? stored : 'auto';
}

function resolveTheme(mode) {
    if (mode === 'dark' || mode === 'light') return mode;
    return themeMediaQuery.matches ? 'dark' : 'light';
}

function updateThemeIcon(mode) {
    // Handling multiple possible icon IDs (Dashboard vs Login)
    const icons = [document.getElementById('theme-icon'), document.getElementById('theme-icon-login')];
    const meta = THEME_MODE_META[mode];
    const next = THEME_MODE_META[THEME_MODES[(THEME_MODES.indexOf(mode) + 1) % THEME_MODES.length]];
    icons.forEach(icon => {
        if (icon) {
            icon.textContent = meta.icon;
            const btn = icon.closest('button');
            if (btn) {
                btn.setAttribute('aria-label', `Theme: ${meta.label}. Switch to ${next.label}`);
                btn.setAttribute('title', `Theme: ${meta.label}`);
            }
        }
    });
}

function applyTheme(mode) {
    const root = document.documentElement;
    root.setAttribute('data-bs-theme', resolveTheme(mode));
    root.setAttribute('data-wb-theme-mode', mode);
}

function setTheme(mode) {
    const normalized = THEME_MODES.includes(mode) ? mode : 'auto';
    safeStorageSet('theme', normalized);
    applyTheme(normalized);
    updateThemeIcon(normalized);
}

function toggleTheme() {
    const current = getThemeMode();
    setTheme(THEME_MODES[(THEME_MODES.indexOf(current) + 1) % THEME_MODES.length]);
}

// Prevent FOUC: apply immediately (this script should run in <head>)
applyTheme(getThemeMode());

// In auto mode, follow OS theme changes while the page is open
const onSystemThemeChange = () => {
    if (getThemeMode() === 'auto') applyTheme('auto');
};
if (typeof themeMediaQuery.addEventListener === 'function') {
    themeMediaQuery.addEventListener('change', onSystemThemeChange);
} else if (typeof themeMediaQuery.addListener === 'function') {
    // Safari < 14
    themeMediaQuery.addListener(onSystemThemeChange);
}

// Update icons when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    updateThemeIcon(getThemeMode());

    // Attach event handlers without inline onclick (CSP-friendly)
    // Theme toggle buttons
    const themeToggles = document.querySelectorAll('[data-action="toggle-theme"]');
    themeToggles.forEach(btn => {
        btn.addEventListener('click', toggleTheme);
    });

    // Reload button on status page
    const reloadBtn = document.querySelector('[data-action="reload-page"]');
    if (reloadBtn) {
        reloadBtn.addEventListener('click', () => window.location.reload());
    }
});
