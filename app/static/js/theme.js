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
function getPreferredTheme() {
    const stored = safeStorageGet('theme');
    if (stored === 'dark' || stored === 'light') return stored;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function updateThemeIcon(theme) {
    // Handling multiple possible icon IDs (Dashboard vs Login)
    const icons = [document.getElementById('theme-icon'), document.getElementById('theme-icon-login')];
    icons.forEach(icon => {
        if (icon) {
            icon.textContent = theme === 'dark' ? 'light_mode' : 'dark_mode';
            const btn = icon.closest('button');
            if (btn) {
                btn.setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`);
            }
        }
    });
}

function setTheme(theme) {
    const normalized = theme === 'dark' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-bs-theme', normalized);
    safeStorageSet('theme', normalized);
    updateThemeIcon(normalized);
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-bs-theme');
    setTheme(current === 'dark' ? 'light' : 'dark');
}

// Prevent FOUC: apply immediately (this script should run in <head>)
const initialTheme = getPreferredTheme();
document.documentElement.setAttribute('data-bs-theme', initialTheme);

// Update icons when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    updateThemeIcon(initialTheme);

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
