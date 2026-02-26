//
// app/static/js/theme.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Theme management
function getPreferredTheme() {
    const stored = localStorage.getItem('theme');
    if (stored) return stored;
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
    document.documentElement.setAttribute('data-bs-theme', theme);
    localStorage.setItem('theme', theme);
    updateThemeIcon(theme);
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
});
