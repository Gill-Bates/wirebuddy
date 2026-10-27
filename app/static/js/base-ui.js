//
// app/static/js/base-ui.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

document.addEventListener('DOMContentLoaded', function () {
    // Reconnect Failsafe Timeout
    // Note: This handles the case where page loads with wb-reconnecting class
    // (server-rendered during reconnect). For runtime reconnects, see reconnect.js.
    if (document.body.classList.contains('wb-reconnecting')) {
        setTimeout(() => {
            document.body.classList.remove('wb-reconnecting');
            const failsafeWrap = document.getElementById('wbReconnectFailsafeWrap');
            showElement(failsafeWrap);
        }, 15000);
    }

    // Reload button in reconnect modal
    const reloadBtn = document.getElementById('wbReconnectReload');
    if (reloadBtn) {
        reloadBtn.addEventListener('click', () => window.location.reload());
    }

    // Theme toggle
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', function () {
            if (typeof toggleTheme === 'function') {
                toggleTheme();
                return;
            }
            console.error('toggleTheme is unavailable \u2014 /static/js/theme.js failed to load.');
        });
    }

    // Logout
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function () {
            if (typeof logout === 'function') {
                logout();
                return;
            }
            console.error('logout is unavailable \u2014 /static/js/api.js failed to load.');
        });
    }

    // Mobile navbar: close menu when clicking a nav link
    const navbarCollapse = document.getElementById('navbarNav');
    if (navbarCollapse && window.bootstrap?.Collapse) {
        const mobileNavLinks = navbarCollapse.querySelectorAll('.navbar-mobile-grid a.nav-link');
        const bsCollapse = window.bootstrap.Collapse.getOrCreateInstance(navbarCollapse, { toggle: false });
        let _pendingNavUrl = null;

        // Single hidden.bs.collapse listener to handle navigation
        navbarCollapse.addEventListener('hidden.bs.collapse', () => {
            if (_pendingNavUrl) {
                window.location.assign(_pendingNavUrl);
                _pendingNavUrl = null;
            }
            navbarCollapse.classList.remove('wb-nav-closing');
        });

        navbarCollapse.addEventListener('show.bs.collapse', () => {
            navbarCollapse.classList.add('wb-nav-opening');
            navbarCollapse.classList.remove('wb-nav-closing');
            // Scroll to top only on mobile to ensure navbar is visible
            // Skip smooth behavior to avoid UX friction on quick navigation
            if (window.matchMedia('(max-width: 991.98px)').matches) {
                window.scrollTo({ top: 0, behavior: 'instant' });
            }
        });

        navbarCollapse.addEventListener('shown.bs.collapse', () => {
            navbarCollapse.classList.remove('wb-nav-opening');
        });

        navbarCollapse.addEventListener('hide.bs.collapse', () => {
            navbarCollapse.classList.add('wb-nav-closing');
            navbarCollapse.classList.remove('wb-nav-opening');
        });

        mobileNavLinks.forEach(link => {
            link.addEventListener('click', (event) => {
                if (!navbarCollapse.classList.contains('show')) {
                    return;
                }

                const href = link.getAttribute('href') || '';
                if (!href || href.startsWith('#')) {
                    bsCollapse.hide();
                    return;
                }

                event.preventDefault();
                _pendingNavUrl = href; // Use relative URL to avoid origin issues
                bsCollapse.hide();
            });
        });
    }

    const modalReturnFocus = new WeakMap();
    document.addEventListener('show.bs.modal', function (event) {
        const modal = event.target;
        if (!(modal instanceof HTMLElement) || modal.id === 'wbReconnectModal') return;

        const active = event.relatedTarget instanceof HTMLElement ? event.relatedTarget : document.activeElement;
        if (!(active instanceof HTMLElement) || active === document.body || modal.contains(active)) return;
        const dropdown = active.closest('.dropdown-menu')?.closest('.dropdown');
        const dropdownToggle = dropdown?.querySelector('[data-bs-toggle="dropdown"]');
        modalReturnFocus.set(modal, dropdownToggle || active);
    });

    // Blur before Bootstrap hides the modal, then restore the invoking control once hidden.
    document.addEventListener('hide.bs.modal', function (event) {
        const modal = event.target;
        if (document.activeElement === modal || modal.contains(document.activeElement)) {
            document.activeElement.blur();
        }
    }, true); // Use capture phase to ensure we run before Bootstrap

    document.addEventListener('hidden.bs.modal', function (event) {
        const modal = event.target;
        if (!(modal instanceof HTMLElement)) return;
        const target = modalReturnFocus.get(modal);
        modalReturnFocus.delete(modal);
        if (!target) return;

        const openModal = document.querySelector('.modal.show');
        if (openModal && !openModal.contains(target)) return;
        const canFocus = element => element instanceof HTMLElement && element.isConnected
            && !element.matches(':disabled') && element.getClientRects().length > 0;
        const fallbackRoot = openModal || document.querySelector('main') || document;
        const fallback = Array.from(fallbackRoot.querySelectorAll('button, a[href], input, select, textarea'))
            .find(canFocus);
        const returnTarget = canFocus(target) ? target : fallback;
        returnTarget?.focus({ preventScroll: true });
    });
});

