        document.addEventListener('DOMContentLoaded', function() {
            // Reconnect Failsafe Timeout
            // Note: This handles the case where page loads with wb-reconnecting class
            // (server-rendered during reconnect). For runtime reconnects, see reconnect.js.
            if (document.body.classList.contains('wb-reconnecting')) {
                setTimeout(() => {
                    document.body.classList.remove('wb-reconnecting');
                    const failsafeWrap = document.getElementById('wbReconnectFailsafeWrap');
                    if (failsafeWrap) failsafeWrap.classList.remove('d-none');
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
                themeToggle.addEventListener('click', function() {
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
                logoutBtn.addEventListener('click', function() {
                    if (typeof logout === 'function') {
                        logout();
                        return;
                    }
                    console.error('logout is unavailable \u2014 /static/js/api.js failed to load.');
                });
            }

            // Mobile navbar: close menu when clicking a nav link
            const navbarCollapse = document.getElementById('navbarNav');
            if (navbarCollapse) {
                const mobileNavLinks = navbarCollapse.querySelectorAll('.navbar-mobile-grid a.nav-link');
                const bsCollapse = bootstrap.Collapse.getOrCreateInstance(navbarCollapse, { toggle: false });
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

            // Bootstrap Modal Accessibility Fix
            // Prevents ARIA warning when modal or its descendants have focus during hide
            // Use event delegation on document to catch all modals (including dynamic ones)
            document.addEventListener('hide.bs.modal', function(event) {
                const modal = event.target;
                // If focus is on the modal itself or inside it, blur it
                if (document.activeElement === modal || modal.contains(document.activeElement)) {
                    document.activeElement.blur();
                }
            }, true); // Use capture phase to ensure we run before Bootstrap
        });
    
