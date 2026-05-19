//
// app/static/js/about.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

(function() {
    // -------------------- Update Check --------------------
    function parseVersionParts(version) {
        if (!version || typeof version !== 'string') return [0];
        const clean = version.trim().replace(/^v/i, '');
        const match = clean.match(/^(\d+(?:\.\d+)*)/);
        if (!match) return [0];
        return match[1].split('.').map((part) => Number.parseInt(part, 10) || 0);
    }

    function compareVersions(a, b) {
        const pa = parseVersionParts(a);
        const pb = parseVersionParts(b);
        const len = Math.max(pa.length, pb.length);
        for (let i = 0; i < len; i += 1) {
            const va = pa[i] || 0;
            const vb = pb[i] || 0;
            if (va > vb) return 1;
            if (va < vb) return -1;
        }
        return 0;
    }

    async function checkForUpdates(force = false, isManualCheck = false) {
        const loadingEl = document.getElementById('update-check-loading');
        const resultEl = document.getElementById('update-check-result');
        const statusBadge = document.getElementById('update-status-badge');
        const currentVersionEl = document.getElementById('update-current-version');
        const latestVersionEl = document.getElementById('update-latest-version');
        const publishedRow = document.getElementById('update-published-row');
        const publishedAtEl = document.getElementById('update-published-at');
        const errorEl = document.getElementById('update-error');
        const errorTextEl = document.getElementById('update-error-text');
        const availableSectionEl = document.getElementById('update-available-section');
        const releaseLinkEl = document.getElementById('update-release-link');
        const checkBtn = document.getElementById('btn-check-updates');

        // Show loading state
        loadingEl.classList.remove('d-none');
        resultEl.classList.add('d-none');
        if (checkBtn) checkBtn.disabled = true;

        try {
            const url = force 
                ? '/api/wireguard/settings/check-updates?force=true'
                : '/api/wireguard/settings/check-updates';
            const res = await api('GET', url, null, { timeoutMs: 15000 });
            
            // Hide loading, show result
            loadingEl.classList.add('d-none');
            resultEl.classList.remove('d-none');
            
            // Populate version info
            currentVersionEl.textContent = res.current_version || '–';
            latestVersionEl.textContent = res.latest_version || '–';
            
            // Show published date if available
            if (res.published_at) {
                publishedRow.classList.remove('d-none');
                const pubDate = new Date(res.published_at);
                publishedAtEl.textContent = pubDate.toLocaleDateString(undefined, {
                    year: 'numeric', month: 'short', day: 'numeric'
                });
            } else {
                publishedRow.classList.add('d-none');
            }
            
            // Status badge
            const currentVersion = res.current_version || '';
            const latestVersion = res.latest_version || '';
            const currentIsHigher = latestVersion && compareVersions(currentVersion, latestVersion) > 0;

            if (currentIsHigher) {
                setUpdateStatusBadge(
                    statusBadge,
                    'warning',
                    'warning_amber',
                    null,
                    'You are currently using a pre-release. This is not recommended for production!'
                );
                availableSectionEl.classList.add('d-none');
            } else if (res.update_available) {
                setUpdateStatusBadge(
                    statusBadge,
                    'success',
                    'new_releases',
                    'Update available!',
                    `Version ${latestVersion || '–'} is ready.`
                );
                // Show release link
                availableSectionEl.classList.remove('d-none');
                if (res.release_url) {
                    releaseLinkEl.href = res.release_url;
                }
            } else {
                setUpdateStatusBadge(
                    statusBadge,
                    'secondary',
                    'check_circle',
                    null,
                    "You're running the latest version."
                );
                availableSectionEl.classList.add('d-none');
            }
            
            // Show error if any (but only for manual checks or critical errors)
            if (res.error) {
                // Filter out non-critical network errors on auto-check
                const isNetworkError = res.error.includes('Network error') || 
                                      res.error.includes('Connection timeout') ||
                                      res.error.includes('No address associated');
                
                if (isManualCheck || !isNetworkError) {
                    errorEl.classList.remove('d-none');
                    errorTextEl.textContent = res.error;
                } else {
                    errorEl.classList.add('d-none');
                    // Silently log for debugging but don't show to user
                }
            } else {
                errorEl.classList.add('d-none');
            }
            
        } catch (error) {
            loadingEl.classList.add('d-none');
            resultEl.classList.remove('d-none');
            statusBadge.replaceChildren();
            
            // Only show fetch errors on manual check
            if (isManualCheck) {
                errorEl.classList.remove('d-none');
                errorTextEl.textContent = 'Failed to check for updates: ' + (error.message || error);
            } else {
                errorEl.classList.add('d-none');
            }
        } finally {
            if (checkBtn) checkBtn.disabled = false;
        }
    }

    function setUpdateStatusBadge(container, type, icon, leadText, tailText) {
        if (!container) return;
        container.replaceChildren();
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} py-1 mb-0 small`;

        const iconEl = document.createElement('span');
        iconEl.className = 'material-icons align-middle me-1';
        iconEl.style.fontSize = '16px';
        iconEl.textContent = icon;
        alert.appendChild(iconEl);

        if (leadText) {
            const strong = document.createElement('strong');
            strong.textContent = leadText;
            alert.appendChild(strong);
            if (tailText) alert.appendChild(document.createTextNode(` ${tailText}`));
        } else if (tailText) {
            alert.appendChild(document.createTextNode(tailText));
        }

        container.appendChild(alert);
    }

    function initChangelogDetailsScroll() {
        document.querySelectorAll('.changelog-content details').forEach((details) => {
            const summary = details.querySelector('summary');
            if (!summary) return;

            let body = details.querySelector('.changelog-details-body');
            if (!body) {
                body = document.createElement('div');
                body.className = 'changelog-details-body';

                let node = summary.nextSibling;
                while (node) {
                    const next = node.nextSibling;
                    body.appendChild(node);
                    node = next;
                }

                if (body.childNodes.length) {
                    details.appendChild(body);
                }
            }

            details.addEventListener('toggle', () => {
                if (details.open && body) {
                    body.scrollTop = 0;
                }
            });
        });
    }

    // Initialize
    const checkBtn = document.getElementById('btn-check-updates');
    const isAdmin = checkBtn?.dataset?.isAdmin === 'true';
    checkBtn?.addEventListener('click', () => checkForUpdates(isAdmin, true));
    initChangelogDetailsScroll();
    
    // Auto-check on page load (silent network errors)
    checkForUpdates(false, false);
})();
