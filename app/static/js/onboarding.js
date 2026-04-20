//
// app/static/js/onboarding.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

/* ── Onboarding Modal (Lazy-Loaded Fragment) ── */
(function () {
    const ONBOARDING_KEY = 'wb_onboarding_dismissed';
    const SESSION_KEY = 'wb_onboarding_shown';
    const MAX_SHOW_ATTEMPTS = 4;
    const MAX_DEFER_ATTEMPTS = 8;
    const DELAYS = {
        initialMs: 500,
        modalConflictMs: 700,
        safetyNetMs: 450,
        visibilityMs: 200,
    };
    let showAttempts = 0;
    let deferAttempts = 0;
    let showTimer = null;
    let safetyTimer = null;
    let pendingShowConfirmation = false;
    let modalFullyShown = false;
    let fragmentLoaded = false;

    function isDismissedOrShown() {
        return Boolean(localStorage.getItem(ONBOARDING_KEY) || sessionStorage.getItem(SESSION_KEY));
    }

    // Don't show if permanently dismissed or already shown this session
    if (isDismissedOrShown()) return;

    const mountPoint = document.getElementById('wbOnboardingMount');
    if (!mountPoint) return;

    if (typeof bootstrap === 'undefined' || !bootstrap.Modal) {
        console.warn('Onboarding: Bootstrap modal is not available');
        return;
    }

    function clearTimers() {
        clearTimeout(showTimer);
        clearTimeout(safetyTimer);
        showTimer = null;
        safetyTimer = null;
    }

    function shouldSkipOnboarding() {
        const onboardingEl = document.getElementById('wbOnboardingModal');
        return isDismissedOrShown()
            || (onboardingEl && onboardingEl.classList.contains('show'))
            || showAttempts >= MAX_SHOW_ATTEMPTS;
    }

    async function loadFragment() {
        if (fragmentLoaded) return true;
        
        try {
            const response = await fetch('/ui/fragments/onboarding');
            if (!response.ok) {
                console.warn('Onboarding: Failed to load fragment (HTTP ' + response.status + ')');
                return false;
            }
            const html = await response.text();
            mountPoint.innerHTML = html;
            fragmentLoaded = true;
            
            // Set up event listeners after fragment is loaded
            setupEventListeners();
            return true;
        } catch (err) {
            console.warn('Onboarding: Failed to fetch fragment:', err);
            return false;
        }
    }

    function setupEventListeners() {
        const onboardingEl = document.getElementById('wbOnboardingModal');
        if (!onboardingEl) return;

        const dismissCheckbox = document.getElementById('wbOnboardingDismiss');
        const onboardingModal = bootstrap.Modal.getOrCreateInstance(onboardingEl);

        onboardingEl.addEventListener('show.bs.modal', function () {
            document.body.classList.add('wb-onboarding');
        });

        onboardingEl.addEventListener('shown.bs.modal', function () {
            pendingShowConfirmation = false;
            modalFullyShown = true;
            deferAttempts = 0;
            // Mark only after it is actually visible
            sessionStorage.setItem(SESSION_KEY, '1');
        });

        onboardingEl.addEventListener('hidden.bs.modal', function () {
            modalFullyShown = false;
            pendingShowConfirmation = false;
            document.body.classList.remove('wb-onboarding');
            if (dismissCheckbox && dismissCheckbox.checked) {
                localStorage.setItem(ONBOARDING_KEY, '1');
            }
            // Clean up mount point after modal is closed to prevent duplicate fragments
            // on subsequent client-side navigations
            if (mountPoint) {
                mountPoint.innerHTML = '';
                fragmentLoaded = false;
            }
        });
    }

    function scheduleShow(delayMs, options = {}) {
        const skipIfPending = Boolean(options.skipIfPending);
        if (skipIfPending && showTimer) return;
        clearTimeout(showTimer);
        showTimer = setTimeout(function () {
            showTimer = null;
            tryShowOnboarding();
        }, delayMs);
    }

    async function tryShowOnboarding() {
        if (shouldSkipOnboarding()) return;

        // Load fragment if not already loaded
        if (!fragmentLoaded) {
            const loaded = await loadFragment();
            if (!loaded) return;
        }

        // Avoid showing onboarding on top of another modal.
        const otherOpenModal = document.querySelector('.modal.show:not(#wbOnboardingModal)');
        if (otherOpenModal) {
            if (deferAttempts < MAX_DEFER_ATTEMPTS) {
                deferAttempts++;
                scheduleShow(DELAYS.modalConflictMs);
            }
            return;
        }
        deferAttempts = 0;

        const onboardingEl = document.getElementById('wbOnboardingModal');
        if (!onboardingEl) return;

        const onboardingModal = bootstrap.Modal.getOrCreateInstance(onboardingEl);

        showAttempts++;
        pendingShowConfirmation = true;
        modalFullyShown = false;
        onboardingModal.show();

        // Mobile safety net: retry if Bootstrap did not display modal.
        clearTimeout(safetyTimer);
        safetyTimer = setTimeout(() => {
            safetyTimer = null;
            if (shouldSkipOnboarding()) {
                return;
            }

            // Bootstrap called show() but did not finish opening.
            if (pendingShowConfirmation && !modalFullyShown) {
                if (onboardingEl.classList.contains('show')) {
                    onboardingModal.hide();
                }
                scheduleShow(DELAYS.safetyNetMs, { skipIfPending: true });
            }
        }, DELAYS.safetyNetMs);
    }

    // Show after a short delay to let page render.
    scheduleShow(DELAYS.initialMs);

    // Retry once tab becomes visible again (mobile browser quirk).
    document.addEventListener('visibilitychange', function () {
        if (document.hidden) return;
        if (shouldSkipOnboarding()) return;
        scheduleShow(DELAYS.visibilityMs, { skipIfPending: true });
    });
})();
