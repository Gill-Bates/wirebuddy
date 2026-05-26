//
// app/static/js/onboarding.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

/* ── Onboarding Modal (Lazy-Loaded Fragment) ── */
(function () {
    const ONBOARDING_VERSION = 'v2';
    const ONBOARDING_KEY = 'wb_onboarding_dismissed_' + ONBOARDING_VERSION;
    const SESSION_KEY = 'wb_onboarding_shown_' + ONBOARDING_VERSION;
    const MAX_SHOW_ATTEMPTS = 4;
    const MAX_DEFER_ATTEMPTS = 8;
    const ModalState = {
        IDLE: 'idle',
        LOADING: 'loading',
        SHOWING: 'showing',
        SHOWN: 'shown',
        HIDING: 'hiding',
    };
    const DELAYS = {
        initialMs: 500,
        modalConflictMs: 700,
        safetyNetMs: 450,
        visibilityMs: 200,
    };
    const reduceMotion = typeof window.matchMedia === 'function'
        && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const ACTIVE_DELAYS = reduceMotion ? {
        initialMs: 0,
        modalConflictMs: 200,
        safetyNetMs: 150,
        visibilityMs: 0,
    } : DELAYS;
    let showAttempts = 0;
    let deferAttempts = 0;
    let showTimer = null;
    let safetyTimer = null;
    let modalState = ModalState.IDLE;
    let fragmentLoaded = false;
    let fragmentLoadPromise = null;
    let fragmentAbortController = null;
    let isTearingDown = false;

    function safeStorageGet(storageName, key) {
        try {
            const storage = window[storageName];
            return storage ? storage.getItem(key) : null;
        } catch (_err) {
            return null;
        }
    }

    function safeStorageSet(storageName, key, value) {
        try {
            const storage = window[storageName];
            if (storage) {
                storage.setItem(key, value);
            }
        } catch (_err) {
            // Restricted browser modes may disable storage entirely.
        }
    }

    function clearTimer(timerId) {
        if (timerId !== null) {
            clearTimeout(timerId);
        }
        return null;
    }

    function abortFragmentLoad() {
        if (fragmentAbortController) {
            fragmentAbortController.abort();
            fragmentAbortController = null;
        }
    }

    function isDismissedOrShown() {
        return Boolean(
            safeStorageGet('localStorage', ONBOARDING_KEY)
            || safeStorageGet('sessionStorage', SESSION_KEY)
        );
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
        showTimer = clearTimer(showTimer);
        safetyTimer = clearTimer(safetyTimer);
    }

    function shouldSkipOnboarding() {
        const onboardingEl = document.getElementById('wbOnboardingModal');
        return isDismissedOrShown()
            || isTearingDown
            || (onboardingEl && onboardingEl.classList.contains('show'))
            || modalState === ModalState.SHOWN
            || showAttempts >= MAX_SHOW_ATTEMPTS;
    }

    function cleanupFragment() {
        abortFragmentLoad();
        if (mountPoint) {
            mountPoint.replaceChildren();
        }
        fragmentLoaded = false;
        fragmentLoadPromise = null;
    }

    async function loadFragment() {
        if (fragmentLoaded) return true;
        if (fragmentLoadPromise) return fragmentLoadPromise;

        modalState = ModalState.LOADING;
        fragmentAbortController = new AbortController();
        fragmentLoadPromise = (async function () {
            try {
                const response = await fetch('/ui/fragments/onboarding', {
                    signal: fragmentAbortController.signal,
                });
                if (!response.ok) {
                    console.warn('Onboarding: Failed to load fragment (HTTP ' + response.status + ')');
                    return false;
                }
                const contentType = response.headers.get('content-type') || '';
                if (!contentType.includes('text/html')) {
                    throw new Error('Unexpected onboarding fragment content type');
                }
                const html = await response.text();
                if (isTearingDown || isDismissedOrShown()) {
                    return false;
                }

                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');
                mountPoint.replaceChildren(...Array.from(doc.body.childNodes));
                fragmentLoaded = true;

                // Set up event listeners after fragment is loaded
                setupEventListeners();
                return true;
            } catch (err) {
                if (err && err.name === 'AbortError') {
                    return false;
                }
                console.warn('Onboarding: Failed to fetch fragment:', err);
                return false;
            } finally {
                fragmentAbortController = null;
                fragmentLoadPromise = null;
                if (!fragmentLoaded && modalState === ModalState.LOADING) {
                    modalState = ModalState.IDLE;
                }
            }
        })();

        return fragmentLoadPromise;
    }

    function setupEventListeners() {
        const onboardingEl = document.getElementById('wbOnboardingModal');
        if (!onboardingEl) return;

        const dismissCheckbox = document.getElementById('wbOnboardingDismiss');
        bootstrap.Modal.getOrCreateInstance(onboardingEl);

        onboardingEl.addEventListener('show.bs.modal', function () {
            modalState = ModalState.SHOWING;
            isTearingDown = false;
            document.body.classList.add('wb-onboarding');
        });

        onboardingEl.addEventListener('shown.bs.modal', function () {
            modalState = ModalState.SHOWN;
            deferAttempts = 0;
            // Mark only after it is actually visible
            safeStorageSet('sessionStorage', SESSION_KEY, '1');
        });

        onboardingEl.addEventListener('hide.bs.modal', function () {
            modalState = ModalState.HIDING;
            isTearingDown = true;
        });

        onboardingEl.addEventListener('hidden.bs.modal', function () {
            modalState = ModalState.IDLE;
            document.body.classList.remove('wb-onboarding');
            if (dismissCheckbox && dismissCheckbox.checked) {
                safeStorageSet('localStorage', ONBOARDING_KEY, '1');
            }
            // Clean up mount point after modal is closed to prevent duplicate fragments
            // on subsequent client-side navigations
            cleanupFragment();
            isTearingDown = false;
        });
    }

    function hasConflictingOpenModal() {
        const modals = document.querySelectorAll('.modal');
        for (const modalEl of modals) {
            if (modalEl.id === 'wbOnboardingModal') continue;
            const modalInstance = bootstrap.Modal.getInstance(modalEl);
            const isVisible = modalEl.classList.contains('show')
                || (modalEl.getAttribute('aria-hidden') !== 'true' && modalEl.style.display !== 'none');
            if (modalInstance && isVisible) {
                return true;
            }
            if (!modalInstance && modalEl.classList.contains('show')) {
                return true;
            }
        }
        return false;
    }

    function scheduleShow(delayMs, options = {}) {
        const skipIfPending = Boolean(options.skipIfPending);
        if (skipIfPending && showTimer !== null) return;
        showTimer = clearTimer(showTimer);
        showTimer = setTimeout(function () {
            showTimer = null;
            tryShowOnboarding();
        }, delayMs);
    }

    async function tryShowOnboarding() {
        if (shouldSkipOnboarding()) return;
        if (modalState === ModalState.SHOWING || modalState === ModalState.SHOWN || modalState === ModalState.HIDING) {
            return;
        }

        // Load fragment if not already loaded
        if (!fragmentLoaded) {
            const loaded = await loadFragment();
            if (!loaded) return;
        }

        // Avoid showing onboarding on top of another modal.
        if (hasConflictingOpenModal()) {
            if (deferAttempts < MAX_DEFER_ATTEMPTS) {
                deferAttempts++;
                scheduleShow(ACTIVE_DELAYS.modalConflictMs);
            }
            return;
        }
        deferAttempts = 0;

        const onboardingEl = document.getElementById('wbOnboardingModal');
        if (!onboardingEl) return;

        const onboardingModal = bootstrap.Modal.getOrCreateInstance(onboardingEl);

        showAttempts++;
        modalState = ModalState.SHOWING;
        isTearingDown = false;
        onboardingModal.show();

        // Mobile safety net: retry if Bootstrap did not display modal.
        safetyTimer = clearTimer(safetyTimer);
        safetyTimer = setTimeout(() => {
            safetyTimer = null;
            if (shouldSkipOnboarding()) {
                return;
            }

            // Bootstrap called show() but did not finish opening.
            if (modalState === ModalState.SHOWING) {
                if (onboardingEl.classList.contains('show')) {
                    isTearingDown = true;
                    onboardingModal.hide();
                }
                scheduleShow(ACTIVE_DELAYS.safetyNetMs, { skipIfPending: true });
            }
        }, ACTIVE_DELAYS.safetyNetMs);
    }

    // Show after a short delay to let page render.
    scheduleShow(ACTIVE_DELAYS.initialMs);

    // Retry once tab becomes visible again (mobile browser quirk).
    document.addEventListener('visibilitychange', function () {
        if (document.hidden) return;
        if (isTearingDown) return;
        if (shouldSkipOnboarding()) return;
        scheduleShow(ACTIVE_DELAYS.visibilityMs, { skipIfPending: true });
    });

    window.addEventListener('pagehide', function () {
        clearTimers();
        abortFragmentLoad();
    }, { once: true });
})();
