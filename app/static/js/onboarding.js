//
// app/static/js/onboarding.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

/* ── Onboarding Modal ── */
(function () {
    const ONBOARDING_KEY = 'wb_onboarding_dismissed';
    const SESSION_KEY = 'wb_onboarding_shown';
    const MAX_SHOW_ATTEMPTS = 4;
    let showAttempts = 0;
    let showTimer = null;
    let safetyTimer = null;

    // Don't show if permanently dismissed or already shown this session
    if (localStorage.getItem(ONBOARDING_KEY)) return;
    if (sessionStorage.getItem(SESSION_KEY)) return;

    const onboardingEl = document.getElementById('wbOnboardingModal');
    if (!onboardingEl) return;

    const onboardingModal = bootstrap.Modal.getOrCreateInstance(onboardingEl);
    const dismissCheckbox = document.getElementById('wbOnboardingDismiss');

    onboardingEl.addEventListener('show.bs.modal', function () {
        document.body.classList.add('wb-onboarding');
    });

    onboardingEl.addEventListener('shown.bs.modal', function () {
        // Mark only after it is actually visible
        sessionStorage.setItem(SESSION_KEY, '1');
    });

    onboardingEl.addEventListener('hidden.bs.modal', function () {
        document.body.classList.remove('wb-onboarding');
        if (dismissCheckbox && dismissCheckbox.checked) {
            localStorage.setItem(ONBOARDING_KEY, '1');
        }
    });

    function scheduleShow(delayMs) {
        if (showTimer) {
            clearTimeout(showTimer);
        }
        showTimer = setTimeout(tryShowOnboarding, delayMs);
    }

    function tryShowOnboarding() {
        if (localStorage.getItem(ONBOARDING_KEY)) return;
        if (sessionStorage.getItem(SESSION_KEY)) return;
        if (onboardingEl.classList.contains('show')) return;
        if (showAttempts >= MAX_SHOW_ATTEMPTS) return;

        // Avoid showing onboarding on top of another modal.
        const otherOpenModal = document.querySelector('.modal.show:not(#wbOnboardingModal)');
        if (otherOpenModal) {
            showAttempts++;
            scheduleShow(700);
            return;
        }

        showAttempts++;
        onboardingModal.show();

        // Mobile safety net: retry if Bootstrap did not display modal.
        if (safetyTimer) clearTimeout(safetyTimer);
        safetyTimer = setTimeout(() => {
            safetyTimer = null;
            if (!localStorage.getItem(ONBOARDING_KEY)
                && !sessionStorage.getItem(SESSION_KEY)
                && !onboardingEl.classList.contains('show')
                && showAttempts < MAX_SHOW_ATTEMPTS) {
                scheduleShow(450);
            }
        }, 450);
    }

    // Show after a short delay to let page render.
    scheduleShow(500);

    // Retry once tab becomes visible again (mobile browser quirk).
    document.addEventListener('visibilitychange', function () {
        if (document.hidden) return;
        if (localStorage.getItem(ONBOARDING_KEY)) return;
        if (sessionStorage.getItem(SESSION_KEY)) return;
        if (onboardingEl.classList.contains('show')) return;
        if (showAttempts >= MAX_SHOW_ATTEMPTS) return;
        scheduleShow(200);
    });
})();
