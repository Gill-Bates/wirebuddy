//
// tools/ui-lint/lib/runtime/auth/login-flow.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { disableMotion } from '../motion/disable-motion.mjs';
import { bootstrapAuthenticatedSession } from './auth-state.mjs';
import { validateCredentials } from './credential-validation.mjs';

export async function performLogin(page, { baseUrl, username, password, motionResetCss }) {
    if (!validateCredentials({ username, password })) {
        throw new Error('Invalid credentials');
    }

    await page.goto(`${baseUrl}/login`, { waitUntil: 'networkidle', timeout: 10000 });
    await disableMotion(page, motionResetCss, 'login');

    await page.fill('#username', username);
    await page.fill('#password', password);

    await page.click('#submit-btn');

    try {
        const outcome = await page.waitForFunction(
            () => {
                const loginSucceeded = !window.location.pathname.includes('/login')
                    || Boolean(document.getElementById('logoutBtn'));
                if (loginSucceeded) {
                    return 'success';
                }

                const errorAlert = document.getElementById('error-alert');
                if (errorAlert && errorAlert.isConnected) {
                    const style = window.getComputedStyle(errorAlert);
                    const rect = errorAlert.getBoundingClientRect();
                    const hiddenByClass = errorAlert.classList.contains('is-hidden')
                        || errorAlert.classList.contains('d-none');
                    const hiddenByAttr = errorAlert.hidden || errorAlert.getAttribute('aria-hidden') === 'true';
                    const isVisible = !hiddenByClass
                        && !hiddenByAttr
                        && style.display !== 'none'
                        && style.visibility !== 'hidden'
                        && style.opacity !== '0'
                        && rect.width > 0
                        && rect.height > 0;
                    if (isVisible) {
                        return 'failure';
                    }
                }

                const submitButton = document.getElementById('submit-btn');
                const submitText = (submitButton?.textContent || '').trim();
                if (submitButton?.disabled && /retry in\s+\d+s/i.test(submitText)) {
                    return 'failure';
                }

                return null;
            },
            { timeout: 10000, polling: 100 },
        );
        const resolvedOutcome = await outcome.jsonValue();
        if (resolvedOutcome === 'failure') {
            const loginFailure = await detectLoginFailure(page);
            throw new Error(`Login failed: ${loginFailure || 'Too many attempts. Please wait.'}`);
        }
    } catch (err) {
        if (err instanceof Error && err.message.startsWith('Login failed:')) {
            throw err;
        }
        const loginFailure = await detectLoginFailure(page);
        if (loginFailure) {
            throw new Error(`Login failed: ${loginFailure}`);
        }
        throw err;
    }

    await bootstrapAuthenticatedSession(page, { baseUrl });
}

export { performLogin as login };

export async function detectLoginFailure(page) {
    const errorText = await page.locator('.alert-danger, .login-error, .error-message').evaluateAll((elements) => {
        const isVisible = (el) => {
            if (!el || !el.isConnected) return false;
            if (el.closest('.d-none, [hidden], [aria-hidden="true"]')) return false;
            const style = window.getComputedStyle(el);
            if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
            const rect = el.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0;
        };

        const visibleError = elements.find((el) => isVisible(el));
        return visibleError ? (visibleError.textContent || '').trim() : '';
    });

    return errorText || null;
}
