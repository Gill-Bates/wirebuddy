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
    await Promise.all([
        page.waitForURL((url) => !url.toString().includes('/login'), { timeout: 10000 }),
        page.click('#submit-btn'),
    ]);

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
