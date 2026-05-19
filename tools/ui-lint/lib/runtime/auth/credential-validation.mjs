//
// tools/ui-lint/lib/runtime/auth/credential-validation.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function validateCredentials({ username, password } = {}) {
    return typeof username === 'string' && username.trim().length > 0
        && typeof password === 'string' && password.trim().length > 0;
}
