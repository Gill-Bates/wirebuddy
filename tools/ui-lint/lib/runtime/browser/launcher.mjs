//
// tools/ui-lint/lib/runtime/browser/launcher.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Re-export so the runtime and the audit-runner facade cannot drift apart;
// the adapters themselves live in lib/browsers/launcher.mjs.
export { BrowserAdapters, getBrowserLauncher } from '../../browsers/launcher.mjs';
