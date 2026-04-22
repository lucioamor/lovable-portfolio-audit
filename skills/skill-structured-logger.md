# Skill: Structured Logger with Token Strip

> **Roadmap refs:** H2, §17  
> **Complexity:** Small  
> **Files affected:** `extension/lib/logger.js`, `extension/background.js`

---

## Problem

Standard `console.log` and `console.error` calls can inadvertently print raw tokens, API keys, or cookies into the DevTools console. This violates the strict privacy invariants.

---

## Implementation

### 1. Create `logger.js`

```js
// extension/lib/logger.js

/**
 * Recursively strip sensitive keys from an object before logging.
 */
function stripSensitive(obj) {
  if (typeof obj !== 'object' || obj === null) return obj;
  if (Array.isArray(obj)) return obj.map(stripSensitive);

  const safeObj = {};
  const blockedKeys = ['token', 'cookie', 'secret', 'password', 'authorization', 'evidence', 'raw'];

  for (const [key, value] of Object.entries(obj)) {
    if (blockedKeys.some(b => key.toLowerCase().includes(b))) {
      safeObj[key] = '[REDACTED]';
    } else {
      safeObj[key] = stripSensitive(value);
    }
  }
  return safeObj;
}

export const log = {
  info: (msg, ctx = {}) => {
    console.log(JSON.stringify({ ts: new Date().toISOString(), level: 'INFO', msg, ctx: stripSensitive(ctx) }));
  },
  error: (msg, err, ctx = {}) => {
    const errObj = err instanceof Error ? { message: err.message, stack: err.stack } : err;
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'ERROR', msg, error: errObj, ctx: stripSensitive(ctx) }));
  }
};
```

### 2. Replace console calls

Search the extension for `console.log` and `console.error` and replace them with `log.info` and `log.error`.

```js
// background.js
import { log } from './lib/logger.js';

log.info('Lovable Portfolio Audit installed', { version: '1.0.0' });
// ...
log.error('Scan failed', err, { projectId: project.id });
```

---

## Acceptance Criteria

- [ ] All logs are output as single-line JSON strings
- [ ] Keys containing 'token', 'secret', etc., are redacted
- [ ] No raw `console.log` calls remain in the core logic
