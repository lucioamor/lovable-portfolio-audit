# Skill: sha256 Hashing for Findings Privacy

> **Roadmap refs:** §5.4, B3, B4, §4.4  
> **Complexity:** Small  
> **Files affected:** `extension/lib/data-patterns.js`, `extension/lib/audit-engine.js`

---

## Problem

The current masking implementation stores a substring of the raw match value
(`value.substring(0, 8) + '•••••' + value.slice(-3)`) in `chrome.storage.local`.

The roadmap's privacy invariant (§4.4) requires:
- `secret_masked` — display string only
- `secret_hash` — `sha256(rawValue)` → hex → first 16 chars
- Raw value is **never** stored, logged, or returned

The hash serves deduplication across scans (same secret found twice = same hash)
without retaining the actual value.

---

## Implementation

### 1. Add `masking.js` to `extension/lib/`

```js
// extension/lib/masking.js
// Pure helpers — no fetch, no regex, no chrome.* calls

/**
 * Mask a secret for display.
 * Aligned with roadmap §5.4:
 *   length <= 12: first 3 chars + bullets
 *   else:         first 4 + bullets + last 4
 */
export function maskSecret(value) {
  if (!value || typeof value !== 'string') return '•••';
  if (value.length <= 12) return value.slice(0, 3) + '•'.repeat(value.length - 3);
  return value.slice(0, 4) + '•'.repeat(value.length - 8) + value.slice(-4);
}

/**
 * sha256(value) → hex string → first 16 chars.
 * Uses Web Crypto API (available in MV3 service workers).
 */
export async function hashSecret(value) {
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(value)
  );
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 16);
}

/**
 * Compute 1-based line number of a match at byte offset `idx` within `content`.
 */
export function lineNumber(content, idx) {
  return (content.slice(0, idx).match(/\n/g) || []).length + 1;
}
```

### 2. Update `scanContent()` in `data-patterns.js`

Change signature to async and add hash + line number:

```js
import { maskSecret, hashSecret, lineNumber } from './masking.js';

export async function scanContent(content, source) {
  const findings = [];

  for (const pattern of SECRET_PATTERNS) {
    const match = pattern.regex.exec(content);
    if (match) {
      const raw = match[0];
      const [masked, hash] = await Promise.all([
        Promise.resolve(maskSecret(raw)),
        hashSecret(raw),
      ]);
      findings.push({
        id: crypto.randomUUID(),
        ruleId: pattern.id, severity: pattern.severity,
        title: pattern.label, vector: 'hardcoded_secret', source,
        description: `${pattern.label} found in ${source}`,
        evidence: masked,        // display only
        secret_hash: hash,       // dedupe key
        line: lineNumber(content, match.index),
        recommendation: `Rotate this ${pattern.label} immediately and move to environment variables.`,
        file: source,
      });
    }
  }

  for (const pattern of PII_PATTERNS) {
    const match = pattern.regex.exec(content);
    if (match) {
      const raw = match[0];
      const [masked, hash] = await Promise.all([
        Promise.resolve(maskSecret(raw)),
        hashSecret(raw),
      ]);
      findings.push({
        id: crypto.randomUUID(),
        ruleId: pattern.id, severity: pattern.severity,
        title: pattern.label,
        vector: source.includes('message') ? 'pii_in_chat' : 'pii_in_code', source,
        description: `${pattern.label} detected in ${source}`,
        evidence: masked,
        secret_hash: hash,
        line: lineNumber(content, match.index),
        recommendation: 'Remove PII from source code or chat history.',
        file: source,
      });
    }
  }

  return findings;
}
```

### 3. Update callers in `audit-engine.js`

`scanContent` is now async — await it:

```js
const findings = await scanContent(content, file.path || file.name);
```

### 4. Audit grep target

After this change, run the following grep to verify the raw invariant holds:

```
grep -r "match\[0\]" extension/lib/
```
Expected: only appears inside `masking.js` → `hashSecret` and `maskSecret` calls. Not stored anywhere else.

---

## Acceptance Criteria

- [ ] `maskSecret` uses `[:4]+bullets+[-4:]` for values > 12 chars
- [ ] Every finding has `secret_hash` (16-char hex) and `line` (1-based integer)
- [ ] `evidence` field contains only the masked display string
- [ ] `scanContent` is async; all callers `await` it
- [ ] `masking.js` has no `fetch`, no `chrome.*`, no regex — pure helpers only
