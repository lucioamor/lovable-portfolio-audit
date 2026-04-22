# Skill: Pattern Expansion (Missing Secret Rules)

> **Roadmap refs:** B1, §5.2  
> **Complexity:** Small  
> **Files affected:** `extension/lib/data-patterns.js`, `src/lib/data-patterns.ts`

---

## Problem

The roadmap defines 17 secret rules. The extension currently has 16 (and uses
different groupings). The following patterns from the roadmap are absent or
need hardening:

| Missing / needs fix | Notes |
|---|---|
| `Mistral` API key | Pattern: `Bearer [A-Za-z0-9_-]{32,}` in context |
| `HuggingFace` token | Pattern: `hf_[A-Za-z0-9]{30,}` |
| `Pinecone` API key | Pattern: `[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}` |
| `Cohere` API key | Pattern: `[A-Za-z0-9]{40}` in context of `cohere`/`COHERE` |
| `Slack` bot/user token | Pattern: `xox[baprs]-[0-9A-Za-z-]{10,}` |
| `Google OAuth` client secret | Pattern: `GOCSPX-[A-Za-z0-9_-]{28}` |
| `Supabase service role JWT` | Current regex matches anything ≥100 chars eyJ… — too broad. Needs tighter targeting. |

---

## Implementation

Add to `SECRET_PATTERNS` array in `extension/lib/data-patterns.js`:

```js
// -- Missing patterns from roadmap --

{ id: 'slack_token', severity: 'critical', label: 'Slack Token',
  regex: /xox[baprs]-[0-9A-Za-z-]{10,}/ },

{ id: 'mistral_key', severity: 'high', label: 'Mistral API Key',
  // Mistral keys are typically 32+ alphanum. Gate on context word to avoid FP.
  regex: /(?:mistral[_-]?(?:api[_-]?)?key|MISTRAL_API_KEY)\s*[=:]\s*['"][A-Za-z0-9_-]{32,}['"]/ },

{ id: 'huggingface_token', severity: 'high', label: 'HuggingFace Token',
  regex: /hf_[A-Za-z0-9]{30,}/ },

{ id: 'pinecone_key', severity: 'high', label: 'Pinecone API Key',
  // Pinecone keys look like UUIDs — gate on context
  regex: /(?:pinecone[_-]?(?:api[_-]?)?key|PINECONE_API_KEY)\s*[=:]\s*['"][a-z0-9-]{36,}['"]/ },

{ id: 'cohere_key', severity: 'high', label: 'Cohere API Key',
  regex: /(?:cohere[_-]?(?:api[_-]?)?key|COHERE_API_KEY)\s*[=:]\s*['"][A-Za-z0-9]{40,}['"]/ },

{ id: 'google_oauth_secret', severity: 'critical', label: 'Google OAuth Client Secret',
  regex: /GOCSPX-[A-Za-z0-9_-]{28}/ },
```

### Supabase service role JWT hardening

Replace the existing overly-broad pattern:

```js
// BEFORE (too broad — matches any long eyJ… string)
{ id: 'supabase_service_role', severity: 'critical', label: 'Supabase Service Role Key',
  regex: /eyJ[A-Za-z0-9_-]{100,}/ },

// AFTER — require the Supabase role claim pattern
{ id: 'supabase_service_role', severity: 'critical', label: 'Supabase Service Role Key',
  // JWT header+payload where role claim contains "service_role"
  // Two-step: find eyJ…eyJ…, then verify payload decodes to contain service_role
  regex: /eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}(?:service_role)[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{20,}/ },
```

> **Note:** Since regex can't decode base64, this pattern will still have false
> positives with any JWT that has "service_role" literally in the raw base64
> string. Consider adding a post-match validator that base64-decodes the payload
> and checks `role === 'service_role'` before emitting a finding.

### Post-match JWT validator (optional enhancement)

```js
export function isSupabaseServiceRoleJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const payload = JSON.parse(atob(parts[1]));
    return payload?.role === 'service_role';
  } catch { return false; }
}
```

---

## Also: Google API Key (exists but verify)

The existing `firebase_key` pattern (`AIza[0-9A-Za-z_-]{35}`) covers Google
API keys broadly — this is correct and aligns with the roadmap's "Google API"
rule. No change needed there.

---

## TypeScript mirror (`src/lib/data-patterns.ts`)

Apply the same additions to the web app module, preserving TypeScript typing:

```ts
{ id: 'slack_token', severity: 'critical' as const, label: 'Slack Token',
  regex: /xox[baprs]-[0-9A-Za-z-]{10,}/ },
// ... (same patterns, add `as const` to severity)
```

---

## Acceptance Criteria

- [ ] `SECRET_PATTERNS.length === 22` (16 existing + 6 new)
- [ ] All new patterns have unit test coverage (add to `skill-scorer-tests.md`)
- [ ] Supabase service role regex does not match a Supabase anon key (test case needed)
- [ ] Changes mirrored in `src/lib/data-patterns.ts`
