# Skill Index — Lovable Portfolio Audit

> Skills are modular implementation specs. Each file is self-contained and can
> be handed to an LLM (or a developer) as a standalone instruction. Execute
> them in dependency order — skills marked with `(needs X)` should be done
> after `X`.

---

## Dependency order & priority

```
Phase 1 — Foundation (no inter-dependencies)
├── skill-crypto-hashing.md       [S] sha256 hash + line numbers + masking alignment
├── skill-pattern-expansion.md    [S] 6 missing secret patterns
├── skill-scorer-temporal.md      [S] Fix temporal scoring, add GetProject tier
└── skill-consent-gate.md         [S] Safe mode default + legal modal + consent gates

Phase 2 — Endpoint probing (needs Phase 1)
└── skill-dual-probe.md           [M] 4 endpoints + response_signature + dual-account

Phase 3 — Advanced (needs Phase 2)
├── skill-bola-proof.md           [M] BOLA variant-ID confirmation probe
├── skill-evidence-pack.md        [M] HMAC-SHA256 signed export
└── skill-resumable-scan.md       [M] chunk_id + 3× retry with backoff

Phase 4 — Surface expansion (needs Phase 1)
├── skill-chat-scan.md            [S] Chat history regex (decouple from BOLA gate)
├── skill-bundle-scan.md          [M] Fetch minified bundle, find Supabase keys
├── skill-csp-sri.md              [M] CSP / SRI check on public project URL
└── skill-diff-alerts.md          [S] Compare current vs previous scan severity

Phase 5 — Quality (independent)
├── skill-scorer-tests.md         [S] vitest deterministic scorer tests
├── skill-structured-logger.md    [S] JSON logger with defensive token strip
├── skill-rls-copypaste.md        [S] Emit copy-paste SQL instead of direct exec
└── skill-masking-hardening.md    [S] Tighten masking algo alignment
```

---

## File list

| Skill file | Phase | Size | Roadmap refs | Status |
|---|---|---|---|---|
| [skill-crypto-hashing.md](./skill-crypto-hashing.md) | 1 | S | B3, B4, §5.4 | 📋 Spec ready |
| [skill-pattern-expansion.md](./skill-pattern-expansion.md) | 1 | S | B1, §5.2 | 📋 Spec ready |
| [skill-scorer-temporal.md](./skill-scorer-temporal.md) | 1 | S | C1–C8 | 📋 Spec ready |
| [skill-consent-gate.md](./skill-consent-gate.md) | 1 | S | E7–E9, §7.1 | 📋 Spec ready |
| [skill-dual-probe.md](./skill-dual-probe.md) | 2 | M | A1–A5, §13.2 | 📋 Spec ready |
| [skill-bola-proof.md](./skill-bola-proof.md) | 3 | M | P1 | 📋 Spec ready |
| [skill-evidence-pack.md](./skill-evidence-pack.md) | 3 | M | H5 | 📋 Spec ready |
| skill-resumable-scan.md | 3 | M | A7 | ⬜ Not written yet |
| skill-chat-scan.md | 4 | S | P10 | ⬜ Not written yet |
| skill-bundle-scan.md | 4 | M | P9 | ⬜ Not written yet |
| skill-csp-sri.md | 4 | M | P8 | ⬜ Not written yet |
| skill-diff-alerts.md | 4 | S | P11 | ⬜ Not written yet |
| skill-scorer-tests.md | 5 | S | C9 | ⬜ Not written yet |
| skill-structured-logger.md | 5 | S | H2 | ⬜ Not written yet |
| skill-rls-copypaste.md | 5 | S | D1–D4 | ⬜ Not written yet |
| skill-masking-hardening.md | 5 | S | §5.4 | ⬜ Not written yet |

---

## Architecture constraints (apply to all skills)

These are hard constraints that every skill must respect:

1. **No server calls** — all logic runs in the extension (service worker or content scripts). No Supabase, no backend.
2. **Tokens never leave the browser** — never transmit `sessionToken`, `auditToken`, or any finding's raw value to an external server.
3. **Raw secret values never stored** — only `evidence` (masked display) and `secret_hash` (sha256[:16]) may be persisted in `chrome.storage.local`.
4. **Read-only** — only GET requests. No POST/PUT/DELETE to `api.lovable.dev`.
5. **Rate limited** — minimum 200ms between requests (`setDelay` enforced in `api-client.js`).
6. **Module boundaries** — `api-client.js` does HTTP only. `data-patterns.js` does regex only. `health-scorer.js` does math only. `masking.js` does string transforms only. No mixing.
7. **Safe mode default ON** — every scan configuration must default to `safe_mode: true`.

---

## Out-of-scope items (do NOT implement in extension)

Per roadmap §21.3 + architectural constraints:

- ❌ Direct SQL execution against user's Supabase (despite `supabase-inspector.ts` doing this in web app — should be replaced with copy-paste SQL)
- ❌ Any Supabase backend / edge functions  
- ❌ Envelope encryption / DEK per user (no server)  
- ❌ Anonymous telemetry to external server (local-only promise)  
- ❌ User-defined regex patterns (ReDoS risk without sandbox)  
- ❌ Automatic secret rotation  
- ❌ `lovable.dev/?import=...` migration flows  
