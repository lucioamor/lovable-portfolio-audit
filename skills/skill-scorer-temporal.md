# Skill: Scorer Temporal Signal + GetProject Tier

> **Roadmap refs:** C1–C8, §5.3  
> **Complexity:** Small  
> **Files affected:** `extension/lib/health-scorer.js`, `src/lib/health-scorer.ts`

---

## Problem

The extension's scorer uses **project creation date cutoffs** (pre-May-2025,
pre-Nov-2025) as a temporal signal with large fixed penalties (+80/+60).
The roadmap uses a single clean signal: **edited in the last 30 days → +10**
(and this bonus is zeroed when all endpoints are patched).

The current approach:
1. Creates an artificial cluster of projects created before the cutoff dates
   that receive high scores regardless of actual risk.
2. Doesn't distinguish between a project that's been dormant for years vs.
   one actively being edited.
3. Uses `createdAt` instead of `updatedAt` — wrong signal.

---

## Implementation

### 1. Replace temporal scoring in `health-scorer.js`

```js
// REMOVE these lines:
const CUTOFF_EARLY = new Date('2025-05-25T00:00:00Z');
const CUTOFF_LATE  = new Date('2025-11-01T00:00:00Z');
// ...
if (created < CUTOFF_EARLY) score += 80;
else if (created < CUTOFF_LATE) score += 60;

// ADD this instead:
const daysSinceEdit = (Date.now() - new Date(result.updatedAt).getTime()) / 86400000;
const allPatched = result.probeResults?.every(r => r.signature === 'patched');
if (daysSinceEdit < 30 && !allPatched) score += 10;
```

### 2. Add `GetProject` probe score

When using new probe results (see `skill-dual-probe.md`):

```js
if (result.probeResults) {
  for (const r of result.probeResults) {
    if (r.signature !== 'vulnerable') continue;
    switch (r.label) {
      case 'GitFilesResponse':
      case 'GetProjectFile':
        score += 60; break;
      case 'GetProjectMessagesOutputBody':
        score += 60; break;
      case 'GetProject':
        score += 30; break;
    }
  }
} else {
  // Legacy fallback (remove after full migration)
  if (result.bolaFileStatus === 'vulnerable') score += 60;
  if (result.bolaChatStatus === 'vulnerable') score += 60;
}
```

### 3. Keep RLS score (+40) — divergence from roadmap is intentional

The roadmap keeps RLS as a separate checklist, not scored. The extension
scores it because it runs the actual Supabase inspector. Keep this divergence
documented as a deliberate extension-specific enhancement.

> **Design note:** If the RLS direct-exec is eventually replaced by copy-paste
> SQL (see `skill-rls-copypaste.md`), the +40 bonus should be removed from
> the scorer and RLS audit surfaced purely as a checklist finding.

### 4. Uncap the score

The roadmap does not cap at 100 — it uses bands. However, capping at 100 is
reasonable UX for a 0–100 "health score" display. Keep the cap but document
that the raw sum can exceed 100.

---

## Demo data alignment

Update `generateDemoData()` in `audit-engine.js` to use `updatedAt` dates that
produce meaningful scores with the new system (not the cutoff-era values).

---

## Acceptance Criteria

- [ ] `CUTOFF_EARLY` / `CUTOFF_LATE` constants removed
- [ ] Temporal bonus: `+10` if `updatedAt < 30d ago` AND not all patched
- [ ] `GetProject` vulnerable endpoint adds `+30` to score
- [ ] Score bands unchanged: `≥80 critical`, `≥50 high`, `≥20 medium`, `>0 low`, else `clean`
- [ ] Demo data produces realistic score distribution with new algorithm
