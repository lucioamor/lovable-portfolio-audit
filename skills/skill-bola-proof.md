# Skill: BOLA Proof Mode (Variant-ID Probe)

> **Roadmap refs:** P1, §21.2  
> **Complexity:** Medium  
> **Files affected:** `extension/lib/api-client.js`, `extension/lib/audit-engine.js`, `extension/sidepanel.html`

---

## Problem

The current `testBOLA()` just checks if the authenticated user's own session
returns `200` on endpoint probes. This is a necessary but insufficient
condition — the owner will always get `200`.

**BOLA proof mode** re-probes a vulnerable endpoint with a *slightly mutated*
project ID (non-existent project or different user's project) to confirm
whether the endpoint truly leaks across ownership boundaries, vs. returning
`200` for all authenticated requests regardless.

The roadmap notes this as P1 (pending, with UI flag `bola_proof_mode_*`
already prepared) — it requires a product decision because it could make one
extra probe request that isn't strictly necessary to confirm.

---

## Implementation

### 1. Mutation strategies for proof ID

```js
// extension/lib/api-client.js

/**
 * Generate a "proof" project ID that is structurally valid but almost
 * certainly belongs to a different user (or doesn't exist).
 * Strategy: flip the last 4 chars of the UUID.
 */
export function mutateProjectId(projectId) {
  // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  // Flip last segment to produce a different but valid-format ID
  const parts = projectId.split('-');
  if (parts.length !== 5) return null;
  const last = parts[4];
  const flipped = last.split('').reverse().join('');
  parts[4] = flipped;
  return parts.join('-');
}

/**
 * Probe a single endpoint with the mutated ID.
 * Returns { proofId, status, signature }
 */
export async function bolaProofProbe(projectId, endpointFn) {
  const proofId = mutateProjectId(projectId);
  if (!proofId) return { proofId: null, status: null, signature: 'error' };

  try {
    const res = await apiRequest(endpointFn(proofId));
    const status = res.status;
    // If we get 2xx on a mutated ID → confirmed BOLA (cross-ownership leak)
    // If we get 404/403 → endpoint IS checking ownership (false positive cleared)
    // If we get 401 → session not valid for this endpoint
    const signature = (status >= 200 && status < 300)
      ? 'bola_confirmed'
      : (status === 404 || status === 403) ? 'ownership_enforced'
      : 'inconclusive';
    return { proofId, status, signature };
  } catch (e) {
    return { proofId, status: null, signature: 'error' };
  }
}
```

### 2. Integrate into `audit-engine.js`

Only invoked when `config.bolaProofMode === true`:

```js
// After standard probing, if any endpoint returned 'vulnerable' and proof mode is ON:
if (config.bolaProofMode && result.probeResults?.some(r => r.signature === 'vulnerable')) {
  result.bolaProof = [];
  for (const r of result.probeResults.filter(ep => ep.signature === 'vulnerable')) {
    const ep = PROBE_ENDPOINTS.find(e => e.label === r.label);
    if (!ep) continue;
    const proof = await bolaProofProbe(project.id, ep.path);
    result.bolaProof.push({ endpoint: r.label, ...proof });
    // Update finding description if proof confirmed
    if (proof.signature === 'bola_confirmed') {
      const finding = result.findings.find(f => f.ruleId === 'bola_files' || f.ruleId === 'bola_chat');
      if (finding) {
        finding.title += ' [CONFIRMED — cross-ownership leak verified]';
        finding.severity = 'critical';
      }
    } else if (proof.signature === 'ownership_enforced') {
      // Downgrade — owner check was passing but endpoint enforces ownership
      const finding = result.findings.find(f => f.ruleId === r.label.toLowerCase());
      if (finding) finding.description += ' [Note: ownership check passed on proof probe — may be false positive]';
    }
  }
}
```

### 3. UI gate in `sidepanel.html`

```html
<label id="bola-proof-row" class="toggle-row" hidden>
  <span>BOLA Proof Mode</span>
  <input type="checkbox" id="bola-proof-toggle" />
  <small>
    Makes one additional probe per vulnerable endpoint using a mutated project ID
    to confirm whether the exposure is cross-ownership (true BOLA) or just
    unauthenticated access. Adds ~1 request per vulnerable project.
    <strong>Only enable if you understand the implications.</strong>
  </small>
</label>
```

Show only when Safe Mode is OFF:

```js
document.getElementById('safe-mode-toggle').addEventListener('change', (e) => {
  document.getElementById('bola-proof-row').hidden = e.target.checked;
});
```

### 4. Evidence pack integration

`buildEvidencePack()` should include `bola_proof` in the per-project output:

```js
bola_proof: r.bolaProof || [],
```

---

## Rate limiting note

Each proof probe adds 1 request per vulnerable endpoint. With 4 endpoints
probed and 180+ projects, worst case = 720 extra requests. Gate this behind
a warning:

```js
if (config.bolaProofMode && filtered.length > 20) {
  const confirmed = await confirmDialog(
    `BOLA proof mode will send up to ${filtered.length * 4} additional requests. Proceed?`
  );
  if (!confirmed) config.bolaProofMode = false;
}
```

---

## Acceptance Criteria

- [ ] `mutateProjectId()` produces a valid UUID-format string different from input
- [ ] `bolaProofProbe()` returns `bola_confirmed` when mutated ID returns 2xx
- [ ] `bolaProofProbe()` returns `ownership_enforced` when mutated ID returns 403/404
- [ ] Proof mode only runs when `config.bolaProofMode === true`
- [ ] UI toggle only visible when Safe Mode is OFF
- [ ] Warning shown when proof mode + >20 projects
- [ ] `bolaProof` array included in evidence pack output
