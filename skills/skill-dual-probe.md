# Skill: Dual-Account Endpoint Probe + `response_signature`

> **Roadmap refs:** A1–A5, §13.2  
> **Complexity:** Medium  
> **Files affected:** `extension/lib/api-client.js`, `extension/lib/audit-engine.js`

---

## Problem

The current `testBOLA()` function uses only the owner's session cookie and
classifies `200 → vulnerable`, `403 → protected`. This is a heuristic —
a `200` from the owner proves nothing without comparing against an anonymous
or non-owner probe.

The roadmap defines a precise `response_signature` decision matrix that
requires **two accounts** probed side-by-side per endpoint:

| Owner status | Audit status | `response_signature` | Meaning |
|---|---|---|---|
| any | 2xx | `vulnerable` | Non-owner can read → BOLA |
| 2xx | 401/403/404 | `patched` | Auth working as expected |
| null / ≥500 | * | `error` | Network failure |
| * | null / ≥500 | `error` | Network failure |
| else | else | `unknown` | Inconclusive |

The extension has access to `chrome.cookies` for the **owner** session. A
second "audit" account requires the user to supply a second Bearer token or
cookie manually (or via a second Chrome profile).

---

## Implementation Plan

### 1. Extend `api-client.js`

Add a secondary token concept:

```js
let auditToken = null;
export function setAuditToken(token) { auditToken = token; }
export function hasAuditToken() { return !!auditToken; }

async function auditRequest(path) {
  await throttle();
  if (!auditToken) return null;
  const headers = {
    'Content-Type': 'application/json',
    'X-Client': USER_AGENT,
    'Authorization': `Bearer ${auditToken}`,
  };
  try {
    return await fetch(`${API_BASE}${path}`, { headers });
  } catch { return null; }
}
```

Add all 4 confirmed endpoints:

```js
export const PROBE_ENDPOINTS = [
  { label: 'GetProject',                   path: (id) => `/projects/${id}` },
  { label: 'GetProjectMessagesOutputBody', path: (id) => `/projects/${id}/messages` },
  { label: 'GitFilesResponse',             path: (id) => `/projects/${id}/git/files` },
  { label: 'GetProjectFile',               path: (id) => `/projects/${id}/git/files/src%2Fmain.ts` },
];

export function computeResponseSignature(ownerStatus, auditStatus) {
  const is2xx = (s) => s >= 200 && s < 300;
  const isError = (s) => s === null || s >= 500;
  const isAuth = (s) => s === 401 || s === 403 || s === 404;
  if (isError(ownerStatus) || isError(auditStatus)) return 'error';
  if (is2xx(auditStatus)) return 'vulnerable';
  if (is2xx(ownerStatus) && isAuth(auditStatus)) return 'patched';
  return 'unknown';
}

export async function probeEndpointPair(projectId, endpoint) {
  const [ownerRes, auditRes] = await Promise.all([
    apiRequest(endpoint.path(projectId)).catch(() => null),
    auditRequest(endpoint.path(projectId)).catch(() => null),
  ]);
  return {
    label: endpoint.label,
    ownerStatus: ownerRes?.status ?? null,
    auditStatus: auditToken ? (auditRes?.status ?? null) : null,
    signature: computeResponseSignature(ownerRes?.status ?? null, auditToken ? (auditRes?.status ?? null) : null),
  };
}
```

### 2. Update `audit-engine.js`

Replace `testBOLA()` with `probeAllEndpoints()`:

```js
const probeResults = [];
for (const ep of PROBE_ENDPOINTS) {
  const r = await probeEndpointPair(project.id, ep);
  probeResults.push(r);
}
result.probeResults = probeResults;
result.bolaFileStatus = probeResults.find(r => r.label === 'GitFilesResponse')?.signature ?? 'unknown';
result.bolaChatStatus = probeResults.find(r => r.label === 'GetProjectMessagesOutputBody')?.signature ?? 'unknown';
result.bolaProjectStatus = probeResults.find(r => r.label === 'GetProject')?.signature ?? 'unknown';
```

### 3. Update `health-scorer.js`

Add `GetProject` probe score (+30) and honour `patched` (zeroes temporal bonus):

```js
// Replace binary bolaFileStatus check with signature-aware check
if (result.probeResults) {
  for (const r of result.probeResults) {
    if (r.signature === 'vulnerable') {
      if (r.label === 'GitFilesResponse' || r.label === 'GetProjectFile') score += 60;
      else if (r.label === 'GetProjectMessagesOutputBody') score += 60;
      else if (r.label === 'GetProject') score += 30;
    }
  }
  // If all patched, zero temporal bonus
  const allPatched = result.probeResults.every(r => r.signature === 'patched');
  if (allPatched) score = Math.max(0, score - 10);
} else {
  // Legacy fallback
  if (result.bolaFileStatus === 'vulnerable') score += 60;
  if (result.bolaChatStatus === 'vulnerable') score += 60;
}
```

### 4. UI: Audit Token Input

Add an optional "Audit token" input field in `sidepanel.html` / `popup.html`:

```html
<details id="advanced-settings">
  <summary>Advanced: Dual-account BOLA verification</summary>
  <input id="audit-token" type="password"
    placeholder="Bearer token for a second (non-owner) account" />
  <small>Optional. When provided, each endpoint is probed from both accounts
    to produce a definitive vulnerable/patched classification.</small>
</details>
```

In `sidepanel.js`:
```js
const auditToken = document.getElementById('audit-token').value.trim();
if (auditToken) setAuditToken(auditToken);
```

---

## Acceptance Criteria

- [ ] All 4 roadmap endpoints probed per project
- [ ] `probeResults[]` on every scan result
- [ ] `response_signature` computed per endpoint
- [ ] Score uses new probe results, not legacy `bolaFileStatus` string
- [ ] No change to behaviour when audit token is absent (owner-only → `unknown` for audit side)

---

## Non-goals (preserve)

- Do NOT store audit token beyond the current session (`sessionStorage` max, prefer in-memory only)
- Do NOT send audit token to any external server
- Do NOT auto-persist audit token in `chrome.storage.local`
