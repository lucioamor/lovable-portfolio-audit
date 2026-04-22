# Skill: Resumable Scan (Chunking & Retries)

> **Roadmap refs:** A7, §16  
> **Complexity:** Medium  
> **Files affected:** `extension/lib/api-client.js`, `extension/lib/audit-engine.js`

---

## Problem

Network requests can fail intermittently (5xx errors, rate limiting, connection drops). A single `fetch` error currently causes the endpoint probe to fail silently or abort the project scan. The roadmap requires up to 3 retries with linear backoff for any endpoint probe that returns an `"error"` signature. Additionally, it introduces `chunk_id` tracking for logical grouping.

---

## Implementation

### 1. `api-client.js` retry wrapper

```js
const MAX_RETRIES = 3;
const BACKOFF_MS = 500;

async function fetchWithRetry(path, options, attempt = 1) {
  try {
    const res = await apiRequest(path, options);
    if (res.status >= 500 || res.status === 429) {
      if (attempt <= MAX_RETRIES) {
        await new Promise(r => setTimeout(r, attempt * BACKOFF_MS));
        return fetchWithRetry(path, options, attempt + 1);
      }
    }
    return res;
  } catch (err) {
    if (attempt <= MAX_RETRIES) {
      await new Promise(r => setTimeout(r, attempt * BACKOFF_MS));
      return fetchWithRetry(path, options, attempt + 1);
    }
    throw err;
  }
}
```

### 2. Update `probeEndpointPair` to track attempts

```js
export async function probeEndpointPair(projectId, endpoint) {
  let attempts = 1;
  // Custom wrapper that counts attempts
  const executeProbe = async (reqFn) => {
    // ... retry logic that increments `attempts` ...
  };
  
  // ...
  return {
    label: endpoint.label,
    signature: computeResponseSignature(ownerStatus, auditStatus),
    attempt_number: attempts,
  };
}
```

### 3. Add `chunk_id` logic to `audit-engine.js`

```js
// Group projects into chunks of 10 for logical resuming
const chunkSize = 10;
const chunk_id = Math.floor(i / chunkSize);

result.chunk_id = chunk_id;
// For every finding and probe result, attach chunk_id if needed
```

---

## Acceptance Criteria

- [ ] Network failures (5xx, timeouts) automatically retry up to 3 times
- [ ] Linear backoff applied between retries (e.g. 500ms, 1000ms, 1500ms)
- [ ] `attempt_number` recorded in `probeResults` array
- [ ] `chunk_id` computed and persisted on the scan result object
