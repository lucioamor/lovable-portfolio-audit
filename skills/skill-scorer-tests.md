# Skill: Deterministic Scorer Tests

> **Roadmap refs:** C9, §17  
> **Complexity:** Small  
> **Files affected:** `test/health-scorer.test.js` (new), `package.json`

---

## Problem

The scoring matrix is pure math, but bugs easily creep in if not tested. The roadmap requires a deterministic test suite using `vitest` (or `jest`).

---

## Implementation

### 1. Add vitest to package.json

```json
{
  "devDependencies": {
    "vitest": "^1.0.0"
  },
  "scripts": {
    "test": "vitest run"
  }
}
```

### 2. Write the test suite

```js
// test/health-scorer.test.js
import { describe, it, expect } from 'vitest';
import { computeRiskScore } from '../extension/lib/health-scorer.js';

describe('computeRiskScore', () => {
  it('caps at 100', () => {
    const result = {
      updatedAt: new Date().toISOString(),
      findings: [
        { severity: 'critical' }, { severity: 'critical' },
        { severity: 'critical' }, { severity: 'critical' }
      ]
    };
    expect(computeRiskScore(result)).toBe(100);
  });

  it('adds 60 for GitFilesResponse vulnerable', () => {
    const result = {
      updatedAt: new Date().toISOString(),
      probeResults: [{ label: 'GitFilesResponse', signature: 'vulnerable' }],
      findings: []
    };
    expect(computeRiskScore(result)).toBe(60); // Assuming >30d old
  });

  it('adds 10 temporal bonus if updated recently and not all patched', () => {
    const result = {
      updatedAt: new Date().toISOString(), // Just now
      probeResults: [{ label: 'GetProject', signature: 'inconclusive' }],
      findings: []
    };
    expect(computeRiskScore(result)).toBe(10);
  });

  it('zeroes temporal bonus if all patched', () => {
    const result = {
      updatedAt: new Date().toISOString(),
      probeResults: [{ label: 'GetProject', signature: 'patched' }],
      findings: []
    };
    expect(computeRiskScore(result)).toBe(0);
  });
});
```

---

## Acceptance Criteria

- [ ] `npm test` runs the suite successfully
- [ ] Tests cover capping, temporal bonus, and all probe tiers
- [ ] Tests cover findings summation (critical +30, high +20, etc.)
