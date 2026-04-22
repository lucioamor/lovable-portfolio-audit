# Skill: Masking Algo Alignment

> **Roadmap refs:** §5.4  
> **Complexity:** Small  
> **Files affected:** `extension/lib/masking.js`

---

## Problem

We need to ensure the masking algorithm used in `masking.js` behaves *exactly* as specified in the roadmap for all edge cases, and add unit tests to prove it.

Roadmap specification:
```text
maskSecret(value):
  if value.length <= 12:  value[:3] + "•" * (length-3)
  else:                   value[:4] + "•" * (length-8) + value[-4:]
```

---

## Implementation

### 1. Verify and tighten `masking.js`

```js
export function maskSecret(value) {
  if (!value || typeof value !== 'string') return '•••';
  
  const len = value.length;
  if (len <= 3) return '•'.repeat(len); // Edge case not explicitly in roadmap, but logical
  
  if (len <= 12) {
    return value.slice(0, 3) + '•'.repeat(len - 3);
  }
  
  return value.slice(0, 4) + '•'.repeat(len - 8) + value.slice(-4);
}
```

### 2. Unit Tests (requires `skill-scorer-tests.md`)

```js
// test/masking.test.js
import { describe, it, expect } from 'vitest';
import { maskSecret } from '../extension/lib/masking.js';

describe('maskSecret', () => {
  it('masks short strings (length <= 12)', () => {
    expect(maskSecret('12345678')).toBe('123•••••');
    expect(maskSecret('123456789012')).toBe('123•••••••••');
  });

  it('masks long strings (length > 12)', () => {
    expect(maskSecret('1234567890123456')).toBe('1234••••••••3456');
    expect(maskSecret('sk_live_1234567890abcdef')).toBe('sk_l••••••••••••cdef');
  });

  it('handles edge cases', () => {
    expect(maskSecret('12')).toBe('••');
    expect(maskSecret(null)).toBe('•••');
    expect(maskSecret('')).toBe('•••');
  });
});
```

---

## Acceptance Criteria

- [ ] Implementation exactly matches the `length <= 12` vs `length > 12` logic
- [ ] Number of characters in the output string exactly matches the input string
- [ ] Edge cases (null, extremely short strings) do not throw errors
