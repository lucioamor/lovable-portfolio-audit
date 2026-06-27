import { describe, it, expect } from 'vitest';
import { maskSecret } from '../extension/lib/masking.js';

describe('maskSecret', () => {
  it('masks short strings (length <= 12)', () => {
    expect(maskSecret('12345678')).toBe('123•••••');
    expect(maskSecret('123456789012')).toBe('123•••••••••');
  });

  it('masks long strings (length > 12)', () => {
    expect(maskSecret('1234567890123456')).toBe('1234••••••••3456');
    expect(maskSecret('sk_live_1234567890abcdef')).toBe('sk_l••••••••••••••••cdef');
  });

  it('handles edge cases', () => {
    expect(maskSecret('12')).toBe('••');
    expect(maskSecret('1')).toBe('•');
    expect(maskSecret(null)).toBe('•••');
    expect(maskSecret('')).toBe('•••');
    expect(maskSecret(undefined)).toBe('•••');
    expect(maskSecret(12345)).toBe('•••');
  });
});
