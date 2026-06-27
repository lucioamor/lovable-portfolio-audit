// ============================================================
// A5 / H3 — Pattern drift-check (runs in the main test suite → CI gate)
// ============================================================
import { describe, it, expect } from 'vitest';
import { compareCatalogs, normalizeRegex } from '../scripts/pattern-drift-core.mjs';
import { SECRET_PATTERNS, PII_PATTERNS } from '../packages/cli/src/engines/patterns';
import { FALLBACK_BUILTIN } from '../extension/lib/skills/pattern-catalog.js';

describe('normalizeRegex', () => {
  it('strips \\b and a whole-spanning capture group', () => {
    expect(normalizeRegex('\\b(AKIA[0-9A-Z]{16})\\b')).toBe('AKIA[0-9A-Z]{16}');
  });
  it('does not unwrap a non-capturing leading group', () => {
    expect(normalizeRegex('(?:a|b)c')).toBe('(?:a|b)c');
  });
  it('does not unwrap an inner capture group', () => {
    expect(normalizeRegex('(?:password|pwd)\\s*[:=]\\s*(["\'])'))
      .toBe('(?:password|pwd)\\s*[:=]\\s*(["\'])');
  });
});

describe('pattern catalog drift (extension ↔ CLI)', () => {
  const cli = [...SECRET_PATTERNS, ...PII_PATTERNS];
  const { errors, warnings } = compareCatalogs(cli, FALLBACK_BUILTIN as any);

  it('has no severity/regex drift on mapped patterns', () => {
    if (errors.length) console.error('Drift errors:\n' + errors.join('\n'));
    expect(errors).toEqual([]);
  });

  it('reports unmapped high-impact patterns only as warnings (non-fatal)', () => {
    // Warnings are allowed but logged so they don't silently accumulate.
    if (warnings.length) console.warn('Drift warnings:\n' + warnings.join('\n'));
    expect(Array.isArray(warnings)).toBe(true);
  });
});
