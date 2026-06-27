// ============================================================
// P19 — Pre-commit token scanner (unit tests)
// ============================================================
import { describe, it, expect } from 'vitest';
import { scanDiff, mask } from '../scripts/pre-commit-token-scan.mjs';

// Build a minimal `git diff --cached --unified=0` fragment for one file.
function diffFor(file, addedLines) {
  const header = [
    `diff --git a/${file} b/${file}`,
    `index 0000000..1111111 100644`,
    `--- a/${file}`,
    `+++ b/${file}`,
    `@@ -0,0 +1,${addedLines.length} @@`,
  ];
  return [...header, ...addedLines.map((l) => '+' + l)].join('\n');
}

describe('mask()', () => {
  it('never reveals the full secret', () => {
    const raw = 'sk_live_test_0123456789abcdef0123456789';
    const masked = mask(raw);
    expect(masked).not.toBe(raw);
    expect(masked).not.toContain('456789abcdef0123456789');
    expect(masked).toContain('•');
    // Shows only a short head/tail.
    expect(masked.startsWith('sk_l')).toBe(true);
    expect(masked.endsWith('6789')).toBe(true);
  });

  it('fully masks short values', () => {
    expect(mask('abc')).toBe('•••');
    expect(mask('12345678')).toBe('••••••••');
  });
});

describe('scanDiff() — secret detection on added lines', () => {
  it('flags a Stripe live secret key', () => {
    const diff = diffFor(
      'src/pay.js',
      ['const key = "sk_live_test_0123456789abcdefABCDEF99";'],
    );
    const findings = scanDiff(diff);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const f = findings.find((x) => x.ruleId === 'stripe_live');
    expect(f).toBeTruthy();
    expect(f.file).toBe('src/pay.js');
    // Masking invariant: the raw key body is not present.
    expect(f.masked).not.toContain('test_0123456789abcdefABCDEF99');
  });

  it('flags a service_role / JWT-shaped token', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.abcDEF1234567890xyzQ';
    const diff = diffFor('src/config.ts', [`const SR = "${jwt}";`]);
    const findings = scanDiff(diff);
    const f = findings.find((x) => x.ruleId === 'jwt');
    expect(f).toBeTruthy();
    expect(f.masked).not.toContain(jwt);
  });

  it('flags a postgres:// URL with credentials', () => {
    const diff = diffFor('db.js', [
      'const u = "postgres://admin:s3cretPW@db.internal.host:5432/app";',
    ]);
    const findings = scanDiff(diff);
    expect(findings.some((x) => x.ruleId === 'postgres_url')).toBe(true);
  });

  it('flags an AWS access key id and a GitHub PAT', () => {
    const diff = diffFor('aws.js', [
      'const id = "AKIAIOSFODNN7EXAMPLE9";', // shaped like AKIA + 16
      'const tok = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";',
    ]);
    const findings = scanDiff(diff);
    // AKIA line contains "EXAMPLE" → suppressed by the false-positive guard,
    // so only the GitHub PAT should remain.
    expect(findings.some((x) => x.ruleId === 'github_pat')).toBe(true);
  });
});

describe('scanDiff() — anti-log-de-token detection', () => {
  it('flags console.log of a token', () => {
    const diff = diffFor('auth.js', ['console.log("debug token", token);']);
    const findings = scanDiff(diff);
    const f = findings.find((x) => x.ruleId === 'log_token');
    expect(f).toBeTruthy();
    expect(f.kind).toBe('log');
  });

  it('flags logging an Authorization / Bearer value', () => {
    const diff = diffFor('http.js', [
      'console.error("Authorization:", req.headers.authorization);',
    ]);
    const findings = scanDiff(diff);
    expect(findings.some((x) => x.ruleId === 'log_authorization')).toBe(true);
  });
});

describe('scanDiff() — clean and false-positive guards', () => {
  it('returns no findings for a clean diff', () => {
    const diff = diffFor('util.js', [
      'export function add(a, b) {',
      '  return a + b;',
      '}',
    ]);
    expect(scanDiff(diff)).toEqual([]);
  });

  it('ignores example / placeholder lines', () => {
    const diff = diffFor('README.md', [
      'STRIPE_KEY=sk_live_example_placeholder_value_here',
      'const token = "your-token-here";',
    ]);
    expect(scanDiff(diff)).toEqual([]);
  });

  it('ignores secrets added under test/ fixture paths', () => {
    const diff = diffFor('test/fixtures/secrets.js', [
      'const key = "sk_live_test_0123456789abcdefABCDEF99";',
    ]);
    expect(scanDiff(diff)).toEqual([]);
  });

  it('does not inspect removed lines or the +++ header', () => {
    // A removed line carrying a secret must NOT be flagged.
    const diff = [
      'diff --git a/old.js b/old.js',
      '--- a/old.js',
      '+++ b/old.js',
      '@@ -1 +0,0 @@',
      '-const key = "sk_live_test_0123456789abcdefABCDEF99";',
    ].join('\n');
    expect(scanDiff(diff)).toEqual([]);
  });

  it('handles empty / undefined input', () => {
    expect(scanDiff('')).toEqual([]);
    expect(scanDiff(undefined)).toEqual([]);
  });
});
