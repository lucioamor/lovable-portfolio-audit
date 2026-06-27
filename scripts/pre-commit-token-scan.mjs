#!/usr/bin/env node
// ============================================================
// P19 — Pre-commit anti-token-log scanner
// ============================================================
// Scans the STAGED diff for two classes of problem on ADDED lines only:
//   1. High-confidence secret strings (service_role JWT, sk_live_, sk-,
//      sk-ant-, AKIA, ghp_, PEM private key, postgres:// creds URL,
//      generic password=/secret= assignments).
//   2. "Anti-log-de-token" — newly added lines that log a token/secret
//      (console.log/info/etc. of something named token/secret/Authorization,
//      or logging a literal Bearer value).
//
// On any hit it prints the file, a MASKED snippet (raw secret never echoed),
// and the rule name, then exits 1 to block the commit. Exits 0 when clean.
//
// Escape hatch: set NXLV_SKIP_TOKEN_SCAN=1 to bypass the scan.
//
// Dependency-free. The detection lives in scanDiff() (pure, unit-testable);
// the CLI wrapper below shells out to git only when run directly.
// ============================================================

import { execFileSync } from 'node:child_process';

// ---- Detection rules -------------------------------------------------------

// High-confidence secret value patterns. Each captures the secret-shaped text
// so it can be masked. Anchored / shaped to keep false positives low.
export const SECRET_RULES = [
  {
    id: 'jwt',
    name: 'JWT / Supabase service_role key',
    // Three base64url segments — covers Supabase service_role + anon JWTs.
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  },
  {
    id: 'stripe_live',
    name: 'Stripe live secret key',
    regex: /\bsk_live_[A-Za-z0-9]{16,}\b/,
  },
  {
    id: 'anthropic_key',
    name: 'Anthropic API key',
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: 'openai_key',
    name: 'OpenAI API key',
    // sk- followed by a long token; excludes sk-ant- (handled above) is fine —
    // both are secrets, this just labels the generic case.
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/,
  },
  {
    id: 'aws_access_key',
    name: 'AWS Access Key ID',
    regex: /\bAKIA[0-9A-Z]{16}\b/,
  },
  {
    id: 'github_pat',
    name: 'GitHub token',
    regex: /\bgh[pous]_[A-Za-z0-9]{36,}\b/,
  },
  {
    id: 'pem_private_key',
    name: 'PEM private key',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
  },
  {
    id: 'postgres_url',
    name: 'PostgreSQL connection string with credentials',
    regex: /postgres(?:ql)?:\/\/[^:@\s]+:[^@\s]+@[^/\s]+\/\S+/i,
  },
  {
    id: 'password_assignment',
    name: 'Hardcoded password/secret assignment',
    // key = "value" with a real-looking value; the false-positive guard below
    // drops example/placeholder values.
    regex: /(?:password|passwd|pwd|secret|api[_-]?key)\s*[:=]\s*["']([^"']{8,})["']/i,
  },
];

// Logging-of-token rules. These flag a *log call* that includes a token/secret
// reference, not the secret value itself. They don't capture a secret group.
export const LOG_RULES = [
  {
    id: 'log_token',
    name: 'Logging a token/secret value',
    // console.log/info/debug/warn/error( ... token|secret|apiKey|password ... )
    regex: /console\.(?:log|info|debug|warn|error|trace)\s*\([^)]*\b(?:token|secret|api[_-]?key|password|passwd|pwd)\b/i,
  },
  {
    id: 'log_authorization',
    name: 'Logging an Authorization / Bearer value',
    regex: /console\.(?:log|info|debug|warn|error|trace)\s*\([^)]*\b(?:authorization|bearer)\b/i,
  },
];

// Substrings that mark a line as a benign example / fixture / placeholder.
const FALSE_POSITIVE_MARKERS = [
  'example',
  'placeholder',
  'test-token',
  'test_token',
  'your-token',
  'your_token',
  'your-key',
  'your_key',
  'xxxx',
  'dummy',
  'redacted',
  'changeme',
];

// File paths (post-`+++ b/`) that are test/example territory — added secrets
// there are fixtures, not real leaks.
function isFixturePath(file) {
  if (!file) return false;
  const f = file.replace(/\\/g, '/').toLowerCase();
  return (
    f.startsWith('test/') ||
    f.includes('/test/') ||
    f.startsWith('tests/') ||
    f.includes('/tests/') ||
    f.includes('__tests__/') ||
    f.includes('/fixtures/') ||
    f.startsWith('fixtures/') ||
    /\.test\.[cm]?[jt]sx?$/.test(f) ||
    /\.spec\.[cm]?[jt]sx?$/.test(f) ||
    f.endsWith('.example') ||
    f.endsWith('.sample')
  );
}

function looksLikeExample(line) {
  const lower = line.toLowerCase();
  return FALSE_POSITIVE_MARKERS.some((m) => lower.includes(m));
}

/**
 * Mask a secret value so the raw text never leaves this process.
 * Shows a few leading/trailing chars only.
 */
export function mask(raw) {
  const s = String(raw ?? '');
  if (s.length <= 8) return '•'.repeat(Math.max(s.length, 3));
  const start = s.slice(0, 4);
  const end = s.slice(-4);
  return `${start}${'•'.repeat(Math.max(4, s.length - 8))}${end}`;
}

// ---- Pure scanner ----------------------------------------------------------

/**
 * Scan a `git diff --cached --unified=0` text for secret/log violations.
 * Only ADDED lines (starting with a single `+`, not the `+++` file header)
 * are inspected.
 *
 * @param {string} diffText
 * @returns {Array<{file: string, line: string, ruleId: string, ruleName: string, masked: string, kind: 'secret'|'log'}>}
 */
export function scanDiff(diffText) {
  const findings = [];
  if (!diffText) return findings;

  let currentFile = '';
  const lines = String(diffText).split('\n');

  for (const raw of lines) {
    // Track the file being added/modified.
    if (raw.startsWith('+++ ')) {
      // Format: "+++ b/path/to/file" or "+++ /dev/null"
      const m = raw.slice(4).trim();
      currentFile = m === '/dev/null' ? '' : m.replace(/^b\//, '');
      continue;
    }
    if (raw.startsWith('--- ')) continue;

    // Only added content lines (exactly one leading '+').
    if (!raw.startsWith('+') || raw.startsWith('+++')) continue;

    const added = raw.slice(1); // strip the leading '+'

    // Skip obvious fixtures / examples to keep false positives low.
    const inFixture = isFixturePath(currentFile);
    const exampleLine = looksLikeExample(added);

    // Secret-value rules (skipped for fixtures/examples).
    if (!inFixture && !exampleLine) {
      for (const rule of SECRET_RULES) {
        const m = rule.regex.exec(added);
        if (m) {
          const secret = m[1] || m[0];
          findings.push({
            file: currentFile || '(unknown)',
            line: added.trim(),
            ruleId: rule.id,
            ruleName: rule.name,
            masked: mask(secret),
            kind: 'secret',
          });
        }
      }
    }

    // Log-of-token rules (apply even in non-test source; still skip fixtures
    // and example lines to avoid flagging documented samples).
    if (!inFixture && !exampleLine) {
      for (const rule of LOG_RULES) {
        if (rule.regex.test(added)) {
          findings.push({
            file: currentFile || '(unknown)',
            line: added.trim(),
            ruleId: rule.id,
            ruleName: rule.name,
            masked: mask(added.trim()),
            kind: 'log',
          });
        }
      }
    }
  }

  return findings;
}

// ---- CLI wrapper -----------------------------------------------------------

const STAGED_DIFF_ARGS = ['diff', '--cached', '--unified=0', '--no-color'];

function getStagedDiff() {
  try {
    return execFileSync('git', STAGED_DIFF_ARGS, {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch (err) {
    // Not a git repo, or git unavailable — nothing to scan.
    return '';
  }
}

function main() {
  if (process.env.NXLV_SKIP_TOKEN_SCAN === '1') {
    console.log('• Token scan skipped (NXLV_SKIP_TOKEN_SCAN=1).');
    process.exit(0);
  }

  const diff = getStagedDiff();
  const findings = scanDiff(diff);

  if (findings.length === 0) {
    process.exit(0);
  }

  console.error('\n✖ Pre-commit token scan blocked this commit:\n');
  for (const f of findings) {
    const tag = f.kind === 'secret' ? 'secret' : 'token-log';
    console.error(`  • [${tag}] ${f.ruleName}`);
    console.error(`      file:    ${f.file}`);
    console.error(`      snippet: ${f.masked}`);
  }
  console.error(
    '\nRemove the secret / token-logging from the staged change, or set ' +
      'NXLV_SKIP_TOKEN_SCAN=1 to bypass (only when you are certain it is safe).\n',
  );
  process.exit(1);
}

// Run main only when invoked directly, not when imported by tests.
const invokedDirectly =
  process.argv[1] && import.meta.url === new URL(`file://${process.argv[1].replace(/\\/g, '/')}`).href;

if (invokedDirectly || process.argv[1]?.endsWith('pre-commit-token-scan.mjs')) {
  main();
}
