// ============================================================
// A5 / H3 — Pattern drift-check (core logic)
// ============================================================
// The extension (extension/lib/skills/pattern-catalog.js builtin) and the CLI
// (packages/cli/src/engines/patterns.ts) maintain two pattern catalogs with
// different id schemes. This module verifies that the LOGICALLY EQUIVALENT
// patterns stay in sync on severity and regex shape. If someone edits a
// pattern in one channel without the other, the normalized cores diverge and
// the check fails — which is exactly what CI should catch.
//
// Pure: takes the two catalogs as input, returns { errors, warnings }.
// ============================================================

// Equivalent (cliId ↔ extId) pairs compared on BOTH severity and regex core.
export const PAIRS = [
  // secrets
  { cliId: 'SUP-001', extId: 'secret_supabase_service_role' },
  { cliId: 'STR-001', extId: 'secret_stripe_live' },
  { cliId: 'DB-001',  extId: 'secret_db_url' },
  { cliId: 'OAI-001', extId: 'secret_openai' },
  { cliId: 'ANT-001', extId: 'secret_anthropic' },
  { cliId: 'AWS-001', extId: 'secret_aws' },
  { cliId: 'GH-001',  extId: 'secret_github_pat' },
  { cliId: 'SLK-001', extId: 'secret_slack' },
  { cliId: 'SG-001',  extId: 'secret_sendgrid' },
  { cliId: 'RSN-001', extId: 'secret_resend' },
  { cliId: 'STR-002', extId: 'secret_stripe_test' },
  { cliId: 'GCP-001', extId: 'secret_google_api' },
  { cliId: 'PEM-001', extId: 'secret_pem' },
  { cliId: 'PWD-001', extId: 'secret_generic_pwd' },
  // PII
  { cliId: 'PII-001', extId: 'pii_email' },
  { cliId: 'PII-002', extId: 'pii_cpf' },
  { cliId: 'PII-004', extId: 'pii_ssn' },
];

// Pairs compared on severity only — the regex is intentionally different
// (e.g. CLI uses brand-specific card prefixes, extension uses a length heuristic).
export const SEVERITY_ONLY_PAIRS = [
  { cliId: 'PII-005', extId: 'pii_credit_card', reason: 'card regex intentionally differs (brand-specific vs heuristic)' },
];

/**
 * Strip non-semantic wrappers so two regexes that mean the same thing compare
 * equal: remove \b word boundaries and a single outer *capturing* group that
 * spans the whole expression.
 */
export function normalizeRegex(src) {
  let s = String(src).replace(/\\b/g, '').trim();

  if (s.startsWith('(') && s[1] !== '?') {
    let depth = 0;
    let end = -1;
    let inClass = false;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '\\') { i++; continue; }
      if (inClass) { if (c === ']') inClass = false; continue; }
      if (c === '[') inClass = true;
      else if (c === '(') depth++;
      else if (c === ')') { depth--; if (depth === 0) { end = i; break; } }
    }
    if (end === s.length - 1) s = s.slice(1, -1);
  }
  return s;
}

/**
 * @param cliPatterns  array of { id, severity, regex: RegExp }
 * @param extPatterns  array of { id, severity, regex: string }
 */
export function compareCatalogs(cliPatterns, extPatterns) {
  const errors = [];
  const warnings = [];

  const cliById = new Map(cliPatterns.map(p => [p.id, p]));
  const extById = new Map(extPatterns.map(p => [p.id, p]));

  for (const { cliId, extId } of PAIRS) {
    const cli = cliById.get(cliId);
    const ext = extById.get(extId);
    if (!cli) { errors.push(`CLI pattern "${cliId}" not found (mapped to extension "${extId}")`); continue; }
    if (!ext) { errors.push(`Extension pattern "${extId}" not found (mapped to CLI "${cliId}")`); continue; }

    if (cli.severity !== ext.severity) {
      errors.push(`Severity drift ${cliId}↔${extId}: CLI="${cli.severity}" vs ext="${ext.severity}"`);
    }
    const a = normalizeRegex(cli.regex.source ?? cli.regex);
    const b = normalizeRegex(ext.regex);
    if (a !== b) {
      errors.push(`Regex drift ${cliId}↔${extId}:\n      CLI: ${a}\n      ext: ${b}`);
    }
  }

  for (const { cliId, extId, reason } of SEVERITY_ONLY_PAIRS) {
    const cli = cliById.get(cliId);
    const ext = extById.get(extId);
    if (!cli) { errors.push(`CLI pattern "${cliId}" not found`); continue; }
    if (!ext) { errors.push(`Extension pattern "${extId}" not found`); continue; }
    if (cli.severity !== ext.severity) {
      errors.push(`Severity drift ${cliId}↔${extId}: CLI="${cli.severity}" vs ext="${ext.severity}" (${reason})`);
    }
  }

  // Coverage warning: any high-impact extension secret not in the mapping is
  // a silent-divergence risk — surface it (non-fatal).
  const mappedExt = new Set([...PAIRS, ...SEVERITY_ONLY_PAIRS].map(p => p.extId));
  for (const ext of extPatterns) {
    if ((ext.severity === 'catastrophic' || ext.severity === 'critical') &&
        (ext.kind === 'secret' || ext.kind === undefined) &&
        !mappedExt.has(ext.id)) {
      warnings.push(`Extension pattern "${ext.id}" (${ext.severity}) is unmapped — add it to PAIRS or confirm CLI has no equivalent.`);
    }
  }

  return { errors, warnings };
}
