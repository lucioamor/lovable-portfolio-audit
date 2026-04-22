// SKILL-09: pattern-catalog
// Patterns dinâmicos com TTL cache e toggle por pattern.
// Fallback para builtin se endpoint offline.

import { createLogger } from './structured-logger.js';

const logger = createLogger({ module: 'pattern-catalog' });
const CACHE_KEY   = 'lpa:patterns:cache';
const TOGGLE_KEY  = 'lpa:patterns:toggles';
const DEFAULT_REMOTE_URL = 'https://audit.nxlv.ai/patterns.json';
const TTL_MS = 24 * 60 * 60 * 1000;

const FALLBACK_BUILTIN = Object.freeze([
  // Secrets — Critical/Catastrophic
  { id: 'secret_supabase_service_role', kind: 'secret', severity: 'catastrophic', regex: 'eyJ[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}', flags: 'g', label: 'Supabase Service Role JWT', enabled: true },
  { id: 'secret_stripe_live',  kind: 'secret', severity: 'catastrophic', regex: 'sk_live_[A-Za-z0-9]{24,}', flags: 'g', label: 'Stripe Live Key', enabled: true },
  { id: 'secret_db_url',       kind: 'secret', severity: 'catastrophic', regex: 'postgres(?:ql)?:\\/\\/[^:]+:[^@]+@[^/]+\\/\\S+', flags: 'gi', label: 'PostgreSQL Connection String', enabled: true },
  { id: 'secret_openai',       kind: 'secret', severity: 'critical',     regex: 'sk-(?:proj-)?[A-Za-z0-9_-]{20,}', flags: 'g', label: 'OpenAI API Key', enabled: true },
  { id: 'secret_anthropic',    kind: 'secret', severity: 'critical',     regex: 'sk-ant-[A-Za-z0-9_-]{20,}', flags: 'g', label: 'Anthropic API Key', enabled: true },
  { id: 'secret_aws',          kind: 'secret', severity: 'critical',     regex: 'AKIA[0-9A-Z]{16}', flags: 'g', label: 'AWS Access Key ID', enabled: true },
  { id: 'secret_github_pat',   kind: 'secret', severity: 'critical',     regex: 'ghp_[A-Za-z0-9]{36}', flags: 'g', label: 'GitHub PAT', enabled: true },
  { id: 'secret_slack',        kind: 'secret', severity: 'critical',     regex: 'xox[baprs]-[0-9]{10,}-[A-Za-z0-9]+', flags: 'g', label: 'Slack Token', enabled: true },
  { id: 'secret_sendgrid',     kind: 'secret', severity: 'critical',     regex: 'SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}', flags: 'g', label: 'SendGrid API Key', enabled: true },
  { id: 'secret_resend',       kind: 'secret', severity: 'critical',     regex: 're_[A-Za-z0-9_-]{24,}', flags: 'g', label: 'Resend API Key', enabled: true },
  { id: 'secret_stripe_test',  kind: 'secret', severity: 'high',         regex: 'sk_test_[A-Za-z0-9]{24,}', flags: 'g', label: 'Stripe Test Key', enabled: true },
  { id: 'secret_google_api',   kind: 'secret', severity: 'high',         regex: 'AIza[A-Za-z0-9_-]{35}', flags: 'g', label: 'Google API Key', enabled: true },
  { id: 'secret_pem',          kind: 'secret', severity: 'catastrophic', regex: '-----BEGIN (?:RSA|EC|OPENSSH)? ?PRIVATE KEY-----', flags: 'g', label: 'PEM Private Key', enabled: true },
  { id: 'secret_generic_pwd',  kind: 'secret', severity: 'high',         regex: '(?:password|passwd|secret)\\s*[:=]\\s*["\']([^"\']{8,})["\']', flags: 'gi', label: 'Generic Password', enabled: true },
  // PII
  { id: 'pii_email',       kind: 'pii', severity: 'medium', regex: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}', flags: 'gi', label: 'Email address', enabled: true, falsePositiveHints: ['example@example.com', 'user@domain.com', 'test@test.com', 'noreply@'] },
  { id: 'pii_cpf',         kind: 'pii', severity: 'high',   regex: '\\b\\d{3}\\.?\\d{3}\\.?\\d{3}-?\\d{2}\\b', flags: 'g', label: 'Brazilian CPF', enabled: true },
  { id: 'pii_credit_card', kind: 'pii', severity: 'critical', regex: '\\b(?:\\d[ -]?){13,16}\\b', flags: 'g', label: 'Credit Card Number', enabled: true },
  { id: 'pii_ssn',         kind: 'pii', severity: 'high',   regex: '\\b\\d{3}-\\d{2}-\\d{4}\\b', flags: 'g', label: 'SSN (US)', enabled: true },
  // Sensitive paths
  { id: 'path_env',            kind: 'path', severity: 'critical', regex: '(^|/)\\.(env)(\\.|$)', flags: '', label: '.env file', enabled: true },
  { id: 'path_supabase_client',kind: 'path', severity: 'high',     regex: 'supabase[/\\\\]client\\.(ts|js)', flags: 'i', label: 'Supabase client init', enabled: true },
  { id: 'path_service_account',kind: 'path', severity: 'catastrophic', regex: 'serviceAccountKey\\.json', flags: 'i', label: 'Firebase Service Account', enabled: true },
].map(p => Object.freeze(p)));

async function readStorage(key) {
  const result = await chrome.storage.local.get(key);
  return result[key];
}
async function writeStorage(key, value) {
  await chrome.storage.local.set({ [key]: value });
}

function isFresh(catalog) {
  return Date.now() - new Date(catalog.fetchedAt).getTime() < TTL_MS;
}

function validateCatalog(raw) {
  if (!raw || typeof raw !== 'object') return false;
  if (typeof raw.version !== 'string') return false;
  if (!Array.isArray(raw.patterns)) return false;
  return raw.patterns.every(p =>
    typeof p.id === 'string' &&
    typeof p.regex === 'string' &&
    ['secret', 'pii', 'path', 'config'].includes(p.kind) &&
    ['catastrophic', 'critical', 'high', 'medium', 'low'].includes(p.severity)
  );
}

function buildFallback() {
  return Object.freeze({ version: 'builtin-1.1', fetchedAt: new Date().toISOString(), patterns: FALLBACK_BUILTIN });
}

export async function loadCatalog(options = {}) {
  const url = options.remoteUrl ?? DEFAULT_REMOTE_URL;

  if (!options.forceRefresh) {
    const cached = await readStorage(CACHE_KEY);
    if (cached && isFresh(cached)) {
      logger.debug('catalog from fresh cache', { version: cached.version });
      return cached;
    }
  }

  try {
    const response = await fetch(url, { credentials: 'omit', redirect: 'error' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const raw = await response.json();
    if (!validateCatalog(raw)) throw new Error('Invalid catalog schema');
    const catalog = Object.freeze({
      version: raw.version,
      fetchedAt: new Date().toISOString(),
      patterns: Object.freeze([...raw.patterns].map(p => Object.freeze(p))),
    });
    await writeStorage(CACHE_KEY, catalog);
    logger.info('catalog refreshed', { version: catalog.version, count: catalog.patterns.length });
    return catalog;
  } catch (err) {
    logger.warn('catalog refresh failed, using fallback', undefined, { error: err.message });
    const stale = await readStorage(CACHE_KEY);
    return stale ?? buildFallback();
  }
}

export async function getCatalog() {
  return (await readStorage(CACHE_KEY)) ?? buildFallback();
}

export async function togglePattern(id, enabled) {
  const toggles = (await readStorage(TOGGLE_KEY)) ?? {};
  await writeStorage(TOGGLE_KEY, { ...toggles, [id]: enabled });
  logger.info('pattern toggled', { id, enabled });
}

export async function resetToggles() {
  await writeStorage(TOGGLE_KEY, {});
}

async function applyToggles(patterns) {
  const toggles = (await readStorage(TOGGLE_KEY)) ?? {};
  return patterns.map(p => toggles[p.id] !== undefined ? { ...p, enabled: toggles[p.id] } : p);
}

export async function listPatterns(opts = {}) {
  const catalog = await getCatalog();
  let result = await applyToggles(catalog.patterns);
  if (opts.kind)        result = result.filter(p => p.kind === opts.kind);
  if (opts.enabledOnly) result = result.filter(p => p.enabled);
  return Object.freeze(result);
}

export async function buildActiveRegexSet() {
  const active = await listPatterns({ enabledOnly: true });
  return Object.freeze({
    compiledAt: new Date().toISOString(),
    patterns: Object.freeze(active.map(pattern => ({
      pattern,
      regex: new RegExp(pattern.regex, pattern.flags || 'g'),
    }))),
  });
}
