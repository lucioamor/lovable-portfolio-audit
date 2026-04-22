// SKILL-05: consent-gate
// Três níveis de consentimento como guards explícitos antes de ações sensíveis.
// L0 = aceite legal (permanente), L1 = safe-mode (24h), L2 = deep-inspect (15min, por scan)

import { createLogger } from './structured-logger.js';

const logger = createLogger({ module: 'consent-gate' });
const STORAGE_KEY = 'lpa:consents';
export const LEGAL_VERSION = '2026.04.21';

const TTL_MS = {
  L0_legal:         null,
  L1_safe_mode:     24 * 60 * 60 * 1000,
  L2_deep_inspect:  15 * 60 * 1000,
};

async function readAll() {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  return result[STORAGE_KEY] ?? {};
}

async function writeAll(records) {
  await chrome.storage.local.set({ [STORAGE_KEY]: records });
}

const consentKey = (level, scope) => scope ? `${level}:${scope}` : level;

const isExpired = (r) => r.expiresAt ? Date.now() > new Date(r.expiresAt).getTime() : false;

export async function hasConsent(level, scope) {
  const all = await readAll();
  const record = all[consentKey(level, scope)];
  if (!record) return false;
  if (isExpired(record)) return false;
  if (level === 'L0_legal' && record.version !== LEGAL_VERSION) return false;
  return true;
}

export async function grantConsent(level, scope) {
  const ttl = TTL_MS[level];
  const now = new Date();
  const record = Object.freeze({
    level, scope,
    grantedAt: now.toISOString(),
    expiresAt: ttl ? new Date(now.getTime() + ttl).toISOString() : null,
    version: LEGAL_VERSION,
  });
  const all = await readAll();
  all[consentKey(level, scope)] = record;
  await writeAll(all);
  logger.info('consent granted', { level, scope });
  return record;
}

export async function revokeConsent(level, scope) {
  const all = await readAll();
  delete all[consentKey(level, scope)];
  await writeAll(all);
  logger.info('consent revoked', { level, scope });
}

export async function listActiveConsents() {
  const all = await readAll();
  return Object.values(all).filter(r => !isExpired(r));
}

export async function requireConsent(level, scope) {
  if (!(await hasConsent(level, scope))) {
    throw new Error(`Consent required: ${level}${scope ? ':' + scope : ''}`);
  }
}
