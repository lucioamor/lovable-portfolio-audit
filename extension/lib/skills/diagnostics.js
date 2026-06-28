// ============================================================
// SKILL-09: diagnostics — runtime snapshot for repair sessions
// ============================================================
// Produces a single redacted .txt report that captures everything a fresh
// debugging session needs but the source repo does NOT have: the live HTTP
// status of each Lovable endpoint (diagnoses the 405), the real observed API
// surface (the "new-endpoint candidates"), recent error logs, extension state,
// and a module inventory. Paste the .txt into a new Claude Code window to seed
// an investigative repair session.
//
// INVARIANTS: never emit a raw token/secret. Secret-bearing storage keys are
// reported as presence + byte size only. Passive findings are already masked
// at capture time. The self-test makes read-only GETs only (no writes).
// ============================================================

import { KNOWN_ENDPOINTS, normalizeLovablePath } from '../passive-endpoints.js';
import { getSessionToken, listProjects, probeEndpoint, PROBE_ENDPOINTS } from '../api-client.js';
import { setSink } from './structured-logger.js';
import { isInitialized, isUnlocked } from './token-vault.js';
import { hasConsent, LEGAL_VERSION } from './consent-gate.js';
import { listRuns } from './scan-history.js';

const LOG_KEY = 'lpa_diag_logs';
const LOG_CAP = 300;

// Storage keys whose value may contain a secret — report presence only.
const SECRET_KEY_RE = /vault|token|secret|password|passphrase/i;

// ---- Persistent log ring buffer --------------------------------------------
// Logs span two JS realms (service worker + sidepanel page). Persisting to
// storage is the only buffer both can share. Writes are serialized through a
// promise chain to avoid read-modify-write races between rapid log calls.
let writeChain = Promise.resolve();

export function recordLog(entry) {
  writeChain = writeChain.then(async () => {
    const { [LOG_KEY]: logs = [] } = await chrome.storage.local.get(LOG_KEY);
    logs.push(entry);
    await chrome.storage.local.set({ [LOG_KEY]: logs.slice(-LOG_CAP) });
  }).catch(() => {});
  return writeChain;
}

export async function getLogs() {
  const { [LOG_KEY]: logs = [] } = await chrome.storage.local.get(LOG_KEY);
  return logs;
}

export async function clearLogs() {
  await chrome.storage.local.remove(LOG_KEY);
}

// Wire the structured-logger to persist warn/error (and info for trail context).
// Call once per context (background, sidepanel).
let sinkInstalled = false;
export function installPersistentSink(contextName = 'unknown') {
  if (sinkInstalled) return;
  sinkInstalled = true;
  setSink((entry) => { recordLog({ ...entry, context: { ...entry.context, _src: contextName } }); });
}

// ---- Endpoint self-test ----------------------------------------------------
// Read-only GETs against the documented surface. This is what reveals the 405:
// it records the literal status the live API returns for each path/method.
export async function runSelfTest() {
  const out = [];
  let token = null;
  try { token = await getSessionToken(); } catch (_) {}
  out.push({ check: 'session-token', present: !!token, note: token ? 'cookie/vault token found' : 'NO TOKEN — log in to lovable.dev or unlock vault' });

  const list = await probeEndpoint('/user/projects');
  out.push({ check: 'listProjects', method: 'GET', path: '/user/projects', status: list.status, ok: list.ok,
    note: list.status === 405 ? 'METHOD NOT ALLOWED — endpoint/method likely changed; compare with observed endpoints below'
        : list.status === 401 || list.status === 403 ? 'AUTH REJECTED — token missing/expired'
        : list.ok ? 'ok' : `unexpected status ${list.status}` });

  // Resolve a sample project id via the RESILIENT client (workspace-scoped
  // search, shared/starred fallbacks). This deliberately does NOT depend on the
  // legacy /user/projects succeeding — that's the whole point: even when the
  // legacy path 405s, we still reach the project-scoped probes (git/files etc.)
  // so drift on those endpoints becomes visible instead of silently skipped.
  let sampleId = null;
  try {
    const projects = await listProjects();
    const arr = Array.isArray(projects) ? projects : (projects?.projects || projects?.data || []);
    sampleId = arr?.[0]?.id || arr?.[0]?.projectId || null;
    out.push({ check: 'listProjects-resilient', ok: !!arr.length, count: arr.length,
      note: arr.length ? `discovered ${arr.length} project(s) via fallback chain` : 'fallback chain returned 0 projects' });
  } catch (e) {
    out.push({ check: 'listProjects-resilient', ok: false, note: `all fallbacks failed: ${e.message}` });
  }

  const classify = (status) =>
    status === 0   ? 'network error / blocked' :
    status === 405 ? 'METHOD NOT ALLOWED — path/method drifted' :
    status === 404 ? 'NOT FOUND — path likely drifted' :
    status === 401 || status === 403 ? 'auth rejected' :
    (status >= 200 && status < 300) ? 'ok' : `unexpected status ${status}`;

  if (sampleId) {
    for (const ep of PROBE_ENDPOINTS) {
      const r = await probeEndpoint(ep.path(sampleId));
      out.push({ check: ep.label, method: 'GET', path: ep.path(sampleId).replaceAll(sampleId, ':id'),
        status: r.status, ok: r.ok, note: classify(r.status) });
    }
  } else {
    out.push({ check: 'project-scoped-probes', skipped: true, note: 'no project id from any discovery path — cannot probe git/files etc.' });
  }
  return out;
}

// ---- Drift analysis --------------------------------------------------------
// Answers two operational questions directly: "where does it err?" (known calls
// the live API now rejects) and "what's missing?" (hardcoded endpoints we've
// never actually seen live — candidates for removal or unverified assumptions).
export function buildDriftAnalysis(selfTest, observed, candidates) {
  const lines = [];

  // 1. WHERE IT ERRS — known calls that failed live during the self-test.
  const erroring = (selfTest || []).filter(t =>
    t.path && typeof t.status === 'number' && (t.status === 0 || t.status >= 400));
  lines.push('  WHERE IT ERRS — known calls that failed against the live API:');
  if (!erroring.length) lines.push('    (none — every probed known endpoint returned < 400)');
  for (const t of erroring) {
    lines.push(`    ✗ ${t.method || 'GET'} ${t.path}  →  ${t.status}  ${t.note ? '(' + t.note + ')' : ''}`);
  }

  // 2. WHAT'S MISSING — hardcoded endpoints never observed (live or via probe).
  const observedNorm = new Set(Object.keys(observed || {}).map(k => normalizeLovablePath(k)));
  const neverSeen = KNOWN_ENDPOINTS.filter(k => !observedNorm.has(k));
  lines.push('');
  lines.push(`  WHAT'S MISSING — hardcoded endpoints never seen live (${neverSeen.length}/${KNOWN_ENDPOINTS.length}):`);
  if (!neverSeen.length) lines.push('    (none — every known endpoint has been observed at least once)');
  for (const k of neverSeen) lines.push(`    ?  ${k}`);

  // 3. CAPTURED BY SCANNER — endpoints our own probes hit (incl. per-project).
  const viaProbe = Object.keys(observed || {}).filter(k => observed[k]?.viaProbe);
  lines.push('');
  lines.push(`  CAPTURED BY SCANNER — endpoints our active probes reached (${viaProbe.length}):`);
  if (!viaProbe.length) lines.push('    (none yet — run a scan or regenerate after a self-test)');
  for (const k of viaProbe.sort()) {
    const e = observed[k];
    lines.push(`    •  ${e.lastMethod || 'GET'} ${k}  →  last=${e.lastStatus ?? '—'}`);
  }

  // 4. NEW SURFACE — observed paths the extension does not know about.
  lines.push('');
  lines.push(`  NEW SURFACE — observed paths not in the hardcoded list: ${Object.keys(candidates || {}).length} (detailed under NEW-ENDPOINT CANDIDATES)`);

  return lines.join('\n');
}

// ---- Report assembly -------------------------------------------------------

const MODULE_INVENTORY = [
  ['background.js', 'service worker: message router, scan orchestration, passive storage, alarms'],
  ['content.js', 'content script: injects interceptor, relays masked findings, browser-state/route scan'],
  ['interceptor.js', 'page-context fetch/XHR wrap: masks + posts passive findings (no raw body crosses)'],
  ['sidepanel.js', 'main UI: tabs, scan flow, vault modals, RLS classify, export, diagnostics'],
  ['devtools-panel.js', 'live passive view: findings, observed endpoints, candidates, routes'],
  ['lib/api-client.js', 'Lovable API: getSessionToken, listProjects, probeEndpoint, BOLA probes'],
  ['lib/audit-engine.js', 'runScan, scanProject, severity scoring, demo data'],
  ['lib/passive-endpoints.js', 'KNOWN_ENDPOINTS registry + normalizeLovablePath (5th-endpoint detection)'],
  ['lib/evidence-pack.js', 'signed evidence-pack export (HMAC over results)'],
  ['lib/skills/structured-logger.js', 'redacting logger + persistent sink'],
  ['lib/skills/diagnostics.js', 'this module: log ring, self-test, report builder'],
  ['lib/skills/token-vault.js', 'AES-256-GCM token vault (PBKDF2)'],
  ['lib/skills/consent-gate.js', 'legal/safe-mode consent gating'],
  ['lib/skills/pattern-catalog.js', 'detection pattern catalog + toggles'],
  ['lib/skills/rls-checklist.js', 'deep RLS audit SQL + classifier'],
  ['lib/skills/scan-history.js', 'run history persistence + delta'],
  ['lib/skills/dual-probe.js', 'cross-account BOLA confirmation'],
  ['lib/skills/rationale-logger.js', 'per-project scoring rationale'],
  ['lib/skills/secret-hasher.js', 'SHA-256 hashing for findings'],
];

const line = (s = '') => s;
const rule = (c = '─') => c.repeat(64);

function section(title) {
  return `\n${rule()}\n## ${title}\n${rule()}`;
}

function safeJson(value, max = 4000) {
  let s;
  try { s = JSON.stringify(value, null, 2); } catch { s = String(value); }
  return s.length > max ? s.slice(0, max) + `\n… [truncated, ${s.length} chars total]` : s;
}

async function gatherStorage() {
  const all = await chrome.storage.local.get(null);
  const keys = Object.keys(all).sort();
  const lines = [];
  for (const k of keys) {
    const v = all[k];
    const size = (() => { try { return JSON.stringify(v).length; } catch { return -1; } })();
    if (SECRET_KEY_RE.test(k)) {
      lines.push(`  ${k}: [REDACTED — present, ${size} bytes]`);
    } else if (Array.isArray(v)) {
      lines.push(`  ${k}: array(${v.length}), ${size} bytes`);
    } else if (v && typeof v === 'object') {
      lines.push(`  ${k}: object(${Object.keys(v).length} keys), ${size} bytes`);
    } else {
      lines.push(`  ${k}: ${JSON.stringify(v)}`);
    }
  }
  return { keys, lines: lines.join('\n') || '  (empty)' };
}

export async function buildReport() {
  const now = new Date().toISOString();
  const manifest = (() => { try { return chrome.runtime.getManifest(); } catch { return {}; } })();
  const ua = (typeof navigator !== 'undefined' && navigator.userAgent) || 'unknown';
  const lang = (typeof navigator !== 'undefined' && navigator.language) || 'unknown';

  const [
    vaultInit, vaultUnlocked, legal, safeMode, selfTest, storage, logs, runs,
    passive,
  ] = await Promise.all([
    isInitialized().catch(() => null),
    isUnlocked().catch(() => null),
    hasConsent('L0_legal').catch(() => null),
    hasConsent('L1_safe_mode').catch(() => null),
    runSelfTest().catch((e) => [{ check: 'self-test', ok: false, note: `self-test threw: ${e.message}` }]),
    gatherStorage(),
    getLogs(),
    listRuns(20).catch(() => []),
    chrome.storage.local.get(['lpa_observed_endpoints', 'lpa_endpoint_candidates', 'lpa_passive_findings', 'lpa_passive_routes', 'lss_summary', 'lss_results', 'lpa_passive_enabled']),
  ]);

  const observed = passive.lpa_observed_endpoints || {};
  const candidates = passive.lpa_endpoint_candidates || {};
  const findings = passive.lpa_passive_findings || [];
  const routes = passive.lpa_passive_routes || {};
  const summary = passive.lss_summary || null;
  const results = passive.lss_results || [];

  const errorLogs = logs.filter(l => l.level === 'error' || l.level === 'warn');

  const findingsBySev = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {});

  const parts = [];

  parts.push(rule('═'));
  parts.push('NXLV SHIELD — EXTENSION DIAGNOSTIC REPORT');
  parts.push(rule('═'));
  parts.push(`generated:    ${now}`);
  parts.push(`extension:    ${manifest.name || '?'} v${manifest.version || '?'}`);
  parts.push(`user-agent:   ${ua}`);
  parts.push(`locale:       ${lang}`);
  parts.push('');
  parts.push('HOW TO USE THIS FILE');
  parts.push('  Paste this whole file into a new Claude Code session opened in the');
  parts.push('  lovable-portfolio-audit repo. It is a runtime snapshot — the source');
  parts.push('  is already in the repo; what follows is the live state the repo lacks.');
  parts.push('  Start from SELF-TEST and OBSERVED ENDPOINTS to debug API/scan failures.');

  parts.push(section('STATUS'));
  parts.push(line(`  session token present : ${selfTest.find(s => s.check === 'session-token')?.present ?? '?'}`));
  parts.push(line(`  vault initialized     : ${vaultInit}`));
  parts.push(line(`  vault unlocked        : ${vaultUnlocked}`));
  parts.push(line(`  legal consent (L0)    : ${legal}  (terms ${LEGAL_VERSION})`));
  parts.push(line(`  safe-mode consent (L1): ${safeMode}`));
  parts.push(line(`  passive sensor on     : ${!!passive.lpa_passive_enabled}`));
  parts.push(line(`  scan results stored   : ${results.length}`));

  parts.push(section('SELF-TEST — live endpoint status (read-only GETs)'));
  parts.push('  This is the authoritative diagnosis for "405 / scan failed".');
  for (const t of selfTest) parts.push('  ' + safeJson(t, 600).replace(/\n/g, '\n  '));

  parts.push(section('DRIFT ANALYSIS — what is missing / where it errs'));
  parts.push('  Auto-comparison of the hardcoded surface vs. what the live API and');
  parts.push('  our own probes actually returned. Fix order: WHERE IT ERRS first.');
  parts.push(buildDriftAnalysis(selfTest, observed, candidates));

  parts.push(section(`OBSERVED ENDPOINTS — real api.lovable.dev surface (${Object.keys(observed).length})`));
  parts.push('  What the page actually called. Compare against the hardcoded list in');
  parts.push('  lib/api-client.js / lib/passive-endpoints.js to find drift.');
  parts.push('  known (hardcoded): ' + KNOWN_ENDPOINTS.join(', '));
  const obsKeys = Object.keys(observed).sort((a, b) => (observed[b].count || 0) - (observed[a].count || 0));
  if (!obsKeys.length) parts.push('  (none — enable passive sensor + browse lovable.dev, then regenerate)');
  for (const k of obsKeys) {
    const e = observed[k];
    parts.push(`  ${e.lastMethod || 'GET'} ${k}  ×${e.count}  last=${e.lastStatus ?? '—'}${e.viaProbe ? '  [probe]' : ''}`);
  }

  parts.push(section(`NEW-ENDPOINT CANDIDATES — observed but NOT in hardcoded list (${Object.keys(candidates).length})`));
  parts.push('  These are the paths the extension does not know about. If listProjects');
  parts.push('  returns 405, the correct path/method is almost certainly in here.');
  const candKeys = Object.keys(candidates).sort();
  if (!candKeys.length) parts.push('  (none)');
  for (const k of candKeys) {
    const c = candidates[k];
    parts.push(`  ${c.method || 'GET'} ${k}  status=${c.status ?? '—'}  firstSeen=${c.firstSeen || '?'}`);
  }

  parts.push(section(`PASSIVE FINDINGS — masked (${findings.length})`));
  parts.push('  by severity: ' + (safeJson(findingsBySev, 300) || '{}'));
  for (const f of findings.slice(0, 40)) {
    parts.push(`  [${f.severity}] ${f.label || f.patternId} · ${f.masked} · sha256:${f.hash || '—'} · ${f.source || ''} ${f.host ? '· ' + f.host : ''}`);
  }
  if (findings.length > 40) parts.push(`  … +${findings.length - 40} more`);

  parts.push(section('PASSIVE ROUTES / DOM SINKS'));
  parts.push(safeJson(routes, 2000).replace(/^/gm, '  '));

  parts.push(section('SCAN SUMMARY'));
  parts.push(summary ? safeJson(summary, 1500).replace(/^/gm, '  ') : '  (no scan run yet)');

  if (results.length) {
    parts.push(section(`SCAN RESULTS — per project (${results.length})`));
    for (const r of results.slice(0, 30)) {
      parts.push(`  ${r.severity?.toUpperCase?.() || '?'} · ${r.projectName || r.projectId || '?'} · score=${r.riskScore ?? '—'} · files=${r.bolaFilesSignature ?? '—'} · chat=${r.bolaChatSignature ?? '—'} · findings=${(r.findings || []).length}`);
    }
  }

  parts.push(section(`SCAN HISTORY (${runs.length})`));
  for (const run of runs.slice(0, 20)) {
    parts.push(`  ${run.startedAt || '?'} · ${run.projectCount ?? '?'} projects · avg ${run.scoreAverage ?? '—'}pts · ${safeJson(run.severityCounts || {}, 200)}`);
  }
  if (!runs.length) parts.push('  (none)');

  parts.push(section(`RECENT ERRORS / WARNINGS (${errorLogs.length} of ${logs.length} log entries)`));
  if (!errorLogs.length) parts.push('  (none captured — note: only logs since last extension reload are kept)');
  for (const l of errorLogs.slice(-60)) {
    parts.push(`  ${l.timestamp} [${l.level.toUpperCase()}] ${l.message}`);
    if (l.context && Object.keys(l.context).length) parts.push('      ctx: ' + safeJson(l.context, 400));
    if (l.stack) parts.push('      ' + String(l.stack).split('\n').slice(0, 4).join('\n      '));
  }

  parts.push(section(`FULL LOG TRAIL (last ${Math.min(logs.length, 120)})`));
  for (const l of logs.slice(-120)) {
    parts.push(`  ${l.timestamp} [${l.level.toUpperCase()}] ${l.message}`);
  }

  parts.push(section('STORAGE KEYS'));
  parts.push(storage.lines);

  parts.push(section('MANIFEST (permissions)'));
  parts.push('  permissions:      ' + (manifest.permissions || []).join(', '));
  parts.push('  host_permissions: ' + (manifest.host_permissions || []).join(', '));

  parts.push(section('MODULE INVENTORY'));
  for (const [file, role] of MODULE_INVENTORY) parts.push(`  ${file}\n      ${role}`);

  parts.push('');
  parts.push(rule('═'));
  parts.push('END OF REPORT');
  parts.push(rule('═'));

  return parts.join('\n');
}
