// ============================================================
// Lovable Portfolio Audit — API Client (Chrome Extension)
// Uses chrome.cookies for automatic auth, bypasses CORS
// ============================================================

import { log } from './logger.js';
import { normalizeLovablePath, isKnownEndpoint } from './passive-endpoints.js';

const API_BASE = 'https://api.lovable.dev';
const USER_AGENT = 'NXLV-Audit/1.0 (+https://github.com/lucioamorim/lovable-portfolio-audit)';

let sessionToken = null;
let auditToken = null;
let lastRequestTime = 0;
let requestDelay = 500;

export function setDelay(ms) { requestDelay = Math.max(200, ms); }
export function setAuditToken(token) { auditToken = token; }
export function hasAuditToken() { return !!auditToken; }

export async function getSessionToken() {
  try {
    const cookie = await chrome.cookies.get({
      url: 'https://lovable.dev',
      name: '__lovable_session'
    });
    if (cookie?.value) {
      sessionToken = cookie.value;
      return sessionToken;
    }
    // Fallback: try other common cookie names
    for (const name of ['sb-access-token', 'supabase-auth-token', 'session']) {
      const alt = await chrome.cookies.get({ url: 'https://lovable.dev', name });
      if (alt?.value) { sessionToken = alt.value; return sessionToken; }
    }
    // Fallback: try to get from storage (manual input)
    const stored = await chrome.storage.local.get('lss_manual_token');
    if (stored.lss_manual_token) { sessionToken = stored.lss_manual_token; return sessionToken; }
    return null;
  } catch (e) {
    log.error('Failed to get session:', e);
    return null;
  }
}

export function hasSession() { return !!sessionToken; }

async function throttle() {
  const elapsed = Date.now() - lastRequestTime;
  if (elapsed < requestDelay) {
    await new Promise(r => setTimeout(r, requestDelay - elapsed));
  }
  lastRequestTime = Date.now();
}

async function apiRequest(path) {
  await throttle();
  const headers = { 'Content-Type': 'application/json', 'X-Client': USER_AGENT };
  if (sessionToken) {
    headers['Authorization'] = `Bearer ${sessionToken}`;
    headers['Cookie'] = `__lovable_session=${sessionToken}`;
  }
  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, { headers, credentials: 'include' });
  } catch (e) {
    recordActiveProbe(path, 'GET', 0); // network error — capture as "where it errs"
    throw e;
  }
  recordActiveProbe(path, 'GET', res.status);
  return res;
}

// ---- Active-probe endpoint registry ----------------------------------------
// Feeds the SAME registry the passive sensor uses (lpa_observed_endpoints /
// lpa_endpoint_candidates), but tagged viaProbe so the diagnostic can tell
// "the page called this" apart from "our scanner called this". This is how
// per-project endpoints (e.g. /projects/:id/git/files) get captured even when
// the user never opened a project in the Lovable UI.
let _probeWriteChain = Promise.resolve();
export function recordActiveProbe(rawPath, method, status) {
  _probeWriteChain = _probeWriteChain.then(async () => {
    try {
      if (typeof chrome === 'undefined' || !chrome.storage?.local) return;
      const path = normalizeLovablePath(rawPath);
      if (!path.startsWith('/')) return;
      const store = await chrome.storage.local.get(['lpa_observed_endpoints', 'lpa_endpoint_candidates']);
      const observed = store.lpa_observed_endpoints || {};
      const candidates = store.lpa_endpoint_candidates || {};
      const prev = observed[path] || { count: 0 };
      observed[path] = {
        count: prev.count + 1,
        lastStatus: status ?? prev.lastStatus ?? null,
        lastMethod: method || prev.lastMethod || 'GET',
        lastSeen: new Date().toISOString(),
        viaProbe: true,
      };
      const updates = { lpa_observed_endpoints: observed };
      if (!isKnownEndpoint(path) && !candidates[path]) {
        candidates[path] = { firstSeen: new Date().toISOString(), method: method || 'GET', status: status ?? null, viaProbe: true };
        updates.lpa_endpoint_candidates = candidates;
      }
      await chrome.storage.local.set(updates);
    } catch (_) { /* best-effort telemetry; never block a scan */ }
  }).catch(() => {});
  return _probeWriteChain;
}

async function auditRequest(path) {
  await throttle();
  if (!auditToken) return null;
  const headers = {
    'Content-Type': 'application/json',
    'X-Client': USER_AGENT,
    'Authorization': `Bearer ${auditToken}`,
  };
  try {
    return await fetch(`${API_BASE}${path}`, { headers });
  } catch { return null; }
}

function extractWorkspaceId(observedEndpoints) {
  for (const path of Object.keys(observedEndpoints || {})) {
    // Match any workspace ID — base62 (e.g. l6ZW8RppJ5fCDjTMEr0r) or legacy workspace_xxx
    const m = path.match(/\/workspaces\/([A-Za-z0-9_-]{4,})\//);
    if (m && m[1] !== ':id') return m[1];
  }
  return null;
}

function normalizeProjectList(data) {
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.projects)) return data.projects;
  if (data && Array.isArray(data.data)) return data.data;
  return [];
}

export async function listProjects() {
  // 1. Legacy path
  const legacyRes = await apiRequest('/user/projects');
  if (legacyRes.ok) return normalizeProjectList(await legacyRes.json());

  // 2. Collect workspace IDs from multiple sources
  const workspaceIds = new Set();

  // 2a. Active workspace detected from SPA navigation (most reliable)
  const { lpa_active_workspace, lpa_observed_endpoints } =
    await chrome.storage.local.get(['lpa_active_workspace', 'lpa_observed_endpoints']);
  if (lpa_active_workspace?.id) workspaceIds.add(lpa_active_workspace.id);

  // 2b. Enumerate workspaces the user belongs to. /user/workspaces is the one
  //     observed returning 200; the bare /workspaces collection 404s, so try the
  //     working path first and keep the other only as a recovery probe.
  for (const wsListPath of ['/user/workspaces', '/workspaces']) {
    try {
      const wsListRes = await apiRequest(wsListPath);
      if (!wsListRes.ok) continue;
      const wsData = await wsListRes.json();
      const wsArray = Array.isArray(wsData) ? wsData
        : (wsData?.workspaces || wsData?.data || []);
      for (const ws of wsArray) {
        const id = ws?.id || ws?.workspace_id;
        if (id) workspaceIds.add(id);
      }
      if (workspaceIds.size) break;
    } catch (_) {}
  }

  // 2c. Extract from passively-observed endpoints (catches IDs seen before this session)
  const passiveId = extractWorkspaceId(lpa_observed_endpoints);
  if (passiveId) workspaceIds.add(passiveId);

  // 3. Try workspace-scoped project search for each discovered workspace
  for (const wsId of workspaceIds) {
    try {
      const wsRes = await apiRequest(`/workspaces/${wsId}/projects/search`);
      if (wsRes.ok) {
        const data = normalizeProjectList(await wsRes.json());
        if (data.length > 0) return data;
      }
    } catch (_) {}
  }

  // 4. Last resort: shared/starred collections (mix of own + other users' projects
  //    shared with you — scan results reflect that limitation). Try v2 first since
  //    the v1 paths are the ones that drifted.
  for (const sharedPath of ['/v2/user/projects/shared', '/user/projects/shared', '/v2/user/projects/starred']) {
    try {
      const sharedRes = await apiRequest(sharedPath);
      if (sharedRes.ok) {
        const data = normalizeProjectList(await sharedRes.json());
        if (data.length > 0) return data;
      }
    } catch (_) {}
  }

  const hint = legacyRes.status === 401 || legacyRes.status === 403
    ? ' — auth rejected; log in to lovable.dev or unlock your token vault.'
    : ' — API surface changed; no fallback succeeded. Open Settings → Diagnostics for observed endpoints.';
  throw new Error(`listProjects failed: ${legacyRes.status}${hint}`);
}

export async function probeEndpoint(path) {
  try {
    const res = await apiRequest(path);
    return { status: res.status, ok: res.ok, contentLength: parseInt(res.headers.get('content-length') || '0') };
  } catch { return { status: 0, ok: false, contentLength: 0 }; }
}

// The bare `/git/files` listing started returning 422 (unprocessable) — the
// endpoint now expects a git ref. Rather than hard-fail (which zeroed out the
// file scan for every project and made every result a meaningless constant),
// walk a small fallback chain of documented ref variants and return the first
// that yields a usable listing. Each attempt is still recorded by apiRequest →
// recordActiveProbe, so the diagnostic keeps seeing the drift.
const GIT_FILES_VARIANTS = [
  (id) => `/projects/${id}/git/files`,
  (id) => `/projects/${id}/git/files?ref=main`,
  (id) => `/projects/${id}/git/files?ref=master`,
  (id) => `/projects/${id}/git/files?ref=HEAD`,
];

function normalizeFileList(data) {
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.files)) return data.files;
  if (data && Array.isArray(data.tree)) return data.tree;
  if (data && Array.isArray(data.data)) return data.data;
  return null;
}

export async function getProjectFiles(projectId) {
  let lastStatus = null;
  for (const variant of GIT_FILES_VARIANTS) {
    let res;
    try { res = await apiRequest(variant(projectId)); } catch { continue; }
    lastStatus = res.status;
    if (res.ok) {
      try {
        const list = normalizeFileList(await res.json());
        if (list) return list;
      } catch { /* not JSON — try next variant */ }
    }
    // 422 = wrong/missing ref → try the next variant. Any other status is
    // terminal (404 path gone, 401/403 auth), so stop early.
    if (res.status !== 422) break;
  }
  log.info('getProjectFiles: no variant returned a listing', { projectId, lastStatus });
  return null;
}

export async function getFileContent(projectId, filePath) {
  // filePath may already be ref-qualified; try the plain path first, then a
  // ref-qualified form if the path-only request 404s (path/encoding drift).
  const enc = encodeURIComponent(filePath);
  for (const suffix of ['', '?ref=main', '?ref=master']) {
    let res;
    try { res = await apiRequest(`/projects/${projectId}/git/files/${enc}${suffix}`); }
    catch { return null; }
    if (res.ok) return await res.text();
    if (res.status !== 404) return null; // auth/again-deterministic → stop
  }
  return null;
}

export async function getProjectMessages(projectId) {
  const res = await apiRequest(`/projects/${projectId}/messages`);
  if (!res.ok) return null;
  return await res.json();
}

export const PROBE_ENDPOINTS = [
  { label: 'GetProject',                   path: (id) => `/projects/${id}` },
  { label: 'GetProjectMessagesOutputBody', path: (id) => `/projects/${id}/messages` },
  { label: 'GitFilesResponse',             path: (id) => `/projects/${id}/git/files` },
  { label: 'GetProjectFile',               path: (id) => `/projects/${id}/git/files/src%2Fmain.ts` },
];

export function computeResponseSignature(ownerStatus, auditStatus) {
  const is2xx = (s) => s >= 200 && s < 300;
  const isError = (s) => s === null || s >= 500;
  const isAuth = (s) => s === 401 || s === 403 || s === 404;
  if (isError(ownerStatus) || isError(auditStatus)) return 'error';
  if (is2xx(auditStatus)) return 'vulnerable';
  if (is2xx(ownerStatus) && isAuth(auditStatus)) return 'patched';
  return 'unknown';
}

export async function probeEndpointPair(projectId, endpoint) {
  const [ownerRes, auditRes] = await Promise.all([
    apiRequest(endpoint.path(projectId)).catch(() => null),
    auditRequest(endpoint.path(projectId)).catch(() => null),
  ]);
  return {
    label: endpoint.label,
    ownerStatus: ownerRes?.status ?? null,
    auditStatus: auditToken ? (auditRes?.status ?? null) : null,
    signature: computeResponseSignature(ownerRes?.status ?? null, auditToken ? (auditRes?.status ?? null) : null),
  };
}

export function mutateProjectId(projectId) {
  const parts = projectId.split('-');
  if (parts.length !== 5) return null;
  const last = parts[4];
  const flipped = last.split('').reverse().join('');
  parts[4] = flipped;
  return parts.join('-');
}

export async function bolaProofProbe(projectId, pathFn) {
  const proofId = mutateProjectId(projectId);
  if (!proofId) return { proofId: null, status: null, signature: 'error' };

  try {
    const res = await apiRequest(pathFn(proofId));
    const status = res.status;
    const signature = (status >= 200 && status < 300)
      ? 'bola_confirmed'
      : (status === 404 || status === 403) ? 'ownership_enforced'
      : 'inconclusive';
    return { proofId, status, signature };
  } catch (e) {
    return { proofId, status: null, signature: 'error' };
  }
}

export async function getPreviewUrl(projectId) {
  return `https://${projectId}.lovableproject.com`;
}

export async function fetchBundleContent(projectId) {
  try {
    const previewUrl = await getPreviewUrl(projectId);
    const htmlRes = await fetch(previewUrl);
    if (!htmlRes.ok) return null;
    const html = await htmlRes.text();
    
    // Find the main JS bundle: <script type="module" crossorigin src="/assets/index-xxxx.js"></script>
    const scriptMatch = html.match(/src="(\/assets\/index-[^"]+\.js)"/);
    if (!scriptMatch) return null;
    
    const bundleUrl = new URL(scriptMatch[1], previewUrl).href;
    const bundleRes = await fetch(bundleUrl);
    if (!bundleRes.ok) return null;
    return await bundleRes.text();
  } catch (e) {
    return null;
  }
}
