// ============================================================
// Lovable Portfolio Audit — API Client (Chrome Extension)
// Uses chrome.cookies for automatic auth, bypasses CORS
// ============================================================

import { log } from './logger.js';

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
  const res = await fetch(`${API_BASE}${path}`, { headers, credentials: 'include' });
  return res;
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

export async function listProjects() {
  const res = await apiRequest('/user/projects');
  if (!res.ok) throw new Error(`listProjects failed: ${res.status}`);
  return await res.json();
}

export async function probeEndpoint(path) {
  try {
    const res = await apiRequest(path);
    return { status: res.status, ok: res.ok, contentLength: parseInt(res.headers.get('content-length') || '0') };
  } catch { return { status: 0, ok: false, contentLength: 0 }; }
}

export async function getProjectFiles(projectId) {
  const res = await apiRequest(`/projects/${projectId}/git/files`);
  if (!res.ok) return null;
  return await res.json();
}

export async function getFileContent(projectId, filePath) {
  const res = await apiRequest(`/projects/${projectId}/git/files/${encodeURIComponent(filePath)}`);
  if (!res.ok) return null;
  return await res.text();
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
