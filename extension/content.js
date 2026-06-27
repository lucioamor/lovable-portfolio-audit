// ============================================================
// NXLV Shield — Content Script (passive sensor bridge + collectors)
// ============================================================
// Runs in the isolated content-script world. Responsibilities:
//   • inject the page-context interceptor (C1)
//   • relay masked passive findings + observed endpoints to the SW (gated)
//   • browser-state scan: localStorage / sessionStorage / non-HttpOnly cookies (C2)
//   • route discovery + light DOM-sink (XSS) scan (C3)
//
// The sensor is OFF by default (safe mode). When disabled, nothing is relayed
// or scanned here — and the interceptor never sends a raw body regardless.
// ============================================================

let bridgeActive = true;
let passiveEnabled = false;

function disableBridge() {
  if (!bridgeActive) return;
  bridgeActive = false;
  window.removeEventListener('message', onMessage);
}

function isContextInvalidatedError(err) {
  const msg = String(err?.message || err || '');
  return msg.includes('Extension context invalidated');
}

// ---- Inject the page-context interceptor (CSP-safe external file) ----
try {
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('interceptor.js');
  script.onload = () => script.remove();
  script.onerror = () => script.remove();
  document.documentElement.appendChild(script);
} catch (err) {
  if (isContextInvalidatedError(err)) disableBridge();
  else console.warn('[NXLV] interceptor injection failed:', String(err?.message || err));
}

console.log('[NXLV] content script loaded on', location.href);

// ---- Safe SW messaging (handles extension reload / context invalidation) ----
function safeSendMessage(payload) {
  try {
    if (!chrome.runtime?.id) return;
    chrome.runtime.sendMessage(payload, () => {
      try { void chrome.runtime?.lastError; }
      catch (err) { if (isContextInvalidatedError(err)) disableBridge(); }
    });
  } catch (err) {
    if (String(err?.message || err).includes('Extension context invalidated')) disableBridge();
    else console.warn('[NXLV] sendMessage failed:', String(err?.message || err));
  }
}

// ---- Passive-enable flag (safe mode default OFF) ----
function readPassiveFlag() {
  try {
    chrome.storage?.local.get('lpa_passive_enabled', (d) => {
      passiveEnabled = !!d?.lpa_passive_enabled;
      if (passiveEnabled) scheduleStateScan();
    });
  } catch (_) {}
}
try {
  chrome.storage?.onChanged.addListener((changes, area) => {
    if (area === 'local' && 'lpa_passive_enabled' in changes) {
      passiveEnabled = !!changes.lpa_passive_enabled.newValue;
      if (passiveEnabled) scheduleStateScan();
    }
  });
} catch (_) {}
readPassiveFlag();

// ---- Relay page → background ----
function onMessage(event) {
  if (!bridgeActive) return;
  if (event.source !== window) return;
  const data = event.data;
  if (!data || typeof data !== 'object') return;

  // Auth token capture is always allowed (needed for auto-auth).
  if (data.type === 'LOVABLE_CT_AUTH_TOKEN') {
    safeSendMessage({ type: 'LOVABLE_AUTH_TOKEN', token: data.token, url: data.url || null });
    return;
  }

  if (!passiveEnabled) return; // sensor off → relay nothing else

  if (data.type === 'NXLV_OBSERVED_ENDPOINT') {
    safeSendMessage({ type: 'OBSERVED_ENDPOINT', path: data.path, method: data.method, status: data.status, host: location.host });
    return;
  }
  if (data.type === 'NXLV_PASSIVE_FINDINGS') {
    safeSendMessage({ type: 'PASSIVE_FINDINGS', source: data.source, path: data.path, findings: data.findings, host: location.host });
    return;
  }
}
window.addEventListener('message', onMessage);

// ============================================================
// C2/C3 collectors (content-script context)
// ============================================================

const C_PATTERNS = [
  { id: 'secret_jwt', kind: 'secret', severity: 'critical', re: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g, label: 'JWT / session token' },
  { id: 'secret_bearer', kind: 'secret', severity: 'high', re: /Bearer\s+[A-Za-z0-9._-]{20,}/gi, label: 'Bearer token' },
  { id: 'secret_sb_access', kind: 'secret', severity: 'high', re: /sb-[a-z0-9-]+-auth-token/gi, label: 'Supabase auth token key' },
  { id: 'pii_email', kind: 'pii', severity: 'medium', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, label: 'Email address' },
];

function maskValue(v) {
  if (typeof v !== 'string' || v.length === 0) return '•••';
  if (v.length <= 12) return v.slice(0, 3) + '•'.repeat(Math.max(3, v.length - 3));
  return v.slice(0, 4) + '•'.repeat(v.length - 8) + v.slice(-4);
}
async function sha256_16(v) {
  try {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v));
    return [...new Uint8Array(buf)].slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
  } catch { return null; }
}
async function scanString(text, source) {
  if (typeof text !== 'string' || !text) return [];
  const out = [];
  for (const p of C_PATTERNS) {
    const re = new RegExp(p.re.source, p.re.flags);
    let m, hits = 0;
    while ((m = re.exec(text)) !== null && hits < 5) {
      const raw = m[0];
      if (!raw || raw.length < 8) continue;
      hits++;
      out.push({ patternId: p.id, kind: p.kind, severity: p.severity, label: p.label, masked: maskValue(raw), hash: await sha256_16(raw), source });
      re.lastIndex = m.index + 1;
    }
  }
  return out;
}

let stateScanned = false;
function scheduleStateScan() {
  if (stateScanned || !passiveEnabled) return;
  stateScanned = true;
  const run = () => { runStateScan(); runRouteAndSinkScan(); };
  if (document.readyState === 'complete' || document.readyState === 'interactive') setTimeout(run, 800);
  else window.addEventListener('DOMContentLoaded', () => setTimeout(run, 800), { once: true });
}

// ---- C2: browser-state scan ----
async function runStateScan() {
  try {
    const findings = [];
    const scanStore = async (store, label) => {
      if (!store) return;
      for (let i = 0; i < store.length; i++) {
        const k = store.key(i);
        let val = '';
        try { val = store.getItem(k) || ''; } catch { continue; }
        // Flag the key name itself if it looks token-ish, plus scan the value.
        const hits = await scanString(`${k} ${val}`, `${label}:${k}`);
        findings.push(...hits);
      }
    };
    await scanStore(window.localStorage, 'localStorage');
    await scanStore(window.sessionStorage, 'sessionStorage');

    // Non-HttpOnly cookies are visible to document.cookie by definition.
    const cookieHits = await scanString(document.cookie || '', 'cookie');
    findings.push(...cookieHits);

    if (findings.length) {
      safeSendMessage({ type: 'PASSIVE_STATE', findings, host: location.host });
    }
  } catch (_) {}
}

// ---- C3: route discovery + light DOM-sink scan ----
function runRouteAndSinkScan() {
  try {
    // Routes: same-origin anchor paths + preloaded module chunks.
    const routes = new Set();
    document.querySelectorAll('a[href]').forEach(a => {
      try {
        const u = new URL(a.getAttribute('href'), location.href);
        if (u.origin === location.origin && u.pathname && u.pathname !== '/') routes.add(u.pathname);
      } catch (_) {}
    });
    const chunks = new Set();
    document.querySelectorAll('script[src], link[rel="modulepreload"][href]').forEach(el => {
      const ref = el.getAttribute('src') || el.getAttribute('href') || '';
      const m = ref.match(/([A-Za-z0-9_-]+)\.js$/);
      if (m) chunks.add(m[1]);
    });

    // DOM sinks: scan inline script text for risky sinks (light heuristic).
    const SINKS = [/\.innerHTML\s*=/, /dangerouslySetInnerHTML/, /document\.write\s*\(/, /\beval\s*\(/, /new\s+Function\s*\(/, /insertAdjacentHTML\s*\(/];
    const sinks = [];
    document.querySelectorAll('script:not([src])').forEach(s => {
      const code = s.textContent || '';
      if (code.length < 8 || code.length > 500000) return;
      for (const re of SINKS) {
        if (re.test(code)) sinks.push({ sink: re.source, sample: 'inline <script>' });
      }
    });

    if (routes.size || sinks.length || chunks.size) {
      safeSendMessage({
        type: 'PASSIVE_ROUTES',
        routes: [...routes].slice(0, 50),
        chunks: [...chunks].slice(0, 50),
        sinks: sinks.slice(0, 20),
        host: location.host,
      });
    }
  } catch (_) {}
}
