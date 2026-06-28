(function () {
  'use strict';

  // ============================================================
  // NXLV Audit — Passive Sensor (page-context interceptor)
  // ============================================================
  // Wraps fetch/XHR. For Lovable API traffic the browser ALREADY received,
  // it extracts security signals IN THIS PAGE CONTEXT, masks + hashes them,
  // and posts ONLY metadata across the boundary.
  //
  // INVARIANT: a raw response body NEVER leaves this page context. We post
  // masked samples + sha256[:16] only — never the body, never a raw secret.
  // No extra network requests are made (we only observe existing ones).
  // ============================================================

  const LOVABLE_API = 'api.lovable.dev';

  // ---- Compact, dependency-free pattern set (page context, no imports) ----
  const PATTERNS = [
    { id: 'secret_supabase_service_role', kind: 'secret', severity: 'catastrophic', re: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g, label: 'JWT / Supabase key' },
    { id: 'secret_openai',    kind: 'secret', severity: 'critical', re: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g, label: 'OpenAI API Key' },
    { id: 'secret_anthropic', kind: 'secret', severity: 'critical', re: /sk-ant-(?:api03-)?[A-Za-z0-9_-]{20,}/g, label: 'Anthropic API Key' },
    { id: 'secret_stripe_live', kind: 'secret', severity: 'catastrophic', re: /sk_live_[A-Za-z0-9]{24,}/g, label: 'Stripe Live Key' },
    { id: 'secret_aws',       kind: 'secret', severity: 'critical', re: /AKIA[0-9A-Z]{16}/g, label: 'AWS Access Key ID' },
    { id: 'secret_github_pat', kind: 'secret', severity: 'critical', re: /ghp_[A-Za-z0-9]{36,}/g, label: 'GitHub PAT' },
    { id: 'secret_db_url',    kind: 'secret', severity: 'catastrophic', re: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^/\s]+\/\S+/g, label: 'PostgreSQL Connection String' },
    { id: 'pii_email',        kind: 'pii', severity: 'medium', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, label: 'Email address' },
    { id: 'pii_cpf',          kind: 'pii', severity: 'high', re: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g, label: 'Brazilian CPF' },
  ];
  const FP_HINTS = ['example.com', 'user@domain', 'test@test', 'noreply@', 'placeholder', 'your-api-key', 'xxxx'];

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

  // Scan a body (string) → masked findings. Bounded to keep it cheap.
  async function scanBody(text, source) {
    if (typeof text !== 'string' || text.length === 0) return [];
    const sample = text.length > 200000 ? text.slice(0, 200000) : text; // cap work
    const found = [];
    const seen = new Set();
    for (const p of PATTERNS) {
      const re = new RegExp(p.re.source, p.re.flags);
      let m;
      let hits = 0;
      while ((m = re.exec(sample)) !== null && hits < 20) {
        const raw = m[0];
        if (!raw || raw.length < 6) continue;
        const low = raw.toLowerCase();
        if (FP_HINTS.some(h => low.includes(h))) continue;
        const key = p.id + ':' + raw;
        if (seen.has(key)) continue;
        seen.add(key);
        hits++;
        found.push({
          patternId: p.id, kind: p.kind, severity: p.severity, label: p.label,
          // Hash the lowercased value for emails so an ignore-list match is case-insensitive.
          masked: maskValue(raw), hash: await sha256_16(p.id === 'pii_email' ? low : raw), source,
        });
        // Advance past the WHOLE match. match.index+1 re-matches the same value
        // shifted by one char, flooding a single email into ~20 fragment findings.
        re.lastIndex = m.index + (raw.length || 1);
      }
    }
    return found;
  }

  // Normalize a Lovable API path so ids collapse → enables 5th-endpoint detection.
  function normalizePath(urlStr) {
    try {
      const u = new URL(urlStr, location.href);
      let p = u.pathname;
      p = p.replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/:id'); // uuid
      p = p.replace(/\/workspaces\/[A-Za-z0-9_-]+/g, '/workspaces/:id'); // any workspace ID (base62 or workspace_xxx)
      // Keep in sync with lib/passive-endpoints.js normalizeLovablePath():
      p = p.replace(/(\/cloud\/db-proxy\/v\d+\/projects\/)[a-z0-9]{16,}/gi, '$1:ref'); // supabase ref
      p = p.replace(/\/git\/files\/.+$/i, '/git/files/:file');
      p = p.replace(/\/profile\/[^/]+/i, '/profile/:username');
      p = p.replace(/\/\d+(?=\/|$)/g, '/:n');
      return p;
    } catch { return urlStr; }
  }

  async function handleLovableResponse(urlStr, method, status, bodyText) {
    try {
      const path = normalizePath(urlStr);
      // Always post the observed endpoint (metadata only — no body).
      window.postMessage({ type: 'NXLV_OBSERVED_ENDPOINT', path, method: method || 'GET', status: status ?? null }, '*');

      const findings = await scanBody(bodyText, path);
      if (findings.length) {
        window.postMessage({ type: 'NXLV_PASSIVE_FINDINGS', source: 'response', path, findings }, '*');
      }
    } catch (_) { /* never throw into app code */ }
  }

  // ---- fetch wrapper ----
  const originalFetch = window.fetch;
  window.fetch = async function (...args) {
    const response = await originalFetch.apply(this, args);
    try {
      const url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
      if (url.includes(LOVABLE_API)) {
        // Capture Authorization header for auto-auth (unchanged behavior).
        const headers = args[1] && args[1].headers;
        let authHeader = null;
        if (headers) {
          if (headers instanceof Headers) authHeader = headers.get('Authorization') || headers.get('authorization');
          else if (typeof headers === 'object') authHeader = headers['Authorization'] || headers['authorization'];
        }
        if (authHeader) window.postMessage({ type: 'LOVABLE_CT_AUTH_TOKEN', token: authHeader, url }, '*');

        // Passive extraction — clone so the app still consumes the body.
        const clone = response.clone();
        clone.text().then(text => handleLovableResponse(url, (args[1] && args[1].method) || 'GET', response.status, text)).catch(() => {});
      }
    } catch (_) {}
    return response;
  };

  // ---- XHR wrapper ----
  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  const origSetHeader = XMLHttpRequest.prototype.setRequestHeader;

  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this._lctUrl = url; this._lctMethod = method; this._lctHeaders = {};
    return origOpen.call(this, method, url, ...rest);
  };
  XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
    if (this._lctHeaders) this._lctHeaders[name] = value;
    return origSetHeader.call(this, name, value);
  };
  XMLHttpRequest.prototype.send = function (...args) {
    this.addEventListener('load', function () {
      try {
        const url = this._lctUrl || '';
        if (!String(url).includes(LOVABLE_API)) return;
        const authHeader = this._lctHeaders && (this._lctHeaders['Authorization'] || this._lctHeaders['authorization']);
        if (authHeader) window.postMessage({ type: 'LOVABLE_CT_AUTH_TOKEN', token: authHeader, url }, '*');
        // responseText stays in page context; only masked findings are posted.
        handleLovableResponse(url, this._lctMethod || 'GET', this.status, this.responseText);
      } catch (_) {}
    });
    return origSend.apply(this, args);
  };

  console.log('[NXLV] Passive sensor interceptor loaded');
})();
