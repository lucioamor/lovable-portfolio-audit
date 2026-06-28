// ============================================================
// NXLV Lovable Portfolio Audit — DevTools panel (C4, Phase 2 bridge)
// ============================================================
// Live view over the passive sensor. Reads masked findings + observed
// endpoints + routes/sinks from the service worker, refreshes on
// PASSIVE_UPDATE, and exposes the safe-mode toggle + consent notice.
// ============================================================

const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function sevClass(s) {
  return ['catastrophic', 'critical', 'high', 'medium', 'low'].includes(s) ? s : 'medium';
}

function msg(type, payload = {}) {
  return new Promise((resolve) => {
    try { chrome.runtime.sendMessage({ type, ...payload }, resolve); }
    catch { resolve(undefined); }
  });
}

function renderFindings(findings) {
  $('findings-count').textContent = findings.length;
  if (!findings.length) { $('findings').innerHTML = '<div class="empty">No passive findings yet.</div>'; return; }
  const order = { catastrophic: 5, critical: 4, high: 3, medium: 2, low: 1 };
  const sorted = [...findings].sort((a, b) => (order[b.severity] || 0) - (order[a.severity] || 0));
  $('findings').innerHTML = sorted.slice(0, 100).map(f => `
    <div class="row">
      <span class="dot sev-${sevClass(f.severity)}"></span>
      <div>
        <div><strong>${esc(f.label || f.patternId)}</strong>
          <span class="tag">${esc(f.kind || 'secret')}</span></div>
        <div class="muted"><code>${esc(f.masked)}</code> · sha256:${esc(f.hash || '—')}</div>
        <div class="muted">${esc(f.source || '')}${f.host ? ' · ' + esc(f.host) : ''} · ${esc((f.observedAt || '').slice(11, 19))}</div>
      </div>
    </div>`).join('');
}

function renderEndpoints(endpoints) {
  const keys = Object.keys(endpoints);
  if (!keys.length) { $('endpoints').innerHTML = '<div class="empty">None observed.</div>'; return; }
  $('endpoints').innerHTML = keys
    .sort((a, b) => (endpoints[b].count || 0) - (endpoints[a].count || 0))
    .map(k => `<div class="row"><code>${esc(k)}</code><span class="spacer"></span>
      <span class="muted">×${endpoints[k].count} · ${endpoints[k].lastStatus ?? '—'}</span></div>`).join('');
}

function renderCandidates(candidates) {
  const keys = Object.keys(candidates);
  if (!keys.length) { $('candidates').innerHTML = '<div class="empty">None.</div>'; return; }
  $('candidates').innerHTML = keys.map(k => `
    <div class="row"><span class="tag new">NEW</span><code>${esc(k)}</code>
      <span class="muted">${esc(candidates[k].method)} · ${candidates[k].status ?? '—'}</span></div>`).join('');
}

function renderRoutes(routesByHost) {
  const hosts = Object.keys(routesByHost);
  if (!hosts.length) { $('routes').innerHTML = '<div class="empty">None discovered.</div>'; return; }
  $('routes').innerHTML = hosts.map(h => {
    const e = routesByHost[h];
    const routes = (e.routes || []).slice(0, 30).map(r => `<code>${esc(r)}</code>`).join(' ');
    const sinks = (e.sinks || []).map(s => `<span class="tag new">${esc(s.sink)}</span>`).join(' ');
    return `<div class="row"><div>
      <div><strong>${esc(h)}</strong> <span class="muted">${(e.routes || []).length} routes · ${(e.chunks || []).length} chunks</span></div>
      <div class="muted">${routes || '<span class="empty">no routes</span>'}</div>
      ${sinks ? `<div>DOM sinks: ${sinks}</div>` : ''}
    </div></div>`;
  }).join('');
}

async function refresh() {
  const data = await msg('PASSIVE_GET');
  if (!data) return;
  renderFindings(data.findings || []);
  renderEndpoints(data.endpoints || {});
  renderCandidates(data.candidates || {});
  renderRoutes(data.routes || {});
}

async function refreshConsentAndToggle() {
  const consent = await msg('CONSENT_STATUS');
  $('consent-notice').classList.toggle('hidden', !!(consent && consent.legal));
  try {
    chrome.storage.local.get('lpa_passive_enabled', (d) => {
      const on = !!(d && d.lpa_passive_enabled);
      $('enable').checked = on;
      $('off-notice').classList.toggle('hidden', on);
    });
  } catch (_) {}
}

// ---- Events ----
$('enable').addEventListener('change', (e) => {
  try {
    chrome.storage.local.set({ lpa_passive_enabled: e.target.checked });
    $('off-notice').classList.toggle('hidden', e.target.checked);
  } catch (_) {}
});
$('refresh').addEventListener('click', refresh);
$('clear').addEventListener('click', async () => { await msg('PASSIVE_CLEAR'); refresh(); });

try {
  chrome.runtime.onMessage.addListener((m) => { if (m && m.type === 'PASSIVE_UPDATE') refresh(); });
} catch (_) {}

// Initial + periodic fallback (devtools can miss live messages when backgrounded).
refresh();
refreshConsentAndToggle();
setInterval(refresh, 3000);
