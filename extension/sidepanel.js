// ============================================================
// Sidepanel v2 — NXLV Audit (Chrome Extension)
// ============================================================

import { isInitialized, initVault, isUnlocked, lock, putToken, getToken } from './lib/skills/token-vault.js';
import { hasConsent, grantConsent } from './lib/skills/consent-gate.js';
import { listPatterns, togglePattern, resetToggles, loadCatalog } from './lib/skills/pattern-catalog.js';
import { buildEvidencePack, deriveSigningKey } from './lib/evidence-pack.js';
import { RLS_AUDIT_SQL, parseRlsResult, classifyRlsAudit, summarizeRlsAudit, buildRemediationPlan, renderRlsReportMarkdown } from './lib/skills/rls-checklist.js';
import { recordLog, installPersistentSink } from './lib/skills/diagnostics.js';

// Capture UI-side errors into the shared diagnostics log so the report includes
// failures that happen in the sidepanel realm (not just the service worker).
installPersistentSink('sidepanel');
window.addEventListener('error', (e) => {
  recordLog({ timestamp: new Date().toISOString(), level: 'error', message: `uncaught: ${e.message}`, context: { _src: 'sidepanel', file: e.filename, line: e.lineno } });
});
window.addEventListener('unhandledrejection', (e) => {
  recordLog({ timestamp: new Date().toISOString(), level: 'error', message: `unhandled rejection: ${e.reason?.message || e.reason}`, context: { _src: 'sidepanel' } });
});

// ============================================================
// State
// ============================================================

const state = {
  hasSession: false,
  vaultInitialized: false,
  vaultUnlocked: false,
  legalAccepted: false,
  results: [],
  summary: null,
  isDemoMode: false,
  scanning: false,
  history: [],
  activeTab: 'scan',
  filterText: '',
  filterSeverity: '',
  onboarded: false,
};

// ============================================================
// DOM shortcuts
// ============================================================

const $ = (id) => document.getElementById(id);

// ============================================================
// Init
// ============================================================

(async () => {
  await initState();
  attachListeners();
  renderAll();
  listenForScanMessages();
})();

async function initState() {
  // Legal consent
  state.legalAccepted = await hasConsent('L0_legal');

  // Vault status
  state.vaultInitialized = await isInitialized();
  state.vaultUnlocked = await isUnlocked();

  // Session
  const sessionRes = await msg('CHECK_SESSION');
  state.hasSession = sessionRes?.hasSession || false;

  // Existing results
  const resultData = await msg('GET_RESULTS');
  state.results = resultData?.results || [];
  state.summary = resultData?.summary || null;
  state.isDemoMode = resultData?.isDemoMode || false;

  // History
  const histData = await msg('GET_HISTORY');
  state.history = histData?.runs || [];

  // Load scan delay setting
  const { lpa_delay } = await storageGet('lpa_delay');
  if (lpa_delay) $('setting-delay').value = lpa_delay;

  // Onboarding flag
  const { lpa_onboarded } = await storageGet('lpa_onboarded');
  state.onboarded = !!lpa_onboarded;
}

function listenForScanMessages() {
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'SCAN_PROGRESS') onScanProgress(message.progress);
    if (message.type === 'SCAN_RESULT')   onScanResult(message.result);
    if (message.type === 'SCAN_COMPLETE') onScanComplete(message.summary);
    if (message.type === 'SCAN_ERROR')    onScanError(message.error);
  });
}

// ============================================================
// Messaging helpers
// ============================================================

function msg(type, payload = {}) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type, ...payload }, resolve);
  });
}

function storageGet(key) {
  return new Promise((resolve) => chrome.storage.local.get(key, resolve));
}

function storageSet(obj) {
  return new Promise((resolve) => chrome.storage.local.set(obj, resolve));
}

// ============================================================
// Render orchestrator
// ============================================================

function renderAll() {
  renderModals();
  renderBadges();
  renderOnboarding();
  renderNextStep();
  renderTab(state.activeTab);
}

// ============================================================
// Onboarding coach + "what to do now" banner
// ============================================================

function renderOnboarding() {
  // Only after the legal gate is cleared, and only until dismissed once.
  setVisible('onboard-card', state.legalAccepted && !state.onboarded);
}

function computeNextStep() {
  if (!state.legalAccepted) return null; // legal modal handles this
  if (!state.hasSession && !state.vaultUnlocked)
    return { text: '① Log in to lovable.dev (or unlock your vault in Settings) so the scanner can list your projects.', tone: 'warn' };
  if (state.scanning)
    return { text: 'Scanning… results stream in as each project finishes.', tone: 'info' };
  if (!state.results.length)
    return { text: '② Ready — press ▶ Start Scan to audit your projects.', tone: 'info' };
  const s = state.summary || {};
  const crit = (s.catastrophicCount || 0) + (s.criticalCount || 0);
  const high = s.highCount || 0;
  if (crit > 0)
    return { text: `③ ${crit} critical issue(s) found — open Results to review evidence and fixes.`, tone: 'bad', goto: 'results' };
  if (high > 0)
    return { text: `③ ${high} high-severity issue(s) found — open Results for details.`, tone: 'bad', goto: 'results' };
  return { text: '③ Scan complete — no critical issues. Open Results for the full breakdown.', tone: 'good', goto: 'results' };
}

function renderNextStep() {
  const el = $('next-step');
  if (!el) return;
  const step = computeNextStep();
  if (!step) { setVisible('next-step', false); return; }
  el.className = `next-step tone-${step.tone}${step.goto ? ' clickable' : ''}`;
  el.textContent = step.text;
  el.onclick = step.goto ? () => { state.activeTab = step.goto; renderTab(step.goto); } : null;
  setVisible('next-step', true);
}

function renderModals() {
  const showLegal  = !state.legalAccepted;
  const showSetup  = state.legalAccepted && !state.vaultInitialized;
  const showUnlock = state.legalAccepted && state.vaultInitialized && !state.vaultUnlocked && !showSetup;

  setVisible('legal-gate',        showLegal);
  setVisible('vault-setup-modal', showSetup);
  setVisible('vault-unlock-modal', showUnlock);
  setVisible('app', state.legalAccepted && (state.vaultInitialized ? state.vaultUnlocked : true));

  // If vault not initialized yet but legal accepted → prompt setup
  if (state.legalAccepted && !state.vaultInitialized) setVisible('vault-setup-modal', true);
}

function renderBadges() {
  // Session badge
  const sessionBadge = $('session-badge');
  if (sessionBadge) {
    sessionBadge.textContent = state.hasSession ? '✓ Logged in' : '✗ No session';
    sessionBadge.className = `badge ${state.hasSession ? 'badge-success' : 'badge-error'}`;
  }

  // Vault badge
  const vaultBadge = $('vault-badge');
  if (vaultBadge) {
    if (!state.vaultInitialized) {
      vaultBadge.textContent = 'Vault —';
      vaultBadge.className = 'badge badge-neutral';
    } else if (state.vaultUnlocked) {
      vaultBadge.textContent = '🔓 Vault open';
      vaultBadge.className = 'badge badge-success';
    } else {
      vaultBadge.textContent = '🔒 Vault locked';
      vaultBadge.className = 'badge badge-warn';
    }
  }

  // Vault status button tooltip
  const vaultBtn = $('vault-status-btn');
  if (vaultBtn) {
    vaultBtn.textContent = state.vaultUnlocked ? '🔓' : state.vaultInitialized ? '🔒' : '🔐';
  }
}

function renderTab(tab) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));

  const tabEl = $(`tab-${tab}`);
  if (tabEl) tabEl.classList.remove('hidden');
  const tabBtn = document.querySelector(`.tab-btn[data-tab="${tab}"]`);
  if (tabBtn) tabBtn.classList.add('active');

  if (tab === 'scan') renderNextStep();
  if (tab === 'results') renderResults();
  if (tab === 'history') renderHistory();
  if (tab === 'settings') renderSettings();
}

// ============================================================
// Tab: Scan
// ============================================================

function renderSummaryGrid(summary) {
  if (!summary) { setVisible('summary-grid', false); return; }
  setVisible('summary-grid', true);
  $('count-catastrophic').textContent = summary.catastrophicCount || 0;
  $('count-critical').textContent     = summary.criticalCount || 0;
  $('count-high').textContent         = summary.highCount || 0;
  $('count-medium').textContent       = summary.mediumCount || 0;
  $('count-clean').textContent        = summary.cleanCount || 0;
}

function onScanProgress(progress) {
  setVisible('scan-progress', true);
  $('progress-bar').style.width = `${progress.percentage || 0}%`;
  $('progress-label').textContent =
    `[${progress.currentProjectIndex}/${progress.totalProjects}] ${progress.currentProject || ''}`;
}

function onScanResult(result) {
  state.results.push(result);
}

function onScanComplete(summary) {
  state.scanning = false;
  state.summary = summary;
  setVisible('scan-progress', false);
  $('scan-btn').disabled = false;
  $('scan-btn').textContent = '▶ Start Scan';
  renderSummaryGrid(summary);

  // Delta banner
  if (summary.delta?.length > 0) {
    const newCount = summary.delta.reduce((a, d) => a + (d.newFindings?.length || 0), 0);
    const fixedCount = summary.delta.reduce((a, d) => a + (d.resolvedFindings?.length || 0), 0);
    const banner = $('delta-banner');
    banner.innerHTML = `↕ vs last run: <strong>+${newCount} new</strong> · <strong>${fixedCount} resolved</strong>`;
    banner.className = `delta-banner ${newCount > 0 ? 'delta-worse' : 'delta-better'}`;
    setVisible('delta-banner', true);
  }

  // Reload history
  msg('GET_HISTORY').then(d => { state.history = d?.runs || []; });
  renderNextStep();
}

function onScanError(error) {
  state.scanning = false;
  setVisible('scan-progress', false);
  $('scan-btn').disabled = false;
  $('scan-btn').textContent = '▶ Start Scan';
  $('progress-label').textContent = `Error: ${error}`;
  setVisible('scan-progress', true);
  renderNextStep();
}

// ============================================================
// Tab: Results
// ============================================================

function renderResults() {
  const list = $('results-list');
  let items = state.results;

  if (state.filterText) {
    const q = state.filterText.toLowerCase();
    items = items.filter(r => (r.projectName || '').toLowerCase().includes(q));
  }
  if (state.filterSeverity) {
    items = items.filter(r => r.severity === state.filterSeverity);
  }

  if (!items.length) {
    list.innerHTML = '<div class="empty-state">No results match current filters</div>';
    return;
  }

  list.innerHTML = items.map(r => renderProjectCard(r)).join('');
  list.querySelectorAll('.project-card').forEach(card => {
    card.addEventListener('click', () => {
      card.querySelector('.project-detail')?.classList.toggle('hidden');
    });
  });
}

function renderProjectCard(r) {
  const sevClass = `sev-${r.severity}`;
  const findings = r.findings || [];
  const hasFindings = findings.length > 0;

  const findingHtml = hasFindings
    ? findings.slice(0, 5).map(f => `
        <div class="finding-row">
          <span class="finding-sev sev-dot sev-${f.severity || 'medium'}"></span>
          <span class="finding-title">${esc(f.title || f.label || f.ruleId)}</span>
          ${f.masked ? `<code class="finding-masked">${esc(f.masked)}</code>` : ''}
        </div>`).join('')
    : '<div class="finding-row muted">No findings</div>';

  const extraCount = findings.length > 5 ? `<div class="finding-more">+${findings.length - 5} more findings</div>` : '';

  const files = probeSummary(r.bolaFilesSignature, r.bolaFilesStatus);
  const chat  = probeSummary(r.bolaChatSignature, r.bolaChatStatus);
  const findingsLabel = hasFindings
    ? `${findings.length} finding${findings.length === 1 ? '' : 's'}`
    : 'no findings';

  return `
    <div class="project-card ${sevClass}">
      <div class="project-card-header">
        <div>
          <span class="severity-badge ${sevClass}">${r.severity?.toUpperCase()}</span>
          <strong>${esc(r.projectName)}</strong>
        </div>
        <div class="project-meta">
          <span>${r.riskScore ?? '—'} pts</span>
          <span class="muted">${fmtDate(r.scanTimestamp)}</span>
        </div>
      </div>
      <div class="probe-row probe-row-visible">
        <span class="probe-pill probe-${files.cls}" title="Files probe: ${esc(files.title)}">Files: ${esc(files.text)}</span>
        <span class="probe-pill probe-${chat.cls}" title="Chat probe: ${esc(chat.title)}">Chat: ${esc(chat.text)}</span>
        ${r.supabaseDetected ? `<span class="badge-warn">Supabase</span>` : ''}
        <span class="probe-findings muted">${findingsLabel}${hasFindings ? ' ▾' : ''}</span>
      </div>
      <div class="project-detail hidden">
        ${findingHtml}
        ${extraCount}
      </div>
    </div>`;
}

// Human-readable summary of a BOLA probe signature, including the raw HTTP
// status so "error" tells you *why* (e.g. endpoint drift → 404/405).
function probeSummary(sig, status) {
  const code = (status && status !== 200) ? ` (${status})` : '';
  switch (sig) {
    case 'vulnerable':   return { text: 'BOLA ⚠', cls: 'bad',     title: 'Cross-account access confirmed (vulnerable)' };
    case 'owner_only':   return { text: 'owner ✓', cls: 'warn',    title: 'Owner can access; no second token, so BOLA not proven' };
    case 'patched':      return { text: 'patched', cls: 'ok',      title: 'Owner 200 / audit account denied' };
    case 'inaccessible': return { text: 'no access', cls: 'neutral', title: 'Owner request denied (401/403)' };
    case 'auth_required':return { text: 'auth req', cls: 'neutral', title: 'Endpoint requires auth' };
    case 'rate_limited': return { text: 'throttled', cls: 'neutral', title: 'Rate limited (429)' };
    case 'error':        return { text: `error${code || (status === 0 ? ' (network)' : '')}`, cls: 'err', title: `Probe failed — HTTP ${status ?? '?'}. Non-200/401/403 (e.g. endpoint drift)` };
    default:             return { text: '—', cls: 'neutral', title: 'Not probed' };
  }
}

// ============================================================
// Tab: History
// ============================================================

function renderHistory() {
  const list = $('history-list');

  if (!state.history.length) {
    list.innerHTML = '<div class="empty-state">No scan history yet</div>';
    setVisible('compare-runs-btn', false);
    return;
  }

  setVisible('compare-runs-btn', state.history.length >= 2);

  list.innerHTML = state.history.map((run, idx) => renderHistoryRow(run, idx)).join('');

  // Expand/collapse per-run detail on click
  list.querySelectorAll('.history-row').forEach(row => {
    row.addEventListener('click', () => {
      row.querySelector('.history-detail')?.classList.toggle('hidden');
    });
  });
}

function renderHistoryRow(run, idx) {
  const sc = run.severityCounts || {};
  const sevOrder = ['catastrophic', 'critical', 'high', 'medium', 'low', 'clean'];
  const sevChips = sevOrder
    .filter(s => sc[s])
    .map(s => `<span class="sev-chip"><span class="sev-dot sev-${s}"></span>${sc[s]}</span>`)
    .join('');

  // Worst projects by score (byProject map persisted in the run summary)
  const byProject = run.byProject || {};
  const worst = Object.entries(byProject)
    .map(([id, p]) => ({ id, ...p }))
    .sort((a, b) => (b.score || 0) - (a.score || 0))
    .slice(0, 5);

  const worstHtml = worst.length
    ? worst.map(p => `
        <div class="history-proj-row">
          <span class="sev-dot sev-${p.severity || 'medium'}"></span>
          <span class="history-proj-id">${esc(p.id.slice(0, 8))}</span>
          <span class="muted">${p.score ?? '—'} pts · ${esc(p.severity || '—')}</span>
        </div>`).join('')
    : '<div class="muted">No per-project detail stored for this run.</div>';

  return `
    <div class="history-row">
      <div class="history-row-head">
        <div class="history-run-info">
          <span class="history-idx">#${idx + 1}</span>
          <span class="history-date">${fmtDate(run.startedAt)}</span>
          <span class="history-projects">${run.projectCount} projects · ${run.findingCount ?? 0} findings</span>
        </div>
        <div class="history-counts">
          ${sevChips || '<span class="muted">clean</span>'}
          <span class="muted">avg ${run.scoreAverage}pts ▾</span>
        </div>
      </div>
      <div class="history-detail hidden">
        <div class="history-detail-grid">
          <span>Projects: <strong>${run.projectCount}</strong></span>
          <span>Findings: <strong>${run.findingCount ?? 0}</strong></span>
          <span>Avg score: <strong>${run.scoreAverage}</strong></span>
          <span>Catastrophic: <strong>${sc.catastrophic || 0}</strong></span>
          <span>Critical: <strong>${sc.critical || 0}</strong></span>
          <span>High: <strong>${sc.high || 0}</strong></span>
          <span>Medium: <strong>${sc.medium || 0}</strong></span>
          <span>Low: <strong>${sc.low || 0}</strong></span>
          <span>Clean: <strong>${sc.clean || 0}</strong></span>
        </div>
        <div class="history-worst-label">Highest-risk projects</div>
        ${worstHtml}
      </div>
    </div>`;
}

async function renderDeltaView() {
  if (state.history.length < 2) return;
  const deltaView = $('delta-view');
  const delta = state.summary?.delta || [];

  if (!delta?.length) {
    deltaView.innerHTML = '<div class="muted">No changes between last 2 runs.</div>';
    setVisible('delta-view', true);
    return;
  }

  deltaView.innerHTML = `
    <h4>Changes: Run #2 → Run #1</h4>
    ${delta.map(d => `
      <div class="delta-row ${d.scoreDelta > 0 ? 'delta-worse' : d.scoreDelta < 0 ? 'delta-better' : ''}">
        <span class="delta-pid">${d.projectId.slice(0, 8)}</span>
        <span>${d.severityTransition}</span>
        <span>${d.scoreDelta > 0 ? '+' : ''}${d.scoreDelta} pts</span>
        ${d.newFindings?.length ? `<span class="badge-warn">+${d.newFindings.length} new</span>` : ''}
        ${d.resolvedFindings?.length ? `<span class="badge-ok">-${d.resolvedFindings.length} fixed</span>` : ''}
      </div>`).join('')}`;
  setVisible('delta-view', true);
}

// ============================================================
// Tab: Settings
// ============================================================

async function renderSettings() {
  // Vault section
  const notInit   = $('vault-not-init');
  const locked    = $('vault-locked');
  const unlocked  = $('vault-unlocked');

  state.vaultInitialized = await isInitialized();
  state.vaultUnlocked    = await isUnlocked();

  notInit?.classList.toggle('hidden', state.vaultInitialized);
  locked?.classList.toggle('hidden',  !state.vaultInitialized || state.vaultUnlocked);
  unlocked?.classList.toggle('hidden', !state.vaultInitialized || !state.vaultUnlocked);

  // Pre-fill tokens if vault open
  if (state.vaultUnlocked) {
    const ownerTok = await getToken('lovable:owner');
    const auditTok = await getToken('lovable:audit');
    if (ownerTok) $('vault-owner-input').value = ownerTok;
    if (auditTok) $('vault-audit-input').value  = auditTok;
  }

  // Passive sensor toggle + counts
  try {
    const { lpa_passive_enabled } = await storageGet('lpa_passive_enabled');
    if ($('setting-passive')) $('setting-passive').checked = !!lpa_passive_enabled;
    const data = await msg('PASSIVE_GET');
    const fc = data?.findings?.length || 0;
    const ec = Object.keys(data?.endpoints || {}).length;
    const cc = Object.keys(data?.candidates || {}).length;
    if ($('passive-count')) {
      $('passive-count').textContent = `${fc} findings · ${ec} endpoints${cc ? ` · ${cc} new-endpoint candidate(s)` : ''}`;
    }
    const { lpa_email_ignore = [] } = await storageGet('lpa_email_ignore');
    if ($('email-ignore-count')) $('email-ignore-count').textContent = `${lpa_email_ignore.length} email(s) ignored`;
  } catch (_) {}

  // Load pattern list
  await renderPatternList();
}

async function renderPatternList() {
  const container = $('pattern-list');
  container.innerHTML = 'Loading...';
  try {
    const patterns = await listPatterns();
    container.innerHTML = patterns.map(p => `
      <label class="pattern-row toggle-row">
        <input type="checkbox" class="pattern-toggle" data-id="${p.id}" ${p.enabled ? 'checked' : ''}>
        <span>
          <strong>${esc(p.label)}</strong>
          <span class="badge-${severityClass(p.severity)} badge-xs">${p.severity}</span>
          <span class="muted"> · ${p.kind}</span>
        </span>
      </label>`).join('');

    container.querySelectorAll('.pattern-toggle').forEach(cb => {
      cb.addEventListener('change', async () => {
        await togglePattern(cb.dataset.id, cb.checked);
      });
    });
  } catch (e) {
    container.innerHTML = `<span class="error-msg">Failed to load patterns: ${esc(e.message)}</span>`;
  }
}

// ============================================================
// Vault modals
// ============================================================

async function handleVaultSetup() {
  const pass    = $('vault-pass-input').value;
  const confirm = $('vault-pass-confirm').value;
  const errEl   = $('vault-setup-error');

  errEl.classList.add('hidden');
  if (pass.length < 12) return showErr(errEl, 'Passphrase must be at least 12 characters.');
  if (pass !== confirm) return showErr(errEl, 'Passphrases do not match.');

  try {
    $('vault-setup-submit').disabled = true;
    await initVault(pass);
    // Auto-unlock after setup
    const unlockRes = await msg('VAULT_UNLOCK', { passphrase: pass });
    state.vaultInitialized = true;
    state.vaultUnlocked = unlockRes?.success || false;
    renderModals();
    renderBadges();
    renderTab('settings');
  } catch (e) {
    showErr(errEl, `Failed: ${e.message}`);
  } finally {
    $('vault-setup-submit').disabled = false;
  }
}

async function handleVaultUnlock() {
  const pass  = $('vault-unlock-input').value;
  const errEl = $('vault-unlock-error');
  errEl.classList.add('hidden');

  $('vault-unlock-submit').disabled = true;
  try {
    const res = await msg('VAULT_UNLOCK', { passphrase: pass });
    if (res?.success) {
      state.vaultUnlocked = true;
      renderModals();
      renderBadges();
      renderTab('settings');
    } else {
      showErr(errEl, 'Wrong passphrase.');
    }
  } finally {
    $('vault-unlock-submit').disabled = false;
    $('vault-unlock-input').value = '';
  }
}

// ============================================================
// Legal gate
// ============================================================

function initLegalGate() {
  const scrollArea = $('legal-scroll-area');
  const acceptBtn  = $('legal-accept-btn');
  const hint       = $('legal-scroll-hint');

  scrollArea.addEventListener('scroll', () => {
    const atBottom = scrollArea.scrollHeight - scrollArea.scrollTop <= scrollArea.clientHeight + 20;
    if (atBottom) {
      acceptBtn.disabled = false;
      hint.textContent = '✓ You have read all terms';
    }
  });

  acceptBtn.addEventListener('click', async () => {
    await grantConsent('L0_legal');
    await grantConsent('L1_safe_mode');
    state.legalAccepted = true;
    setVisible('legal-gate', false);
    // Check vault after consent
    state.vaultInitialized = await isInitialized();
    state.vaultUnlocked    = await isUnlocked();
    renderModals();
    renderBadges();
    renderOnboarding();
    renderNextStep();
  });

  $('legal-reject-btn').addEventListener('click', () => {
    window.close();
  });
}

// ============================================================
// Event listeners
// ============================================================

function attachListeners() {
  // Legal gate
  initLegalGate();

  // Vault setup modal
  $('vault-setup-submit')?.addEventListener('click', handleVaultSetup);
  $('vault-setup-cancel')?.addEventListener('click', () => setVisible('vault-setup-modal', false));

  // Vault unlock modal
  $('vault-unlock-submit')?.addEventListener('click', handleVaultUnlock);
  $('vault-unlock-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') handleVaultUnlock();
  });

  // Tab nav
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      state.activeTab = btn.dataset.tab;
      renderTab(state.activeTab);
    });
  });

  // Vault header button
  $('vault-status-btn')?.addEventListener('click', () => {
    state.activeTab = 'settings';
    renderTab('settings');
  });

  // Scan tab
  $('opt-dual-probe')?.addEventListener('change', e => {
    setVisible('audit-token-row', e.target.checked);
  });

  $('scan-btn')?.addEventListener('click', startScan);
  $('demo-btn')?.addEventListener('click', loadDemo);
  $('stop-btn')?.addEventListener('click', stopScan);

  // Results tab
  $('results-filter')?.addEventListener('input', e => {
    state.filterText = e.target.value;
    renderResults();
  });
  $('severity-filter')?.addEventListener('change', e => {
    state.filterSeverity = e.target.value;
    renderResults();
  });

  // RLS Deep tab
  $('rls-show-sql')?.addEventListener('click', () => {
    const pre = $('rls-sql');
    if (!pre) return;
    pre.textContent = RLS_AUDIT_SQL;
    pre.classList.toggle('hidden');
  });
  $('rls-copy-sql')?.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(RLS_AUDIT_SQL); flash('rls-copy-sql', '✓ Copied'); }
    catch { /* clipboard blocked — show SQL so user can copy manually */ $('rls-sql').textContent = RLS_AUDIT_SQL; $('rls-sql').classList.remove('hidden'); }
  });
  $('rls-import-csv')?.addEventListener('click', () => $('rls-csv-file')?.click());
  $('rls-csv-file')?.addEventListener('change', e => {
    const file = e.target.files?.[0];
    handleRlsCsvImport(file);
    e.target.value = ''; // allow re-importing the same file
  });
  $('rls-classify')?.addEventListener('click', handleRlsClassify);
  $('export-btn')?.addEventListener('click', exportResults);
  $('clear-btn')?.addEventListener('click', clearResults);

  // History tab
  $('compare-runs-btn')?.addEventListener('click', renderDeltaView);

  // Settings tab — vault
  $('vault-init-btn')?.addEventListener('click', () => setVisible('vault-setup-modal', true));
  $('vault-unlock-btn')?.addEventListener('click', () => setVisible('vault-unlock-modal', true));
  $('vault-lock-btn')?.addEventListener('click', async () => {
    await lock();
    state.vaultUnlocked = false;
    renderBadges();
    renderSettings();
  });
  $('vault-reset-btn')?.addEventListener('click', async () => {
    if (!confirm('Reset vault? All stored tokens will be permanently deleted.')) return;
    await chrome.storage.local.remove('lpa:vault');
    state.vaultInitialized = false;
    state.vaultUnlocked    = false;
    renderBadges();
    setVisible('vault-setup-modal', true);
  });
  $('vault-save-owner')?.addEventListener('click', async () => {
    const tok = $('vault-owner-input').value.trim();
    if (!tok) return;
    await putToken('lovable:owner', tok);
    $('vault-owner-input').value = '';
    $('vault-owner-input').placeholder = '✓ Saved';
  });
  $('vault-save-audit')?.addEventListener('click', async () => {
    const tok = $('vault-audit-input').value.trim();
    if (!tok) return;
    await putToken('lovable:audit', tok);
    $('vault-audit-input').value = '';
    $('vault-audit-input').placeholder = '✓ Saved';
  });

  // Settings — patterns
  $('refresh-patterns-btn')?.addEventListener('click', async () => {
    $('refresh-patterns-btn').textContent = '↻ Refreshing...';
    await loadCatalog({ forceRefresh: true });
    await renderPatternList();
    $('refresh-patterns-btn').textContent = '↻ Refresh catalog';
  });
  $('reset-toggles-btn')?.addEventListener('click', async () => {
    await resetToggles();
    await renderPatternList();
  });

  // Settings — delay
  $('setting-delay')?.addEventListener('change', e => {
    storageSet({ lpa_delay: parseInt(e.target.value, 10) || 500 });
  });

  // Settings — passive sensor
  $('setting-passive')?.addEventListener('change', e => {
    storageSet({ lpa_passive_enabled: e.target.checked });
  });
  $('passive-clear-btn')?.addEventListener('click', async () => {
    await msg('PASSIVE_CLEAR');
    await renderSettings();
  });
  $('passive-details-btn')?.addEventListener('click', togglePassiveDetails);
  $('email-ignore-save')?.addEventListener('click', saveEmailIgnore);

  // Onboarding coach dismiss
  $('onboard-dismiss')?.addEventListener('click', async () => {
    state.onboarded = true;
    await storageSet({ lpa_onboarded: true });
    renderOnboarding();
  });

  // Settings — diagnostics
  $('diag-build-btn')?.addEventListener('click', generateDiagnostics);
  $('diag-clear-logs-btn')?.addEventListener('click', async () => {
    await msg('DIAGNOSTICS_CLEAR_LOGS');
    flash('diag-clear-logs-btn', '✓ Cleared');
  });
}

// ============================================================
// Diagnostics (repair-session export)
// ============================================================

async function generateDiagnostics() {
  const btn = $('diag-build-btn');
  const status = $('diag-status');
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = '⏳ Building report…';
  try {
    const res = await msg('DIAGNOSTICS_BUILD');
    if (!res?.ok) throw new Error(res?.error || 'build failed');
    const text = res.text;

    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: `nxlv-diagnostics-${stamp}.txt` });
    a.click();
    URL.revokeObjectURL(url);

    let note = '✓ Saved .txt';
    try { await navigator.clipboard.writeText(text); note += ' + copied to clipboard'; }
    catch { note += ' (clipboard blocked — use the file)'; }
    if (status) { status.textContent = note; status.classList.remove('hidden'); }
  } catch (e) {
    if (status) { status.textContent = `Failed: ${e.message}`; status.classList.remove('hidden'); }
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

async function sha256_16(v) {
  try {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v));
    return [...new Uint8Array(buf)].slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
  } catch { return null; }
}

// Add emails to the passive ignore-list. Only their hash is stored (the raw email
// never persists), matching how passive findings are hashed (lowercased).
async function saveEmailIgnore() {
  const ta = $('setting-email-ignore');
  if (!ta) return;
  const emails = ta.value.split(/[\n,;]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
  if (!emails.length) { flash('email-ignore-save', 'No emails'); return; }

  const { lpa_email_ignore = [] } = await storageGet('lpa_email_ignore');
  const hashes = new Set(lpa_email_ignore);
  for (const e of emails) { const h = await sha256_16(e); if (h) hashes.add(h); }
  const arr = [...hashes];
  await storageSet({ lpa_email_ignore: arr });

  // Purge already-stored passive findings that match the ignore-list.
  const { lpa_passive_findings = [] } = await storageGet('lpa_passive_findings');
  const set = new Set(arr);
  const filtered = lpa_passive_findings.filter(f => !(f.patternId === 'pii_email' && f.hash && set.has(f.hash)));
  if (filtered.length !== lpa_passive_findings.length) await storageSet({ lpa_passive_findings: filtered });

  ta.value = '';
  await renderSettings();
  flash('email-ignore-save', `✓ ${arr.length} ignored`);
}

async function togglePassiveDetails() {
  const pre = $('passive-details');
  if (!pre) return;
  if (!pre.classList.contains('hidden')) { pre.classList.add('hidden'); return; }
  const d = await msg('PASSIVE_GET');
  const obs = d?.endpoints || {};
  const cand = d?.candidates || {};
  const obsLines = Object.keys(obs)
    .sort((a, b) => (obs[b].count || 0) - (obs[a].count || 0))
    .map(k => `${obs[k].lastMethod || 'GET'} ${k}  ×${obs[k].count}  ${obs[k].lastStatus ?? '—'}`);
  const candLines = Object.keys(cand)
    .sort()
    .map(k => `${cand[k].method || 'GET'} ${k}  ${cand[k].status ?? '—'}`);
  pre.textContent =
    `OBSERVED ENDPOINTS (${obsLines.length}) — what lovable.dev actually called:\n` +
    (obsLines.join('\n') || '  none yet — browse lovable.dev with passive sensor ON') +
    `\n\nNEW-ENDPOINT CANDIDATES (${candLines.length}) — not in the extension's known list:\n` +
    (candLines.join('\n') || '  none');
  pre.classList.remove('hidden');
}

// ============================================================
// Scan flow
// ============================================================

async function startScan() {
  if (!state.hasSession && !state.vaultUnlocked) {
    alert('No session token found. Log in to Lovable or unlock your vault.');
    return;
  }
  if (!state.legalAccepted) {
    setVisible('legal-gate', true);
    return;
  }

  state.scanning = true;
  state.results  = [];
  setVisible('scan-progress', true);
  setVisible('summary-grid', false);
  setVisible('delta-banner', false);
  $('scan-btn').disabled = true;
  $('scan-btn').textContent = '⏳ Scanning...';
  $('progress-bar').style.width = '0%';
  $('progress-label').textContent = 'Initializing...';
  renderNextStep();

  const { lpa_delay } = await storageGet('lpa_delay');

  const config = {
    includeChat:  $('opt-chat')?.checked ?? true,
    includeFiles: $('opt-files')?.checked ?? false,
    deepInspect:  $('opt-files')?.checked ?? false,
    auditToken:   $('opt-dual-probe')?.checked
                    ? ($('audit-token-input')?.value?.trim() || null)
                    : null,
    scanDelay:    parseInt(lpa_delay, 10) || 500,
  };

  await msg('START_SCAN', { config });
}

async function stopScan() {
  await msg('STOP_SCAN');
  state.scanning = false;
  $('scan-btn').disabled = false;
  $('scan-btn').textContent = '▶ Start Scan';
  setVisible('scan-progress', false);
  renderNextStep();
}

async function loadDemo() {
  const res = await msg('LOAD_DEMO');
  state.results    = res?.results || [];
  state.summary    = res?.summary || null;
  state.isDemoMode = true;
  renderSummaryGrid(state.summary);
  renderNextStep();
}

// ============================================================
// Export / Clear
// ============================================================

async function exportResults() {
  // Derive a stable device signing key (device UUID as passphrase, never leaves browser)
  const { lpa_device_id: existingId } = await storageGet('lpa_device_id');
  const deviceId = existingId ?? crypto.randomUUID();
  if (!existingId) await storageSet({ lpa_device_id: deviceId });

  const signingKey = await deriveSigningKey(deviceId);
  const { payload, signature } = await buildEvidencePack(state.results, state.summary ?? {}, signingKey);

  const output = JSON.stringify({
    _format: 'nxlv-evidence-pack/v1',
    _signature: signature,
    _signing_key_id: deviceId.slice(0, 8),
    pack: JSON.parse(payload),
  }, null, 2);

  const blob = new Blob([output], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), {
    href: url,
    download: `nxlv-audit-${new Date().toISOString().slice(0, 10)}.json`,
  });
  a.click();
  URL.revokeObjectURL(url);
}

async function clearResults() {
  if (!confirm('Clear all results?')) return;
  await msg('CLEAR_RESULTS');
  state.results = [];
  state.summary = null;
  setVisible('summary-grid', false);
  setVisible('delta-banner', false);
  renderResults();
}

// ============================================================
// Utilities
// ============================================================

function setVisible(id, visible) {
  const el = $(id);
  if (!el) return;
  el.classList.toggle('hidden', !visible);
}

function showErr(el, msg) {
  el.textContent = msg;
  el.classList.remove('hidden');
}

// ============================================================
// Tab: RLS Deep (copy-paste classification)
// ============================================================

function handleRlsClassify() {
  const raw = $('rls-input')?.value || '';
  const container = $('rls-findings');
  if (!container) return;
  if (!raw.trim()) {
    container.innerHTML = `<div class="empty-state">Import the CSV or paste the audit cell value first.</div>`;
    return;
  }
  try {
    const { findings, policyChecks } = classifyRlsAudit(parseRlsResult(extractAuditCell(raw)));
    renderRlsFindings(findings, policyChecks);
  } catch (err) {
    container.innerHTML = `<div class="empty-state error">${esc(err.message)}</div>`;
  }
}

// Accepts: raw JSON, a CSV-escaped cell ("...""..."), or the whole exported
// CSV file (header "audit" + one quoted field). Returns clean JSON text.
function extractAuditCell(text) {
  let t = String(text).trim();
  if (t.startsWith('{') || t.startsWith('[')) return t;
  // Drop a leading "audit" header line (from the CSV export)
  const nl = t.indexOf('\n');
  if (nl !== -1) {
    const firstLine = t.slice(0, nl).trim().toLowerCase();
    if (firstLine === 'audit' || firstLine === '"audit"') t = t.slice(nl + 1).trim();
  }
  // Unwrap a CSV-quoted field and de-double its quotes
  if (t.startsWith('"') && t.endsWith('"')) {
    t = t.slice(1, -1).replace(/""/g, '"');
  }
  return t.trim();
}

function handleRlsCsvImport(file) {
  const status = $('rls-import-status');
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    const json = extractAuditCell(reader.result || '');
    const input = $('rls-input');
    if (input) input.value = json;
    if (status) status.textContent = `✓ ${file.name}`;
    handleRlsClassify();
  };
  reader.onerror = () => { if (status) status.textContent = '✗ could not read file'; };
  reader.readAsText(file);
}

// Cache of the last classification so copy buttons can pull text by reference
// (inline onclick is blocked by the extension CSP).
let _rlsPlan = [];
let _rlsReportMd = '';

function renderRlsFindings(findings, policyChecks) {
  const container = $('rls-findings');
  if (!container) return;
  if (!findings.length) {
    container.innerHTML = `<div class="empty-state ok">✅ No deep-RLS issues in ${policyChecks.length} table(s).</div>`;
    return;
  }

  const s = summarizeRlsAudit(findings, policyChecks);
  const plan = buildRemediationPlan(findings);
  _rlsPlan = plan;
  _rlsReportMd = renderRlsReportMarkdown(findings, policyChecks);

  const order = { catastrophic: 5, critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const actionable = findings.filter(f => !f.managed).sort((a, b) => (order[b.severity] || 0) - (order[a.severity] || 0));
  const managed = findings.filter(f => f.managed);

  // ---- Summary header + severity chips ----
  const sevChips = ['high', 'medium', 'low']
    .filter(sev => s.bySeverity[sev])
    .map(sev => `<span class="badge badge-${sev}">${s.bySeverity[sev]} ${sev}</span>`)
    .join(' ');
  const head = `
    <div class="rls-summary">
      <div class="rls-summary-line">
        <strong>${s.tables}</strong> tables analyzed ·
        <strong>${s.actionable}</strong> actionable ·
        <span class="muted">${s.managedRaw} in Supabase-managed schemas (collapsed)</span>
      </div>
      <div class="rls-summary-chips">${sevChips}</div>
    </div>`;

  // ---- Remediation plan ----
  const planHead = `
    <div class="rls-plan-head">
      <h4>Remediation plan <span class="muted">· ${plan.length} step${plan.length === 1 ? '' : 's'}</span></h4>
      <button class="btn btn-ghost btn-sm" data-copy-report>📋 Copy full plan</button>
    </div>`;
  const planCards = plan.map((step, i) => {
    const tablePreview = step.tables.length
      ? `<details class="rls-tables"><summary>${step.tables.length} affected ${step.tables.length === 1 ? 'object' : 'objects'}</summary><div class="rls-tables-list">${step.tables.map(t => `<code>${esc(t)}</code>`).join(' ')}</div></details>`
      : '';
    const sqlBlock = step.sql
      ? `<div class="rls-fix-block">
           <div class="rls-fix-head"><span class="rls-fix-label">Consolidated migration</span><button class="btn btn-ghost btn-sm" data-copy-step="${i}" data-what="sql">📋 Copy SQL</button></div>
           <pre class="rls-sql">${esc(step.sql)}</pre>
         </div>`
      : `<div class="hint">No automatic SQL — this needs a policy predicate. Use the prompt above.</div>`;
    return `
      <div class="rls-plan-step card sev-${severityClass(step.severity)}">
        <div class="rls-plan-step-head">
          <span class="badge badge-${step.severity}">${esc(step.ruleId)}</span>
          <span class="rls-plan-step-title">${esc(step.label)}</span>
          <span class="muted rls-plan-step-count">${step.count} item${step.count === 1 ? '' : 's'}</span>
        </div>
        ${tablePreview}
        <div class="rls-prompt-block">
          <div class="rls-fix-head"><span class="rls-fix-label">Prompt for Lovable</span><button class="btn btn-ghost btn-sm" data-copy-step="${i}" data-what="prompt">📋 Copy prompt</button></div>
          <p class="rls-prompt">${esc(step.prompt)}</p>
        </div>
        ${sqlBlock}
      </div>`;
  }).join('');

  // ---- Collapsible: all actionable findings (raw) ----
  const rawRows = actionable.map(f => findingRowHtml(f)).join('');
  const rawDetails = `
    <details class="rls-raw">
      <summary>Show all ${actionable.length} actionable finding${actionable.length === 1 ? '' : 's'}</summary>
      <div class="rls-raw-list">${rawRows}</div>
    </details>`;

  // ---- Collapsible: managed-schema context ----
  const managedDetails = managed.length ? `
    <details class="rls-managed">
      <summary>${managed.length} finding${managed.length === 1 ? '' : 's'} in Supabase-managed schemas (context only)</summary>
      <div class="hint">These live in platform schemas (auth, storage, realtime, …) or are platform roles. You can't ALTER them from the SQL editor — Supabase controls them. Shown so the audit is complete.</div>
      <div class="rls-raw-list">${managed.map(f => findingRowHtml(f)).join('')}</div>
    </details>` : '';

  container.innerHTML = head + planHead + planCards + rawDetails + managedDetails;

  // ---- Wire copy buttons (CSP-safe: no inline handlers) ----
  container.querySelectorAll('[data-copy-step]').forEach(btn => {
    btn.addEventListener('click', () => {
      const step = _rlsPlan[+btn.dataset.copyStep];
      if (!step) return;
      const text = btn.dataset.what === 'sql' ? step.sql : step.prompt;
      copyText(text, btn, btn.textContent);
    });
  });
  const reportBtn = container.querySelector('[data-copy-report]');
  if (reportBtn) reportBtn.addEventListener('click', () => copyText(_rlsReportMd, reportBtn, reportBtn.textContent));
}

function findingRowHtml(f) {
  return `
    <div class="finding-row">
      <span class="finding-sev sev-dot sev-${severityClass(f.severity)}"></span>
      <div class="finding-body">
        <div class="finding-title"><code>${esc(f.ruleId)}</code> ${esc(f.title)}</div>
        <div class="finding-evidence">${esc(f.evidence)}</div>
        ${f.remediationSql ? `<pre class="finding-fix">${esc(f.remediationSql)}</pre>` : ''}
      </div>
    </div>`;
}

function copyText(text, btn, orig) {
  navigator.clipboard.writeText(String(text || '')).then(() => {
    btn.textContent = '✓ Copied';
    setTimeout(() => { btn.textContent = orig; }, 1500);
  }).catch(() => {
    btn.textContent = '✗ blocked';
    setTimeout(() => { btn.textContent = orig; }, 1500);
  });
}

function flash(id, text) {
  const el = $(id);
  if (!el) return;
  const orig = el.textContent;
  el.textContent = text;
  setTimeout(() => { el.textContent = orig; }, 1500);
}

function esc(str) {
  return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function fmtDate(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleDateString('en-US', { day: '2-digit', month: 'short', year: 'numeric' }); }
  catch { return iso; }
}

function severityClass(sev) {
  return { catastrophic: 'catastrophic', critical: 'critical', high: 'high', medium: 'medium', low: 'low', clean: 'clean' }[sev] || 'neutral';
}
