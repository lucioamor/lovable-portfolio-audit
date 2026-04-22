// ============================================================
// Sidepanel v2 — NXLV Shield (Chrome Extension)
// ============================================================

import { isInitialized, initVault, isUnlocked, lock, putToken, getToken } from './lib/skills/token-vault.js';
import { hasConsent, grantConsent } from './lib/skills/consent-gate.js';
import { listPatterns, togglePattern, resetToggles, loadCatalog } from './lib/skills/pattern-catalog.js';
import { buildEvidencePack, deriveSigningKey } from './lib/evidence-pack.js';

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
  renderTab(state.activeTab);
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
}

function onScanError(error) {
  state.scanning = false;
  setVisible('scan-progress', false);
  $('scan-btn').disabled = false;
  $('scan-btn').textContent = '▶ Start Scan';
  $('progress-label').textContent = `Error: ${error}`;
  setVisible('scan-progress', true);
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
      <div class="project-detail hidden">
        <div class="probe-row">
          <span>Files: <code>${r.bolaFilesSignature}</code></span>
          <span>Chat: <code>${r.bolaChatSignature}</code></span>
          ${r.supabaseDetected ? `<span class="badge-warn">Supabase detected</span>` : ''}
        </div>
        ${findingHtml}
        ${extraCount}
      </div>
    </div>`;
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

  list.innerHTML = state.history.map((run, idx) => `
    <div class="history-row">
      <div class="history-run-info">
        <span class="history-idx">#${idx + 1}</span>
        <span class="history-date">${fmtDate(run.startedAt)}</span>
        <span class="history-projects">${run.projectCount} projects</span>
      </div>
      <div class="history-counts">
        ${run.severityCounts?.catastrophic ? `<span class="sev-dot sev-catastrophic"></span>${run.severityCounts.catastrophic}` : ''}
        ${run.severityCounts?.critical     ? `<span class="sev-dot sev-critical"></span>${run.severityCounts.critical}` : ''}
        ${run.severityCounts?.high         ? `<span class="sev-dot sev-high"></span>${run.severityCounts.high}` : ''}
        <span class="muted">avg ${run.scoreAverage}pts</span>
      </div>
    </div>`).join('');
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
    setVisible('vault-setup-modal', false);
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
      setVisible('vault-unlock-modal', false);
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
}

async function loadDemo() {
  const res = await msg('LOAD_DEMO');
  state.results    = res?.results || [];
  state.summary    = res?.summary || null;
  state.isDemoMode = true;
  renderSummaryGrid(state.summary);
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
    download: `nxlv-shield-${new Date().toISOString().slice(0, 10)}.json`,
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
