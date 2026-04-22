// ============================================================
// Lovable Portfolio Audit — Main Application
// ============================================================

import './style.css';
import { ScannerEngine, generateDemoData } from './lib/audit-engine';
import { getSeverityColor, isPreCutoff } from './lib/health-scorer';
import { t, setLocale, getLocale, loadLocale, LOCALE_FLAGS, type Locale } from './lib/i18n';
import type { ProjectScanResult, ScanProgress, ScannerConfig, ScanSummary } from './lib/types';

// ---- Application State ----
interface AppState {
  currentPage: 'dashboard' | 'config' | 'scan' | 'results';
  config: ScannerConfig;
  results: ProjectScanResult[];
  summary: ScanSummary | null;
  scanProgress: ScanProgress | null;
  selectedProject: ProjectScanResult | null;
  detailOpen: boolean;
  scanEngine: ScannerEngine | null;
  isDemoMode: boolean;
}

const state: AppState = {
  currentPage: 'dashboard',
  config: {
    lovableToken: '',
    scanDelay: 500,
    maxConcurrent: 1,
    includeChat: true,
    includeFiles: true,
    testRLS: true,
  },
  results: [],
  summary: null,
  scanProgress: null,
  selectedProject: null,
  detailOpen: false,
  scanEngine: null,
  isDemoMode: false,
};

// ---- Persistence ----
function saveConfig() {
  try { localStorage.setItem('lss_config', JSON.stringify(state.config)); } catch { /* */ }
}
function loadConfig() {
  try {
    const s = localStorage.getItem('lss_config');
    if (s) state.config = { ...state.config, ...JSON.parse(s) };
  } catch { /* */ }
}
function saveResults() {
  try {
    localStorage.setItem('lss_results', JSON.stringify(state.results));
    if (state.summary) localStorage.setItem('lss_summary', JSON.stringify(state.summary));
  } catch { /* */ }
}
function loadResults() {
  try {
    const s = localStorage.getItem('lss_results');
    if (s) state.results = JSON.parse(s);
    const sm = localStorage.getItem('lss_summary');
    if (sm) state.summary = JSON.parse(sm);
  } catch { /* */ }
}

// ---- Helpers ----
function navigate(page: AppState['currentPage']) { state.currentPage = page; render(); }

function formatDate(iso: string): string {
  try { return new Date(iso).toLocaleDateString(getLocale() === 'pt' ? 'pt-BR' : getLocale() === 'es' ? 'es-ES' : 'en-US', { day: '2-digit', month: 'short', year: 'numeric' }); } catch { return iso; }
}
function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
}

function severityLabel(sev: string): string { return t(`severity.${sev}`); }
function severityEmoji(sev: string): string {
  const m: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', clean: '🟢' };
  return m[sev] || '';
}

function riskScoreRing(score: number, severity: ProjectScanResult['severity']): string {
  const r = 22, c = 2 * Math.PI * r, o = c - (score / 100) * c, color = getSeverityColor(severity);
  return `<div class="risk-score-ring"><svg width="56" height="56" viewBox="0 0 56 56"><circle class="ring-bg" cx="28" cy="28" r="${r}" fill="none" stroke-width="4"/><circle class="ring-fill" cx="28" cy="28" r="${r}" fill="none" stroke="${color}" stroke-width="4" stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${o}"/></svg><span class="risk-score-value" style="color:${color}">${score}</span></div>`;
}

// ---- Language Switcher HTML ----
function langSwitcher(): string {
  const locales: Locale[] = ['en', 'pt', 'es'];
  return `
    <div class="lang-switcher">
      ${locales.map(l => `<button class="lang-btn ${getLocale() === l ? 'active' : ''}" data-lang="${l}" title="${l.toUpperCase()}">${LOCALE_FLAGS[l]}</button>`).join('')}
    </div>
  `;
}

// ---- Credits HTML ----
function creditsBlock(): string {
  return `
    <div class="credits-card">
      <a href="https://linkedin.com/in/lucioamorim" target="_blank" rel="noopener noreferrer">
        <div class="credits-label">${t('credits.title')}</div>
        <div class="credits-name">${t('credits.name')}</div>
        <div class="credits-role">${t('credits.role')}</div>
      </a>
    </div>
  `;
}

// ---- Render: Sidebar ----
function renderSidebar(): string {
  const critCount = state.results.filter(r => r.severity === 'critical').length;
  const totalFindings = state.results.reduce((sum, r) => sum + r.findings.length, 0);
  return `
    <nav class="sidebar">
      <div class="sidebar-logo">
        <div class="sidebar-logo-icon">🛡️</div>
        <div class="sidebar-logo-text">${t('sidebar.title')}<small>${t('sidebar.subtitle')}</small></div>
      </div>

      <div class="nav-section">
        <div class="nav-section-title">${t('nav.overview')}</div>
        <div class="nav-item ${state.currentPage === 'dashboard' ? 'active' : ''}" data-nav="dashboard">
          <span class="nav-item-icon">📊</span>${t('nav.dashboard')}
          ${totalFindings > 0 ? `<span class="nav-item-badge">${totalFindings}</span>` : ''}
        </div>
        <div class="nav-item ${state.currentPage === 'results' ? 'active' : ''}" data-nav="results">
          <span class="nav-item-icon">📋</span>${t('nav.results')}
          ${critCount > 0 ? `<span class="nav-item-badge">${critCount} ${t('nav.crit_badge')}</span>` : ''}
        </div>
      </div>

      <div class="nav-section">
        <div class="nav-section-title">${t('nav.actions')}</div>
        <div class="nav-item ${state.currentPage === 'scan' ? 'active' : ''}" data-nav="scan">
          <span class="nav-item-icon">🔍</span>${t('nav.run_scan')}
        </div>
        <div class="nav-item ${state.currentPage === 'config' ? 'active' : ''}" data-nav="config">
          <span class="nav-item-icon">⚙️</span>${t('nav.config')}
        </div>
      </div>

      <div class="nav-section">
        <div class="nav-section-title">${t('nav.reference')}</div>
        <div class="nav-item" onclick="window.open('https://docs.lovable.dev/tips-tricks/security','_blank')">
          <span class="nav-item-icon">📖</span>${t('nav.docs_lovable')}
        </div>
        <div class="nav-item" onclick="window.open('https://supabase.com/docs/guides/database/postgres/row-level-security','_blank')">
          <span class="nav-item-icon">🔒</span>${t('nav.supabase_rls')}
        </div>
      </div>

      <div class="sidebar-footer">
        ${langSwitcher()}
        <div class="sidebar-footer-text">
          ${t('sidebar.footer.line1')}<br>${t('sidebar.footer.line2')}<br>${t('sidebar.footer.line3')}
        </div>
        ${creditsBlock()}
      </div>
    </nav>`;
}

// ---- Render: Project List ----
function renderProjectList(projects: ProjectScanResult[]): string {
  if (!projects.length) return `<div class="empty-state"><div class="empty-state-icon">📭</div><div class="empty-state-title">${t('empty.no_projects')}</div></div>`;
  return `<div class="project-list">${projects.map(p => {
    const fCount = p.findings.length;
    return `
    <div class="card project-card severity-${p.severity}" data-project-id="${p.projectId}">
      <div class="project-card-header">
        <div style="display:flex;align-items:center;gap:var(--space-md)">
          ${riskScoreRing(p.riskScore, p.severity)}
          <div>
            <div class="project-name">${severityEmoji(p.severity)} ${p.projectName}</div>
            <div class="project-meta">
              <span class="project-meta-item">📅 ${t('project.created')} ${formatDate(p.createdAt)}</span>
              <span class="project-meta-item">✏️ ${t('project.edited')} ${formatDate(p.updatedAt)}</span>
              <span class="project-meta-item">📁 ${p.filesScanned} ${t('project.files')}</span>
              <span class="project-meta-item">💬 ${p.chatMessagesScanned} ${t('project.msgs')}</span>
            </div>
          </div>
        </div>
        <span class="severity-badge ${p.severity}">${severityLabel(p.severity)}</span>
      </div>
      <div class="project-findings-row">
        <span class="finding-tag ${p.bolaFileStatus === 'vulnerable' ? 'critical' : ''}"><span class="status-dot ${p.bolaFileStatus}"></span>${t('project.files_label')} ${p.bolaFileStatus === 'vulnerable' ? t('project.exposed') : p.bolaFileStatus === 'protected' ? t('project.protected') : '?'}</span>
        <span class="finding-tag ${p.bolaChatStatus === 'vulnerable' ? 'critical' : ''}"><span class="status-dot ${p.bolaChatStatus}"></span>${t('project.chat_label')} ${p.bolaChatStatus === 'vulnerable' ? t('project.exposed') : p.bolaChatStatus === 'protected' ? t('project.protected') : '?'}</span>
        ${p.supabaseDetected ? `<span class="finding-tag ${p.rlsStatus === 'missing' ? 'critical' : ''}"><span class="status-dot ${p.rlsStatus === 'missing' ? 'vulnerable' : p.rlsStatus === 'enabled' ? 'protected' : 'unknown'}"></span>RLS: ${p.rlsStatus === 'missing' ? t('project.rls_missing') : p.rlsStatus === 'enabled' ? t('project.rls_active') : '?'}</span>` : ''}
        ${fCount > 0 ? `<span class="finding-tag ${p.findings.some(f => f.severity === 'critical') ? 'critical' : 'high'}">${fCount} ${fCount > 1 ? t('project.findings') : t('project.finding')}</span>` : ''}
      </div>
    </div>`;
  }).join('')}</div>`;
}

// ---- Render: Dashboard ----
function renderDashboard(): string {
  if (!state.results.length) {
    return `
      <div class="page-header"><h1 class="page-title">${t('dashboard.title')}</h1><p class="page-subtitle">${t('dashboard.subtitle')}</p></div>
      <div class="empty-state">
        <div class="empty-state-icon">🔐</div>
        <div class="empty-state-title">${t('dashboard.empty.title')}</div>
        <div class="empty-state-desc">${t('dashboard.empty.desc')}</div>
        <div style="display:flex;gap:var(--space-md);justify-content:center;flex-wrap:wrap">
          <button class="btn btn-primary btn-lg" data-action="go-scan">🔍 ${t('dashboard.btn.start_scan')}</button>
          <button class="btn btn-ghost btn-lg" data-action="load-demo">📦 ${t('dashboard.btn.demo')}</button>
        </div>
      </div>`;
  }

  const cc = state.results.filter(r => r.severity === 'critical').length;
  const hc = state.results.filter(r => r.severity === 'high').length;
  const mc = state.results.filter(r => r.severity === 'medium').length;
  const clc = state.results.filter(r => r.severity === 'clean').length;
  const tf = state.results.reduce((s, r) => s + r.findings.length, 0);
  const pre = state.results.filter(r => isPreCutoff(r.createdAt)).length;

  const topFindings = state.results.flatMap(r => r.findings.map(f => ({ ...f, _pn: r.projectName }))).filter(f => f.severity === 'critical').slice(0, 5);

  return `
    <div class="page-header">
      <h1 class="page-title">${t('dashboard.title')}</h1>
      <p class="page-subtitle">
        ${state.results.length} ${t('dashboard.projects_scanned')}
        ${state.summary ? ` — ${t('dashboard.last_scan')} ${formatDate(state.summary.scanEndTime)}` : ''}
        ${state.isDemoMode ? ` — <span style="color:var(--color-medium)">${t('dashboard.demo_mode')}</span>` : ''}
      </p>
    </div>
    <div class="stats-grid animate-in animate-delay-1">
      <div class="card stat-card critical"><div class="stat-value">${cc}</div><div class="stat-label">${t('dashboard.stat.critical')}</div></div>
      <div class="card stat-card high"><div class="stat-value">${hc}</div><div class="stat-label">${t('dashboard.stat.high')}</div></div>
      <div class="card stat-card medium"><div class="stat-value">${mc}</div><div class="stat-label">${t('dashboard.stat.medium')}</div></div>
      <div class="card stat-card clean"><div class="stat-value">${clc}</div><div class="stat-label">${t('dashboard.stat.clean')}</div></div>
      <div class="card stat-card accent"><div class="stat-value">${tf}</div><div class="stat-label">${t('dashboard.stat.total_findings')}</div></div>
    </div>
    ${pre > 0 ? `<div class="alert alert-danger animate-in animate-delay-2"><span class="alert-icon">⚠️</span><div><strong>${pre} ${t('dashboard.alert.pre_cutoff_1')}</strong> ${t('dashboard.alert.pre_cutoff_2')}</div></div>` : ''}
    ${topFindings.length > 0 ? `<div class="animate-in animate-delay-3"><h2 style="font-size:1.1rem;font-weight:700;margin-bottom:var(--space-md)">${t('dashboard.critical_findings')}</h2>${topFindings.map(f => `<div class="finding-card critical"><div class="finding-title"><span class="severity-badge critical">CRITICAL</span> ${(f as any)._pn} — ${f.title}</div><div class="finding-description">${f.description}</div><div class="finding-evidence">${f.evidence}</div></div>`).join('')}</div>` : ''}
    <div class="animate-in animate-delay-4" style="margin-top:var(--space-xl)">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--space-md)">
        <h2 style="font-size:1.1rem;font-weight:700">${t('dashboard.projects_by_risk')}</h2>
        <button class="btn btn-ghost btn-sm" data-nav="results">${t('dashboard.btn.view_all')}</button>
      </div>
      ${renderProjectList(state.results.sort((a, b) => b.riskScore - a.riskScore).slice(0, 5))}
    </div>
    <div class="export-actions animate-in animate-delay-5">
      <button class="btn btn-ghost" data-action="export-json">${t('dashboard.btn.export_json')}</button>
      <button class="btn btn-ghost" data-action="export-csv">${t('dashboard.btn.export_csv')}</button>
      <button class="btn btn-ghost" data-action="clear-results">${t('dashboard.btn.clear')}</button>
    </div>`;
}

// ---- Render: Results ----
function renderResults(): string {
  const sorted = [...state.results].sort((a, b) => b.riskScore - a.riskScore);
  return `
    <div class="page-header"><h1 class="page-title">${t('results.title')}</h1><p class="page-subtitle">${state.results.length} ${t('results.subtitle_1')}</p></div>
    ${state.results.length > 0 ? `<div style="display:flex;gap:var(--space-md);margin-bottom:var(--space-lg);flex-wrap:wrap">
      <button class="btn btn-primary btn-sm" data-filter="all">${t('results.filter.all')} (${state.results.length})</button>
      <button class="btn btn-ghost btn-sm" data-filter="critical">${t('results.filter.critical')} (${state.results.filter(r => r.severity === 'critical').length})</button>
      <button class="btn btn-ghost btn-sm" data-filter="high">${t('results.filter.high')} (${state.results.filter(r => r.severity === 'high').length})</button>
      <button class="btn btn-ghost btn-sm" data-filter="medium">${t('results.filter.medium')} (${state.results.filter(r => r.severity === 'medium').length})</button>
      <button class="btn btn-ghost btn-sm" data-filter="clean">${t('results.filter.clean')} (${state.results.filter(r => r.severity === 'clean').length})</button>
    </div>` : ''}
    ${renderProjectList(sorted)}
    ${state.results.length > 0 ? `<div class="export-actions" style="margin-top:var(--space-xl)"><button class="btn btn-ghost" data-action="export-json">${t('dashboard.btn.export_json')}</button><button class="btn btn-ghost" data-action="export-csv">${t('dashboard.btn.export_csv')}</button></div>` : ''}`;
}

// ---- Render: Config ----
function renderConfig(): string {
  return `
    <div class="page-header"><h1 class="page-title">${t('config.title')}</h1><p class="page-subtitle">${t('config.subtitle')}</p></div>
    <div class="config-section">
      <div class="config-card">
        <div class="config-card-title">${t('config.token.title')}</div>
        <div class="config-card-desc">${t('config.token.desc')}</div>
        <div class="alert alert-warning"><span class="alert-icon">⚠️</span><div><strong>${t('config.token.warning')}</strong> ${t('config.token.warning_detail')}</div></div>
        <div class="input-group">
          <label class="input-label" for="input-token">${t('config.token.label')}</label>
          <textarea class="input" id="input-token" placeholder="eyJ..." rows="3">${state.config.lovableToken}</textarea>
          <div class="input-hint">${t('config.token.hint')}</div>
        </div>
      </div>
      <div class="config-card">
        <div class="config-card-title">${t('config.options.title')}</div>
        <div class="config-card-desc">${t('config.options.desc')}</div>
        <div class="toggle-group"><label class="toggle"><input type="checkbox" id="toggle-files" ${state.config.includeFiles ? 'checked' : ''}><span class="toggle-slider"></span></label><label class="toggle-label" for="toggle-files">${t('config.toggle.files')}</label></div>
        <div class="toggle-group"><label class="toggle"><input type="checkbox" id="toggle-chat" ${state.config.includeChat ? 'checked' : ''}><span class="toggle-slider"></span></label><label class="toggle-label" for="toggle-chat">${t('config.toggle.chat')}</label></div>
        <div class="toggle-group"><label class="toggle"><input type="checkbox" id="toggle-rls" ${state.config.testRLS ? 'checked' : ''}><span class="toggle-slider"></span></label><label class="toggle-label" for="toggle-rls">${t('config.toggle.rls')}</label></div>
        <div class="input-group" style="margin-top:var(--space-md)">
          <label class="input-label" for="input-delay">${t('config.delay.label')}</label>
          <input class="input" type="number" id="input-delay" value="${state.config.scanDelay}" min="200" max="5000" step="100" style="max-width:200px">
          <div class="input-hint">${t('config.delay.hint')}</div>
        </div>
      </div>
      <div class="config-card">
        <div class="config-card-title">${t('config.filter.title')}</div>
        <div class="config-card-desc">${t('config.filter.desc')}</div>
        <div class="input-group">
          <label class="input-label" for="input-filter">${t('config.filter.label')}</label>
          <textarea class="input" id="input-filter" placeholder="abc123-def456-..." rows="4">${(state.config.projectFilter || []).join('\n')}</textarea>
        </div>
      </div>
      <button class="btn btn-primary btn-lg" data-action="save-config" style="width:100%">${t('config.btn.save')}</button>
    </div>`;
}

// ---- Render: Scan Page ----
function renderScan(): string {
  const hasToken = state.config.lovableToken.length > 20;
  const isRunning = state.scanProgress?.status === 'running';

  let progress = '';
  if (state.scanProgress) {
    const p = state.scanProgress;
    const statusText = p.status === 'running' ? `<span class="progress-spinner"></span> ${t('scan.progress.scanning')}` : p.status === 'completed' ? t('scan.progress.completed') : p.status === 'error' ? t('scan.progress.error') : t('scan.progress.paused');
    progress = `
      <div class="progress-container">
        <div class="progress-header"><span class="progress-title">${statusText}</span><span class="progress-value">${p.percentage}%</span></div>
        <div class="progress-bar"><div class="progress-fill" style="width:${p.percentage}%"></div></div>
        <div class="progress-status">${p.currentProject ? `${t('scan.progress.current')} <strong>${p.currentProject}</strong>` : ''} &nbsp;—&nbsp; ${p.currentProjectIndex}/${p.totalProjects} ${t('scan.progress.projects')} &nbsp;—&nbsp; ${p.findings} ${t('scan.progress.findings')}</div>
      </div>
      ${p.errors.length > 0 ? `<div class="alert alert-warning" style="margin-top:var(--space-md)"><span class="alert-icon">⚠️</span><div><strong>${p.errors.length} ${t('scan.progress.errors')}</strong><br>${p.errors.slice(-3).map(e => `• ${e}`).join('<br>')}</div></div>` : ''}`;
  }

  return `
    <div class="page-header"><h1 class="page-title">${t('scan.title')}</h1><p class="page-subtitle">${t('scan.subtitle')}</p></div>
    ${!hasToken ? `<div class="alert alert-danger"><span class="alert-icon">🔑</span><div><strong>${t('scan.no_token')}</strong> ${t('scan.no_token_detail')} <a href="#" data-nav="config" style="color:inherit;text-decoration:underline">${t('scan.no_token_link')}</a> ${t('scan.no_token_suffix')}</div></div>` : ''}
    <div class="card" style="padding:var(--space-xl);margin-bottom:var(--space-lg)">
      <h2 style="font-size:1.1rem;font-weight:700;margin-bottom:var(--space-md)">${t('scan.what_checks')}</h2>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--space-md);font-size:0.85rem">
        <div><strong style="color:var(--color-critical)">${t('scan.check.bola')}</strong><br><span style="color:var(--text-secondary)">${t('scan.check.bola_desc')}</span></div>
        <div><strong style="color:var(--color-critical)">${t('scan.check.creds')}</strong><br><span style="color:var(--text-secondary)">${t('scan.check.creds_desc')}</span></div>
        <div><strong style="color:var(--color-high)">${t('scan.check.rls')}</strong><br><span style="color:var(--text-secondary)">${t('scan.check.rls_desc')}</span></div>
        <div><strong style="color:var(--color-medium)">${t('scan.check.pii')}</strong><br><span style="color:var(--text-secondary)">${t('scan.check.pii_desc')}</span></div>
      </div>
    </div>
    <div style="display:flex;gap:var(--space-md);margin-bottom:var(--space-lg)">
      ${!isRunning ? `<button class="btn btn-primary btn-lg" data-action="start-scan" ${!hasToken ? 'disabled' : ''}>${t('scan.btn.start')}</button><button class="btn btn-ghost btn-lg" data-action="load-demo">${t('scan.btn.demo')}</button>` : `<button class="btn btn-danger btn-lg" data-action="stop-scan">${t('scan.btn.stop')}</button>`}
    </div>
    ${progress}
    ${state.results.length > 0 && !isRunning ? `<div style="margin-top:var(--space-xl)"><h2 style="font-size:1.1rem;font-weight:700;margin-bottom:var(--space-md)">${t('scan.last_results')}</h2>${renderProjectList(state.results.sort((a, b) => b.riskScore - a.riskScore).slice(0, 3))}<button class="btn btn-ghost btn-sm" data-nav="results" style="margin-top:var(--space-md)">${t('scan.btn.view_all')}</button></div>` : ''}`;
}

// ---- Render: Detail Panel ----
function renderDetailPanel(): string {
  if (!state.selectedProject) return '';
  const p = state.selectedProject;
  const color = getSeverityColor(p.severity);

  const bolaFileText = p.bolaFileStatus === 'vulnerable' ? t('detail.exposure.exposed') : p.bolaFileStatus === 'protected' ? t('detail.exposure.protected') : t('detail.exposure.not_tested');
  const bolaChatText = p.bolaChatStatus === 'vulnerable' ? t('detail.exposure.exposed') : p.bolaChatStatus === 'protected' ? t('detail.exposure.protected') : t('detail.exposure.not_tested');
  const rlsText = p.rlsStatus === 'missing' ? t('detail.exposure.rls_missing') : p.rlsStatus === 'enabled' ? t('detail.exposure.rls_active') : p.rlsStatus === 'partial' ? t('detail.exposure.rls_partial') : t('detail.exposure.not_tested');

  return `
    <div class="detail-panel-overlay ${state.detailOpen ? 'open' : ''}" data-action="close-detail"></div>
    <div class="detail-panel ${state.detailOpen ? 'open' : ''}">
      <div class="detail-header">
        <div>
          <div style="font-size:1.05rem;font-weight:700">${severityEmoji(p.severity)} ${p.projectName}</div>
          <div style="font-size:0.78rem;color:var(--text-secondary)">Score: <span style="color:${color};font-weight:800">${p.riskScore}/100</span> — ${severityLabel(p.severity)}</div>
        </div>
        <button class="detail-close" data-action="close-detail">✕</button>
      </div>
      <div class="detail-body">
        <div class="detail-section">
          <div class="detail-section-title">${t('detail.info.title')}</div>
          <div class="kv-grid">
            <span class="kv-key">${t('detail.info.id')}</span><span class="kv-value mono">${p.projectId}</span>
            <span class="kv-key">${t('detail.info.created')}</span><span class="kv-value">${formatDate(p.createdAt)} ${isPreCutoff(p.createdAt) ? t('detail.info.pre_patch') : t('detail.info.post_patch')}</span>
            <span class="kv-key">${t('detail.info.last_edit')}</span><span class="kv-value">${formatDate(p.updatedAt)}</span>
            <span class="kv-key">${t('detail.info.scan_at')}</span><span class="kv-value">${formatDate(p.scanTimestamp)}</span>
            <span class="kv-key">${t('detail.info.duration')}</span><span class="kv-value">${formatDuration(p.scanDurationMs)}</span>
          </div>
        </div>
        <div class="detail-section">
          <div class="detail-section-title">${t('detail.exposure.title')}</div>
          <div class="kv-grid">
            <span class="kv-key">${t('detail.exposure.files_bola')}</span><span class="kv-value"><span class="status-dot ${p.bolaFileStatus}"></span>${bolaFileText}</span>
            <span class="kv-key">${t('detail.exposure.chat_bola')}</span><span class="kv-value"><span class="status-dot ${p.bolaChatStatus}"></span>${bolaChatText}</span>
            <span class="kv-key">${t('detail.exposure.supabase')}</span><span class="kv-value">${p.supabaseDetected ? `${t('detail.exposure.yes')} — ${p.supabaseUrl || ''}` : t('detail.exposure.not_detected')}</span>
            <span class="kv-key">${t('detail.exposure.rls')}</span><span class="kv-value">${rlsText}</span>
            <span class="kv-key">${t('detail.exposure.files_scanned')}</span><span class="kv-value">${p.filesScanned}</span>
            <span class="kv-key">${t('detail.exposure.msgs_scanned')}</span><span class="kv-value">${p.chatMessagesScanned}</span>
          </div>
        </div>
        <div class="detail-section">
          <div class="detail-section-title">${t('detail.findings.title')} (${p.findings.length})</div>
          ${p.findings.length === 0 ? `<div style="text-align:center;padding:var(--space-lg);color:var(--text-muted)">${t('detail.findings.clean')}</div>` : ''}
          ${p.findings.map(f => `
            <div class="finding-card ${f.severity}">
              <div class="finding-title"><span class="severity-badge ${f.severity}">${f.severity.toUpperCase()}</span> ${f.title}</div>
              <div class="finding-description">${f.description}</div>
              ${f.file ? `<div style="font-size:0.72rem;color:var(--text-muted);margin-bottom:4px">📄 ${f.file}${f.line ? `:${f.line}` : ''}</div>` : ''}
              <div class="finding-evidence">${f.evidence}</div>
              <div class="finding-recommendation">💡 ${f.recommendation}</div>
            </div>`).join('')}
        </div>
      </div>
    </div>`;
}

// ---- Main Render ----
function render() {
  const app = document.getElementById('app')!;
  let page = '';
  switch (state.currentPage) {
    case 'dashboard': page = renderDashboard(); break;
    case 'config': page = renderConfig(); break;
    case 'scan': page = renderScan(); break;
    case 'results': page = renderResults(); break;
  }
  app.innerHTML = `${renderSidebar()}<main class="main-content">${page}</main>${renderDetailPanel()}`;
  attachEventListeners();
}

// ---- Events ----
function attachEventListeners() {
  // Navigation
  document.querySelectorAll('[data-nav]').forEach(el => {
    el.addEventListener('click', (e) => { e.preventDefault(); navigate((el as HTMLElement).dataset.nav as AppState['currentPage']); });
  });

  // Language switcher
  document.querySelectorAll('[data-lang]').forEach(el => {
    el.addEventListener('click', () => {
      setLocale((el as HTMLElement).dataset.lang as Locale);
      render();
    });
  });

  // Project click
  document.querySelectorAll('[data-project-id]').forEach(el => {
    el.addEventListener('click', () => {
      const p = state.results.find(r => r.projectId === (el as HTMLElement).dataset.projectId);
      if (p) { state.selectedProject = p; state.detailOpen = true; render(); }
    });
  });

  // Close detail
  document.querySelectorAll('[data-action="close-detail"]').forEach(el => {
    el.addEventListener('click', () => { state.detailOpen = false; render(); });
  });

  // Actions
  document.querySelectorAll('[data-action]').forEach(el => {
    const action = (el as HTMLElement).dataset.action;
    el.addEventListener('click', () => {
      switch (action) {
        case 'go-scan': navigate('scan'); break;
        case 'load-demo':
          state.results = generateDemoData();
          state.isDemoMode = true;
          state.summary = {
            totalProjects: state.results.length, scannedProjects: state.results.length,
            criticalCount: state.results.filter(r => r.severity === 'critical').length,
            highCount: state.results.filter(r => r.severity === 'high').length,
            mediumCount: state.results.filter(r => r.severity === 'medium').length,
            lowCount: state.results.filter(r => r.severity === 'low').length,
            cleanCount: state.results.filter(r => r.severity === 'clean').length,
            topFindings: state.results.flatMap(r => r.findings).slice(0, 10),
            scanStartTime: new Date().toISOString(), scanEndTime: new Date().toISOString(),
            totalDurationMs: 22800,
          };
          saveResults(); navigate('dashboard'); break;
        case 'save-config': saveConfigFromForm(); break;
        case 'start-scan': startScan(); break;
        case 'stop-scan': if (state.scanEngine) state.scanEngine.abort(); break;
        case 'export-json': exportJSON(); break;
        case 'export-csv': exportCSV(); break;
        case 'clear-results':
          state.results = []; state.summary = null; state.isDemoMode = false;
          localStorage.removeItem('lss_results'); localStorage.removeItem('lss_summary');
          render(); break;
      }
    });
  });

  // Filters
  document.querySelectorAll('[data-filter]').forEach(el => {
    el.addEventListener('click', () => {
      const f = (el as HTMLElement).dataset.filter;
      document.querySelectorAll('.project-card').forEach(c => {
        (c as HTMLElement).style.display = f === 'all' || (c as HTMLElement).classList.contains(`severity-${f}`) ? '' : 'none';
      });
      document.querySelectorAll('[data-filter]').forEach(b => {
        (b as HTMLElement).className = (b as HTMLElement).dataset.filter === f ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm';
      });
    });
  });
}

function saveConfigFromForm() {
  const token = (document.getElementById('input-token') as HTMLTextAreaElement)?.value || '';
  const delay = parseInt((document.getElementById('input-delay') as HTMLInputElement)?.value || '500');
  const includeFiles = (document.getElementById('toggle-files') as HTMLInputElement)?.checked ?? true;
  const includeChat = (document.getElementById('toggle-chat') as HTMLInputElement)?.checked ?? true;
  const testRLS = (document.getElementById('toggle-rls') as HTMLInputElement)?.checked ?? true;
  const filterText = (document.getElementById('input-filter') as HTMLTextAreaElement)?.value || '';
  const projectFilter = filterText.split('\n').map(s => s.trim()).filter(s => s.length > 0);
  state.config = { ...state.config, lovableToken: token.trim(), scanDelay: Math.max(200, delay), includeFiles, includeChat, testRLS, projectFilter: projectFilter.length > 0 ? projectFilter : undefined };
  saveConfig();
  const btn = document.querySelector('[data-action="save-config"]') as HTMLButtonElement;
  if (btn) {
    const orig = btn.innerHTML; btn.innerHTML = t('config.btn.saved');
    btn.classList.add('btn-ghost'); btn.classList.remove('btn-primary');
    setTimeout(() => { btn.innerHTML = orig; btn.classList.remove('btn-ghost'); btn.classList.add('btn-primary'); }, 2000);
  }
}

async function startScan() {
  state.isDemoMode = false; state.results = [];
  state.scanEngine = new ScannerEngine(state.config);
  const summary = await state.scanEngine.runScan(
    (progress) => { state.scanProgress = progress; updateProgressUI(); },
    (result) => { state.results.push(result); saveResults(); }
  );
  state.summary = summary; saveResults(); state.scanEngine = null; render();
}

let progressTimeout: ReturnType<typeof setTimeout> | null = null;
function updateProgressUI() {
  if (progressTimeout) return;
  progressTimeout = setTimeout(() => {
    progressTimeout = null;
    const c = document.querySelector('.progress-container');
    if (c && state.scanProgress) {
      const fill = c.querySelector('.progress-fill') as HTMLElement;
      const val = c.querySelector('.progress-value');
      const st = c.querySelector('.progress-status');
      if (fill) fill.style.width = `${state.scanProgress.percentage}%`;
      if (val) val.textContent = `${state.scanProgress.percentage}%`;
      if (st) st.innerHTML = `${state.scanProgress.currentProject ? `${t('scan.progress.current')} <strong>${state.scanProgress.currentProject}</strong>` : ''} &nbsp;—&nbsp; ${state.scanProgress.currentProjectIndex}/${state.scanProgress.totalProjects} ${t('scan.progress.projects')} &nbsp;—&nbsp; ${state.scanProgress.findings} ${t('scan.progress.findings')}`;
    } else { render(); }
  }, 200);
}

function exportJSON() {
  const blob = new Blob([JSON.stringify({ scanDate: new Date().toISOString(), summary: state.summary, results: state.results }, null, 2)], { type: 'application/json' });
  download(blob, `lovable-portfolio-audit-${new Date().toISOString().slice(0, 10)}.json`);
}
function exportCSV() {
  const h = ['Project', 'ID', 'Created', 'Score', 'Severity', 'Findings', 'BOLA Files', 'BOLA Chat', 'Supabase', 'RLS'];
  const rows = state.results.map(r => [r.projectName, r.projectId, r.createdAt, r.riskScore, r.severity, r.findings.length, r.bolaFileStatus, r.bolaChatStatus, r.supabaseDetected ? 'yes' : 'no', r.rlsStatus || 'n/a'].map(c => `"${c}"`).join(','));
  const blob = new Blob([[h.join(','), ...rows].join('\n')], { type: 'text/csv' });
  download(blob, `lovable-portfolio-audit-${new Date().toISOString().slice(0, 10)}.csv`);
}
function download(blob: Blob, name: string) {
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click(); URL.revokeObjectURL(a.href);
}

// ---- Init ----
loadLocale();
loadConfig();
loadResults();
render();
