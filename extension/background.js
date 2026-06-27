// ============================================================
// Background Service Worker v2 — Skills-integrated
// ============================================================

import { runScan, abortScan, generateDemoData } from './lib/audit-engine.js';
import { getSessionToken } from './lib/api-client.js';
import { createLogger } from './lib/skills/structured-logger.js';
import { isInitialized, isUnlocked, unlock, migrateLegacyToken } from './lib/skills/token-vault.js';
import { hasConsent, grantConsent, LEGAL_VERSION } from './lib/skills/consent-gate.js';
import { loadCatalog } from './lib/skills/pattern-catalog.js';
import { pruneRuns, listRuns } from './lib/skills/scan-history.js';
import { isKnownEndpoint } from './lib/passive-endpoints.js';

const logger = createLogger({ module: 'background' });

// ---- Keep-alive for long scans ----
let keepAliveInterval = null;
function startKeepAlive() {
  keepAliveInterval = setInterval(() => chrome.runtime.getPlatformInfo(() => {}), 25000);
}
function stopKeepAlive() {
  if (keepAliveInterval) { clearInterval(keepAliveInterval); keepAliveInterval = null; }
}

// ---- Badge helpers ----
function updateBadge(summary) {
  const crit = (summary.catastrophicCount || 0) + (summary.criticalCount || 0);
  if (crit > 0) {
    chrome.action.setBadgeText({ text: String(crit) });
    chrome.action.setBadgeBackgroundColor({ color: '#ff2e4c' });
  } else {
    chrome.action.setBadgeText({ text: '✓' });
    chrome.action.setBadgeBackgroundColor({ color: '#2ed573' });
  }
}

// ============================================================
// Passive sensor (Phase 2) — storage helpers
// ============================================================
const PASSIVE_MAX = 200;

async function recordEndpoint(path, meta) {
  if (!path || !path.startsWith('/')) return;
  const { lpa_observed_endpoints = {}, lpa_endpoint_candidates = {} } =
    await chrome.storage.local.get(['lpa_observed_endpoints', 'lpa_endpoint_candidates']);

  const prev = lpa_observed_endpoints[path] || { count: 0 };
  lpa_observed_endpoints[path] = {
    count: prev.count + 1,
    lastStatus: meta.status ?? prev.lastStatus ?? null,
    lastMethod: meta.method || prev.lastMethod || 'GET',
    lastSeen: new Date().toISOString(),
  };
  const updates = { lpa_observed_endpoints };

  // 5th-endpoint detection (P7): anything not in the known set is a candidate.
  if (!isKnownEndpoint(path) && !lpa_endpoint_candidates[path]) {
    lpa_endpoint_candidates[path] = {
      firstSeen: new Date().toISOString(), method: meta.method || 'GET', status: meta.status ?? null,
    };
    updates.lpa_endpoint_candidates = lpa_endpoint_candidates;
    logger.info('new Lovable endpoint observed (P7 candidate)', { path });
  }
  await chrome.storage.local.set(updates);
}

async function storePassiveFindings(findings, ctx) {
  if (!Array.isArray(findings) || findings.length === 0) return;
  // Consent gate: only persist when the user has accepted the legal terms.
  if (!(await hasConsent('L0_legal'))) return;

  const { lpa_passive_findings = [] } = await chrome.storage.local.get('lpa_passive_findings');
  const seen = new Set(lpa_passive_findings.map(f => `${f.hash}:${f.patternId}:${f.source}`));
  let added = 0;
  for (const f of findings) {
    const key = `${f.hash || ''}:${f.patternId}:${f.source || ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    lpa_passive_findings.unshift({ ...f, host: ctx.host || null, observedAt: new Date().toISOString() });
    added++;
  }
  const capped = lpa_passive_findings.slice(0, PASSIVE_MAX);
  await chrome.storage.local.set({ lpa_passive_findings: capped });
  if (added) {
    chrome.runtime.sendMessage({ type: 'PASSIVE_UPDATE', count: capped.length, added }).catch(() => {});
    logger.info('passive findings stored', { added, total: capped.length, host: ctx.host });
  }
}

async function storeRoutes(payload) {
  if (!(await hasConsent('L0_legal'))) return;
  const { lpa_passive_routes = {} } = await chrome.storage.local.get('lpa_passive_routes');
  const entry = lpa_passive_routes[payload.host] || { routes: [], chunks: [], sinks: [] };
  entry.routes = [...new Set([...(entry.routes || []), ...(payload.routes || [])])].slice(0, 100);
  entry.chunks = [...new Set([...(entry.chunks || []), ...(payload.chunks || [])])].slice(0, 100);
  entry.sinks = [...(entry.sinks || []), ...(payload.sinks || [])].slice(0, 50);
  entry.updatedAt = new Date().toISOString();
  lpa_passive_routes[payload.host] = entry;
  await chrome.storage.local.set({ lpa_passive_routes });
}

// ---- Message router ----
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  switch (msg.type) {

    case 'LOVABLE_AUTH_TOKEN': {
      if (msg.token) {
        const tokenVal = msg.token.replace(/^Bearer\s+/i, '');
        chrome.storage.local.set({ lss_manual_token: tokenVal });
        logger.info('auto-captured token from page context');
      }
      sendResponse({ received: true });
      return true;
    }

    case 'CHECK_SESSION': {
      getSessionToken().then(token => sendResponse({ hasSession: !!token }));
      return true;
    }

    case 'VAULT_STATUS': {
      Promise.all([isInitialized(), isUnlocked()]).then(([initialized, unlocked]) => {
        sendResponse({ initialized, unlocked });
      });
      return true;
    }

    case 'VAULT_UNLOCK': {
      unlock(msg.passphrase).then(ok => {
        if (ok) migrateLegacyToken().catch(() => {});
        sendResponse({ success: ok });
      });
      return true;
    }

    case 'CONSENT_STATUS': {
      Promise.all([
        hasConsent('L0_legal'),
        hasConsent('L1_safe_mode'),
      ]).then(([legal, safeMode]) => {
        sendResponse({ legal, safeMode, legalVersion: LEGAL_VERSION });
      });
      return true;
    }

    case 'GRANT_CONSENT': {
      grantConsent(msg.level, msg.scope).then(() => sendResponse({ granted: true }));
      return true;
    }

    case 'START_SCAN': {
      startKeepAlive();
      const config = {
        ...(msg.config || {}),
        includeFiles: !!(msg.config?.includeFiles),
        includeChat:  !!(msg.config?.includeChat),
        deepInspect:  !!(msg.config?.deepInspect),
        auditToken:   msg.config?.auditToken || null,
        scanDelay:    msg.config?.scanDelay || 500,
      };

      // Clear previous run results
      chrome.storage.local.remove(['lss_results', 'lss_summary', 'lss_demo']);

      runScan(
        config,
        (progress) => {
          chrome.runtime.sendMessage({ type: 'SCAN_PROGRESS', progress }).catch(() => {});
        },
        (result) => {
          chrome.storage.local.get('lss_results', ({ lss_results }) => {
            const results = lss_results || [];
            results.push(result);
            chrome.storage.local.set({ lss_results: results });
          });
          chrome.runtime.sendMessage({ type: 'SCAN_RESULT', result }).catch(() => {});
        }
      ).then(summary => {
        stopKeepAlive();
        chrome.storage.local.set({ lss_summary: summary });
        chrome.runtime.sendMessage({ type: 'SCAN_COMPLETE', summary }).catch(() => {});
        updateBadge(summary);
        logger.info('scan complete', { scanned: summary.scannedProjects, critical: summary.criticalCount });
      }).catch(err => {
        stopKeepAlive();
        logger.error('scan failed', err);
        chrome.runtime.sendMessage({ type: 'SCAN_ERROR', error: err.message }).catch(() => {});
      });

      sendResponse({ started: true });
      return true;
    }

    case 'STOP_SCAN': {
      abortScan();
      stopKeepAlive();
      sendResponse({ stopped: true });
      return true;
    }

    case 'LOAD_DEMO': {
      const results = generateDemoData();
      const summary = {
        totalProjects: results.length, scannedProjects: results.length,
        catastrophicCount: results.filter(r => r.severity === 'catastrophic').length,
        criticalCount: results.filter(r => r.severity === 'critical').length,
        highCount: results.filter(r => r.severity === 'high').length,
        mediumCount: results.filter(r => r.severity === 'medium').length,
        lowCount: results.filter(r => r.severity === 'low').length,
        cleanCount: results.filter(r => r.severity === 'clean').length,
      };
      chrome.storage.local.set({ lss_results: results, lss_summary: summary, lss_demo: true });
      updateBadge(summary);
      sendResponse({ results, summary });
      return true;
    }

    case 'GET_RESULTS': {
      chrome.storage.local.get(['lss_results', 'lss_summary', 'lss_demo'], (data) => {
        sendResponse({
          results: data.lss_results || [],
          summary: data.lss_summary || null,
          isDemoMode: data.lss_demo || false,
        });
      });
      return true;
    }

    case 'GET_HISTORY': {
      listRuns(20).then(runs => sendResponse({ runs }));
      return true;
    }

    case 'CLEAR_RESULTS': {
      chrome.storage.local.remove(['lss_results', 'lss_summary', 'lss_demo']);
      chrome.action.setBadgeText({ text: '' });
      sendResponse({ cleared: true });
      return true;
    }

    // ---- Passive sensor (Phase 2) ----
    case 'OBSERVED_ENDPOINT': {
      recordEndpoint(msg.path, { method: msg.method, status: msg.status }).catch(() => {});
      sendResponse({ ok: true });
      return true;
    }
    case 'PASSIVE_FINDINGS': {
      storePassiveFindings(msg.findings, { host: msg.host }).catch(() => {});
      sendResponse({ ok: true });
      return true;
    }
    case 'PASSIVE_STATE': {
      storePassiveFindings(msg.findings, { host: msg.host }).catch(() => {});
      sendResponse({ ok: true });
      return true;
    }
    case 'PASSIVE_ROUTES': {
      storeRoutes(msg).catch(() => {});
      sendResponse({ ok: true });
      return true;
    }
    case 'PASSIVE_GET': {
      chrome.storage.local.get(
        ['lpa_passive_findings', 'lpa_observed_endpoints', 'lpa_endpoint_candidates', 'lpa_passive_routes'],
        (d) => sendResponse({
          findings: d.lpa_passive_findings || [],
          endpoints: d.lpa_observed_endpoints || {},
          candidates: d.lpa_endpoint_candidates || {},
          routes: d.lpa_passive_routes || {},
        }),
      );
      return true;
    }
    case 'PASSIVE_CLEAR': {
      chrome.storage.local.remove(['lpa_passive_findings', 'lpa_observed_endpoints', 'lpa_endpoint_candidates', 'lpa_passive_routes']);
      sendResponse({ cleared: true });
      return true;
    }
  }
});

// ---- Alarms ----
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'refresh-patterns') {
    await loadCatalog().catch(() => {});
    logger.info('pattern catalog refreshed');
  }
  if (alarm.name === 'prune-history') {
    const removed = await pruneRuns(30).catch(() => 0);
    if (removed > 0) logger.info('history pruned', { removed });
  }
});

// ---- Install / startup ----
chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  logger.info('extension event', { reason });

  // Schedule periodic tasks
  chrome.alarms.create('refresh-patterns', { periodInMinutes: 60 * 24 });
  chrome.alarms.create('prune-history',    { periodInMinutes: 60 * 24 * 7 });

  // Side panel
  chrome.sidePanel?.setPanelBehavior?.({ openPanelOnActionClick: true });

  // Pre-load pattern catalog (warm cache)
  loadCatalog().catch(() => {});
});

chrome.runtime.onStartup.addListener(() => {
  loadCatalog().catch(() => {});
});

// Enable side panel on action click
chrome.sidePanel?.setPanelBehavior?.({ openPanelOnActionClick: true });
