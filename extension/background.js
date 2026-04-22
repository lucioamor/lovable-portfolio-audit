// ============================================================
// Background Service Worker v2 — Skills-integrated
// ============================================================

import { runScan, abortScan, generateDemoData } from './lib/audit-engine.js';
import { hasSession } from './lib/api-client.js';
import { createLogger } from './lib/skills/structured-logger.js';
import { isInitialized, isUnlocked, unlock, migrateLegacyToken } from './lib/skills/token-vault.js';
import { hasConsent, grantConsent, LEGAL_VERSION } from './lib/skills/consent-gate.js';
import { loadCatalog } from './lib/skills/pattern-catalog.js';
import { pruneRuns, listRuns } from './lib/skills/scan-history.js';

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

// ---- Message router ----
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  switch (msg.type) {

    case 'CHECK_SESSION': {
      hasSession().then(has => sendResponse({ hasSession: has }));
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
