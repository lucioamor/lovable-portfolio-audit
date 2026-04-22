// ============================================================
// Scanner Engine — Orchestrator (Chrome Extension) v2
// Integrates all 10 skills for production-grade security.
// ============================================================

import { getSessionToken, listProjects, PROBE_ENDPOINTS, getProjectFiles, getFileContent, getProjectMessages } from './api-client.js';
import { isSensitiveFile } from './data-patterns.js';
import { createLogger } from './skills/structured-logger.js';
import { hashSecret } from './skills/secret-hasher.js';
import { requireConsent, hasConsent, grantConsent } from './skills/consent-gate.js';
import { createRationaleBuilder, SIGNAL_WEIGHTS } from './skills/rationale-logger.js';
import { probeDual, probeSingle } from './skills/dual-probe.js';
import { saveRun, buildRunSummary, listRuns, computeDelta } from './skills/scan-history.js';
import { buildActiveRegexSet } from './skills/pattern-catalog.js';
import { isUnlocked, getToken } from './skills/token-vault.js';

const logger = createLogger({ module: 'audit-engine' });

let aborted = false;
export function abortScan() { aborted = true; }

const LOVABLE_API = 'https://api.lovable.dev';
const NOV_2025 = new Date('2025-11-01');

// ---- Secret scanning using pattern-catalog ----

async function scanText(text, sourcePath) {
  const { patterns } = await buildActiveRegexSet();
  const findings = [];

  for (const { pattern, regex } of patterns) {
    if (pattern.kind !== 'secret' && pattern.kind !== 'pii') continue;
    const freshRegex = new RegExp(regex.source, regex.flags);
    let match;
    while ((match = freshRegex.exec(text)) !== null) {
      const raw = match[1] || match[0];
      if (!raw || raw.length < 6) continue;

      // Skip false positives
      if (pattern.falsePositiveHints?.some(h => raw.toLowerCase().includes(h.toLowerCase()))) continue;
      if (['your-api-key', 'placeholder', 'xxxx', 'example', 'dummy', 'fake', 'mock'].some(fp => raw.toLowerCase().includes(fp))) continue;

      const hashed = await hashSecret(raw);
      const lineNumber = text.slice(0, match.index).split('\n').length;

      findings.push({
        id: crypto.randomUUID(),
        patternId: pattern.id,
        kind: pattern.kind,
        label: pattern.label,
        severity: pattern.severity,
        hash: hashed.hash,
        masked: hashed.masked,
        prefix: hashed.prefix,
        source: sourcePath,
        lineNumber,
      });

      freshRegex.lastIndex = match.index + 1;
    }
  }
  return findings;
}

// ---- File path pattern check ----

async function checkSensitivePaths(files) {
  const { patterns } = await buildActiveRegexSet();
  const pathPatterns = patterns.filter(p => p.pattern.kind === 'path');
  const findings = [];

  for (const file of files) {
    const path = file.path || file.name || '';
    for (const { pattern, regex } of pathPatterns) {
      if (regex.test(path)) {
        findings.push({
          id: crypto.randomUUID(),
          patternId: pattern.id,
          kind: 'path',
          label: pattern.label,
          severity: pattern.severity,
          path,
          hash: null,
          masked: path,
        });
      }
    }
  }
  return findings;
}

// ---- Main scan ----

export async function runScan(config, onProgress, onResult) {
  aborted = false;

  // Consent gates
  await requireConsent('L0_legal');
  await requireConsent('L1_safe_mode');

  // Get owner token
  let ownerToken;
  if (await isUnlocked()) {
    ownerToken = await getToken('lovable:owner');
  }
  if (!ownerToken) {
    ownerToken = await getSessionToken();
  }
  if (!ownerToken) throw new Error('No session token. Please set up token vault or log in to Lovable.');

  const auditToken = config.auditToken || (await isUnlocked() ? await getToken('lovable:audit') : null);
  const scanDelay = config.scanDelay || 500;

  const projects = await listProjects();
  const filtered = config.projectFilter?.length
    ? projects.filter(p => config.projectFilter.includes(p.id))
    : projects;

  const runId = crypto.randomUUID();
  const startedAt = new Date().toISOString();

  const summary = {
    totalProjects: filtered.length, scannedProjects: 0,
    catastrophicCount: 0, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, cleanCount: 0,
    runId, startedAt,
  };

  const progress = {
    status: 'running', totalProjects: filtered.length,
    currentProjectIndex: 0, currentProject: '', findings: 0,
    percentage: 0, errors: [],
  };

  const rationales = [];

  for (let i = 0; i < filtered.length; i++) {
    if (aborted) { progress.status = 'paused'; onProgress({ ...progress }); break; }

    const project = filtered[i];
    progress.currentProjectIndex = i + 1;
    progress.currentProject = project.name || project.id;
    progress.percentage = Math.round(((i + 1) / filtered.length) * 100);
    onProgress({ ...progress });

    try {
      const result = await scanProject(project, config, ownerToken, auditToken, scanDelay);
      progress.findings += result.findings.length;
      onResult(result);
      rationales.push(result.rationale);
      summary.scannedProjects++;
      summary[result.rationale.severity + 'Count'] = (summary[result.rationale.severity + 'Count'] || 0) + 1;
      logger.info('project scanned', { projectId: project.id, severity: result.rationale.severity, score: result.rationale.scoreTotal });
    } catch (e) {
      progress.errors.push(`${project.name || project.id}: ${e.message}`);
      logger.error('project scan failed', e, { projectId: project.id });
      onProgress({ ...progress });
    }
  }

  summary.scanEndTime = new Date().toISOString();
  progress.status = aborted ? 'paused' : 'completed';
  onProgress({ ...progress });

  // Persist run history
  if (!aborted && rationales.length > 0) {
    try {
      const runSummary = buildRunSummary(runId, startedAt, rationales);
      await saveRun(runSummary);

      const runs = await listRuns(2);
      if (runs.length >= 2) {
        summary.delta = await computeDelta(runs[1].id, runs[0].id);
      }
    } catch (e) {
      logger.warn('could not save run history', undefined, { error: e.message });
    }
  }

  return summary;
}

async function scanProject(project, config, ownerToken, auditToken, scanDelay) {
  const start = Date.now();
  const builder = createRationaleBuilder(project.id);
  const findings = [];

  const result = {
    projectId: project.id,
    projectName: project.name || project.id,
    createdAt: project.created_at || project.createdAt || new Date().toISOString(),
    updatedAt: project.updated_at || project.updatedAt || new Date().toISOString(),
    scanTimestamp: new Date().toISOString(),
    scanDurationMs: 0,
    bolaFilesSignature: 'unknown',
    bolaChatSignature: 'unknown',
    supabaseDetected: false,
    supabaseUrl: null,
    findings,
    filesScanned: 0,
    chatMessagesScanned: 0,
  };

  const isPreNov2025 = new Date(result.createdAt) < NOV_2025;
  const thirtyDaysAgo = new Date(Date.now() - 30 * 86400 * 1000);
  const isActive = new Date(result.updatedAt) > thirtyDaysAgo;

  // ---- BOLA Probes ----
  const probeConfig = { ownerToken, auditToken: auditToken || ownerToken, throttleMs: scanDelay };

  for (const ep of PROBE_ENDPOINTS) {
    const endpoint = `${LOVABLE_API}${ep.path(project.id)}`;
    let probeResult;

    if (auditToken && auditToken !== ownerToken) {
      probeResult = await probeDual(endpoint, project.id, probeConfig);
    } else {
      probeResult = await probeSingle(endpoint, project.id, ownerToken);
    }

    if (ep.label === 'GitFilesResponse') {
      result.bolaFilesSignature = probeResult.signature;
      if (['vulnerable', 'owner_only'].includes(probeResult.signature)) {
        builder.add({ kind: 'bola_files', points: SIGNAL_WEIGHTS.bola_files, evidence: { endpoint } });
      }
    } else if (ep.label === 'GetProjectMessagesOutputBody') {
      result.bolaChatSignature = probeResult.signature;
      if (['vulnerable', 'owner_only'].includes(probeResult.signature)) {
        builder.add({ kind: 'bola_chat', points: SIGNAL_WEIGHTS.bola_chat, evidence: { endpoint } });
      }
    }
  }

  const ownerHasFiles = ['vulnerable', 'owner_only'].includes(result.bolaFilesSignature);
  const ownerHasChat  = ['vulnerable', 'owner_only'].includes(result.bolaChatSignature);

  // ---- File content scan ----
  if (config.includeFiles && ownerHasFiles) {
    const hasDeepConsent = await hasConsent('L2_deep_inspect', `scan_${result.projectId}`);
    if (config.deepInspect && !hasDeepConsent) {
      await grantConsent('L2_deep_inspect', `scan_${result.projectId}`);
    }

    if (config.deepInspect || hasDeepConsent) {
      try {
        const files = await getProjectFiles(project.id);
        if (Array.isArray(files)) {
          // Check sensitive paths
          const pathFindings = await checkSensitivePaths(files);
          for (const f of pathFindings) {
            findings.push(f);
            builder.add({ kind: 'sensitive_file', points: SIGNAL_WEIGHTS.sensitive_file, evidence: { path: f.path } });
          }

          // Scan content of sensitive files
          const toScan = files.filter(f => isSensitiveFile(f.path || f.name || '')).slice(0, 15);
          for (const file of toScan) {
            try {
              const content = await getFileContent(project.id, file.path || file.name);
              if (content) {
                const secretFindings = await scanText(content, file.path || file.name);
                for (const sf of secretFindings) {
                  findings.push(sf);
                  const kind = ['catastrophic', 'critical'].includes(sf.severity) ? 'secret_critical' : 'secret_high';
                  builder.add({ kind, points: SIGNAL_WEIGHTS[kind], evidence: { findingHash: sf.hash, path: sf.source } });

                  // Detect Supabase URL in content
                  const sbMatch = content.match(/https:\/\/([a-z0-9]{20})\.supabase\.co/);
                  if (sbMatch && !result.supabaseDetected) {
                    result.supabaseDetected = true;
                    result.supabaseUrl = sbMatch[0];
                  }
                }
              }
              result.filesScanned++;
            } catch { /* silent per-file failure */ }
          }
        }
      } catch (e) {
        logger.warn('file scan failed', undefined, { projectId: project.id, error: e.message });
      }
    }
  }

  // ---- Chat scan ----
  if (config.includeChat && ownerHasChat) {
    try {
      const messages = await getProjectMessages(project.id);
      if (Array.isArray(messages)) {
        for (const msg of messages.slice(0, 200)) {
          const content = msg.content || msg.text || msg.body || '';
          if (content.length > 10) {
            const chatFindings = await scanText(content, `chat:${msg.id || 'msg'}`);
            for (const cf of chatFindings) {
              findings.push(cf);
              builder.add({ kind: 'pii_in_chat', points: SIGNAL_WEIGHTS.pii_in_chat, evidence: { findingHash: cf.hash } });
            }
          }
          result.chatMessagesScanned++;
        }
      }
    } catch { /* silent */ }
  }

  // ---- Context modifiers ----
  if (isActive) {
    builder.add({ kind: 'active_project_bonus', points: SIGNAL_WEIGHTS.active_project_bonus, evidence: { lastEditedAt: result.updatedAt } });
  }
  if (isPreNov2025) {
    builder.add({ kind: 'pre_nov2025_penalty', points: SIGNAL_WEIGHTS.pre_nov2025_penalty, evidence: {} });
  }

  const rationale = builder.build();
  result.rationale = rationale;
  result.riskScore = rationale.scoreTotal;
  result.severity = rationale.severity;
  result.scanDurationMs = Date.now() - start;

  // Add top-level BOLA findings for UI display
  if (['vulnerable', 'owner_only'].includes(result.bolaFilesSignature)) {
    findings.unshift({
      id: crypto.randomUUID(), ruleId: 'bola_files', severity: 'critical',
      title: result.bolaFilesSignature === 'vulnerable' ? 'BOLA Confirmed: Source code accessible by any account' : 'Files accessible (owner access verified)',
      vector: 'bola_files', source: 'api.lovable.dev',
      description: 'Lovable API exposes project files without proper ownership enforcement.',
      evidence: `Probe signature: ${result.bolaFilesSignature} | Files accessible: ${result.filesScanned}`,
      recommendation: 'Contact Lovable support to apply retroactive ownership fix.',
    });
  }
  if (['vulnerable', 'owner_only'].includes(result.bolaChatSignature)) {
    findings.unshift({
      id: crypto.randomUUID(), ruleId: 'bola_chat', severity: 'critical',
      title: result.bolaChatSignature === 'vulnerable' ? 'BOLA Confirmed: Chat history accessible by any account' : 'Chat accessible (owner access verified)',
      vector: 'bola_chat', source: 'api.lovable.dev',
      description: 'AI conversation history exposed — may contain secrets, schemas, credentials.',
      evidence: `Probe signature: ${result.bolaChatSignature} | Messages scanned: ${result.chatMessagesScanned}`,
      recommendation: 'Delete sensitive messages. Contact Lovable support.',
    });
  }

  return result;
}

// ---- Demo mode ----
export function generateDemoData() {
  return [
    makeDemo('Admin Panel v2',     '2025-06-15', '2026-04-10', 'vulnerable', 'vulnerable', true,  'missing',    23, 312, 190, 'catastrophic'),
    makeDemo('E-commerce MVP',     '2025-09-01', '2026-04-10', 'vulnerable', 'vulnerable', true,  'missing',    42, 520, 160, 'catastrophic'),
    makeDemo('Landing Page',       '2025-06-15', '2025-12-20', 'owner_only', 'patched',    false, 'not_tested', 12,   0,  80, 'critical'),
    makeDemo('CRM Dashboard',      '2025-06-15', '2026-04-10', 'patched',    'patched',    true,  'enabled',    30,  89,  30, 'medium'),
    makeDemo('Blog Pessoal',       '2026-03-01', '2026-04-10', 'patched',    'patched',    false, 'not_tested', 15,  45,   0, 'clean'),
  ];
}

function makeDemo(name, created, updated, bFiles, bChat, hasSupabase, _rls, files, msgs, score, severity) {
  const now = new Date().toISOString();
  return {
    projectId: crypto.randomUUID(), projectName: name,
    createdAt: created, updatedAt: updated,
    scanTimestamp: now, scanDurationMs: Math.random() * 3000 + 500,
    bolaFilesSignature: bFiles, bolaChatSignature: bChat,
    supabaseDetected: hasSupabase, supabaseUrl: hasSupabase ? 'https://abcdefghijklmnopqrst.supabase.co' : null,
    filesScanned: files, chatMessagesScanned: msgs,
    riskScore: score, severity,
    rationale: { projectId: 'demo', scoreTotal: score, severity, contributions: [], schemaVersion: '1.0', computedAt: now },
    findings: score > 0 ? [{
      id: crypto.randomUUID(), ruleId: 'bola_files', severity: 'critical',
      title: 'Demo: BOLA vulnerability detected', vector: 'bola_files',
      source: 'api.lovable.dev', description: 'Demo finding — run a real scan to see actual results.',
      evidence: `score=${score}`, recommendation: 'Run scan on real projects.',
    }] : [],
  };
}
