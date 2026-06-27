// SKILL-03: scan-history
// Persiste runs sequenciais e computa deltas entre eles.
// Habilita KPIs evolutivos: "este projeto piorou desde ontem?"

import { createLogger } from './structured-logger.js';

const logger = createLogger({ module: 'scan-history' });
const STORAGE_KEY = 'lpa:runs';
const MAX_RUNS_DEFAULT = 30;

async function readStorage() {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  return result[STORAGE_KEY] ?? [];
}

async function writeStorage(runs) {
  await chrome.storage.local.set({ [STORAGE_KEY]: runs });
}

export async function saveRun(summary) {
  const existing = await readStorage();
  const next = [summary, ...existing].slice(0, MAX_RUNS_DEFAULT);
  await writeStorage(next);
  logger.info('run saved', { runId: summary.id, projectCount: summary.projectCount });
}

export async function listRuns(limit = 10) {
  const all = await readStorage();
  return all.slice(0, limit);
}

export async function getRun(id) {
  const all = await readStorage();
  return all.find(r => r.id === id) ?? null;
}

export async function computeDelta(previousRunId, currentRunId) {
  const [prev, curr] = await Promise.all([getRun(previousRunId), getRun(currentRunId)]);
  if (!prev || !curr) {
    logger.warn('run not found for delta', { previousRunId, currentRunId });
    return [];
  }

  const allProjectIds = new Set([
    ...Object.keys(prev.byProject),
    ...Object.keys(curr.byProject),
  ]);

  const deltas = [];
  for (const projectId of allProjectIds) {
    const p = prev.byProject[projectId];
    const c = curr.byProject[projectId];
    if (!p || !c) continue;

    const prevHashes = new Set(p.findingHashes ?? []);
    const currHashes = new Set(c.findingHashes ?? []);
    const newFindings = [...currHashes].filter(h => !prevHashes.has(h));
    const resolvedFindings = [...prevHashes].filter(h => !currHashes.has(h));

    deltas.push({
      projectId,
      scoreDelta: c.score - p.score,
      severityTransition: `${p.severity}→${c.severity}`,
      newFindings,
      resolvedFindings,
    });
  }

  return deltas.sort((a, b) => b.scoreDelta - a.scoreDelta);
}

export async function pruneRuns(keepLast = MAX_RUNS_DEFAULT) {
  const all = await readStorage();
  const kept = all.slice(0, keepLast);
  await writeStorage(kept);
  const removed = all.length - kept.length;
  if (removed > 0) logger.info('runs pruned', { removed });
  return removed;
}

export function buildRunSummary(runId, startedAt, rationales) {
  const severityCounts = { catastrophic: 0, critical: 0, high: 0, medium: 0, low: 0, clean: 0 };
  const byProject = {};
  let findingCount = 0;
  let scoreSum = 0;

  for (const r of rationales) {
    severityCounts[r.severity] = (severityCounts[r.severity] ?? 0) + 1;
    scoreSum += r.scoreTotal;
    findingCount += r.contributions.length;
    byProject[r.projectId] = {
      score: r.scoreTotal,
      severity: r.severity,
      findingHashes: r.contributions
        .map(c => c.evidence?.findingHash)
        .filter(Boolean),
    };
  }

  return {
    id: runId,
    startedAt,
    endedAt: new Date().toISOString(),
    projectCount: rationales.length,
    findingCount,
    scoreAverage: rationales.length ? Math.round(scoreSum / rationales.length) : 0,
    severityCounts,
    byProject,
  };
}
