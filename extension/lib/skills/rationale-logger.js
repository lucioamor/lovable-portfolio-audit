// SKILL-06: rationale-logger
// Score vira ProjectRationale com breakdown por signal + evidência.
// Requisito para auditoria e CI determinístico.

import { createLogger } from './structured-logger.js';

const logger = createLogger({ module: 'rationale-logger' });

export const SIGNAL_WEIGHTS = Object.freeze({
  bola_files:           60,
  bola_chat:            60,
  secret_critical:      30,
  secret_high:          20,
  pii_in_code:          20,
  pii_in_chat:          20,
  rls_missing:          30,
  sensitive_file:       15,
  storage_exposed:      25,
  source_map_exposed:   10,
  active_project_bonus: 10,
  pre_nov2025_penalty:   5,
  service_role_exposed: 50,
});

export const SEVERITY_BANDS = Object.freeze({
  catastrophic: 120,
  critical:      80,
  high:          50,
  medium:        20,
  low:            1,
});

function computeSeverity(total) {
  if (total >= SEVERITY_BANDS.catastrophic) return 'catastrophic';
  if (total >= SEVERITY_BANDS.critical)     return 'critical';
  if (total >= SEVERITY_BANDS.high)         return 'high';
  if (total >= SEVERITY_BANDS.medium)       return 'medium';
  if (total >= SEVERITY_BANDS.low)          return 'low';
  return 'clean';
}

export function createRationaleBuilder(projectId) {
  const contributions = [];

  return {
    add(c) {
      const expected = SIGNAL_WEIGHTS[c.kind];
      if (expected !== undefined && c.points !== expected) {
        logger.warn('points mismatch', { kind: c.kind, got: c.points, expected });
      }
      contributions.push(Object.freeze({
        ...c,
        evidence: Object.freeze({ ...c.evidence }),
      }));
      return this;
    },
    build() {
      const scoreTotal = contributions.reduce((s, c) => s + c.points, 0);
      return Object.freeze({
        projectId,
        scoreTotal,
        severity: computeSeverity(scoreTotal),
        contributions: Object.freeze(contributions.slice()),
        schemaVersion: '1.0',
        computedAt: new Date().toISOString(),
      });
    },
  };
}

export function verifyRationale(r) {
  const recomputed = r.contributions.reduce((s, c) => s + c.points, 0);
  return recomputed === r.scoreTotal && computeSeverity(recomputed) === r.severity;
}

export function formatRationaleAsText(r) {
  const lines = r.contributions.map(c => {
    const evidenceStr = [
      c.evidence.endpoint && `@ ${c.evidence.endpoint}`,
      c.evidence.path && `file:${c.evidence.path}`,
      c.evidence.table && `table=${c.evidence.table}`,
      c.evidence.findingHash && `hash:${c.evidence.findingHash.slice(0, 8)}`,
    ].filter(Boolean).join(' ');
    return `  +${c.points.toString().padStart(3)}  ${c.kind} ${evidenceStr}`;
  });
  return [
    `Project: ${r.projectId}`,
    `Score:   ${r.scoreTotal} (${r.severity.toUpperCase()})`,
    `Signals (${r.contributions.length}):`,
    ...lines,
  ].join('\n');
}
