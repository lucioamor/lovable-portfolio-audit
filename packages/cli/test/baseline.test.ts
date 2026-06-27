// ============================================================
// A3 — Baseline + delta (H4)
// ============================================================
import { describe, it, expect } from 'vitest';
import {
  fingerprintFinding,
  computeDelta,
  nextBaseline,
  emptyBaseline,
} from '../src/engines/baseline';
import type { Finding, ProjectScanResult } from '../src/types';

let seq = 0;
function finding(ruleId: string, partial: Partial<Finding> = {}): Finding {
  seq += 1;
  return {
    id: `f-${seq}`, ruleId, vector: 'hardcoded_secret', severity: 'high',
    confidence: 'confirmed', lovableLevel: 'L1', title: `${ruleId} title`,
    description: '', evidence: `ev-${ruleId}`, recommendation: '', aiPrompt: '',
    ...partial,
  };
}

function project(id: string, findings: Finding[]): ProjectScanResult {
  return {
    projectId: id, projectName: id, createdAt: '', updatedAt: '',
    isPreNov2025: false, scanTimestamp: '', riskScore: 0, severity: 'high',
    lovableLevel: 'L1', findings, rationale: [], filesScanned: 0,
    chatMessagesScanned: 0, scanDurationMs: 0,
    bolaFilesProbe: { endpoint: '', status: 200, signature: 'owner_only' },
    bolaChatProbe: { endpoint: '', status: 200, signature: 'owner_only' },
    supabaseDetected: false, sourceMapsExposed: false,
  };
}

const T0 = '2026-06-01T00:00:00.000Z';
const T1 = '2026-06-26T00:00:00.000Z';

describe('fingerprintFinding', () => {
  it('is stable for the same finding', () => {
    const f = finding('APP-001', { hash: 'abc' });
    expect(fingerprintFinding('p1', f)).toBe(fingerprintFinding('p1', f));
  });
  it('differs across projects and rules', () => {
    const f = finding('APP-001', { hash: 'abc' });
    expect(fingerprintFinding('p1', f)).not.toBe(fingerprintFinding('p2', f));
  });
});

describe('computeDelta', () => {
  it('first run against null baseline → all new', () => {
    const results = [project('p1', [finding('A'), finding('B')])];
    const d = computeDelta(results, null, T1);
    expect(d.newCount).toBe(2);
    expect(d.resolvedCount).toBe(0);
    expect(d.unchangedCount).toBe(0);
  });

  it('re-run with no changes → delta zero (all unchanged)', () => {
    const r0 = [project('p1', [finding('A'), finding('B')])];
    const base = nextBaseline(r0, null, T0);
    // identical findings the second time
    seq = 0; // reset so evidence/ids regenerate identically
    const r1 = [project('p1', [finding('A'), finding('B')])];
    const d = computeDelta(r1, base, T1);
    expect(d.newCount).toBe(0);
    expect(d.resolvedCount).toBe(0);
    expect(d.unchangedCount).toBe(2);
  });

  it('new finding → new; disappeared finding → resolved', () => {
    const r0 = [project('p1', [finding('A'), finding('B')])];
    const base = nextBaseline(r0, null, T0);
    seq = 0;
    // A persists, B gone, C appears
    const r1 = [project('p1', [finding('A'), finding('C')])];
    const d = computeDelta(r1, base, T1);
    const states = Object.fromEntries(d.items.map(i => [i.ruleId, i.drift_state]));
    expect(states['A']).toBe('unchanged');
    expect(states['C']).toBe('new');
    expect(states['B']).toBe('resolved');
    expect(d.newCount).toBe(1);
    expect(d.resolvedCount).toBe(1);
    expect(d.unchangedCount).toBe(1);
  });
});

describe('nextBaseline', () => {
  it('preserves first_seen_at for survivors, drops resolved', () => {
    const r0 = [project('p1', [finding('A'), finding('B')])];
    const base = nextBaseline(r0, null, T0);
    seq = 0;
    const r1 = [project('p1', [finding('A')])]; // B resolved
    const updated = nextBaseline(r1, base, T1);
    const entries = Object.values(updated.findings);
    expect(entries).toHaveLength(1);
    expect(entries[0].ruleId).toBe('A');
    expect(entries[0].first_seen_at).toBe(T0); // preserved
    expect(entries[0].last_seen_at).toBe(T1);  // bumped
  });

  it('emptyBaseline has the right schema', () => {
    expect(emptyBaseline(T0).schema).toBe('nxlv-baseline/v1');
  });
});
