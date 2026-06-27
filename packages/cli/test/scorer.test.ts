// ============================================================
// SKILL-10 — Scorer determinism suite (C9)
// ============================================================
// Guards the invariant that calculateRiskScore is pure and that the
// rationale breakdown is reproducible. Mirrors the extension scorer tests.
// ============================================================

import { describe, it, expect } from 'vitest';
import {
  calculateRiskScore,
  getSeverityFromScore,
  MAX_SCORE,
} from '../src/engines/scorer';
import type { Finding, ScanVector, Severity } from '../src/types';

let seq = 0;
function makeFinding(severity: Severity, vector: ScanVector): Finding {
  seq += 1;
  return {
    id: `f-${seq}`,
    ruleId: `RULE-${seq}`,
    vector,
    severity,
    confidence: 'confirmed',
    lovableLevel: 'L1',
    title: `finding ${seq}`,
    description: '',
    evidence: 'masked',
    recommendation: '',
    aiPrompt: '',
  };
}

const sumPoints = (rationale: { points: number }[]) =>
  rationale.reduce((acc, r) => acc + r.points, 0);

describe('calculateRiskScore — determinism & weights', () => {
  it('empty findings with no context → score 0, empty rationale', () => {
    const { score, rationale } = calculateRiskScore([], false, false, false, false);
    expect(score).toBe(0);
    expect(rationale).toHaveLength(0);
  });

  it('rationale points sum equals score when under the cap', () => {
    const findings = [makeFinding('high', 'security_headers')]; // +20
    const { score, rationale } = calculateRiskScore(findings, false, false, false, false);
    expect(score).toBe(20);
    expect(sumPoints(rationale)).toBe(score);
  });

  it('unknown / non-special vector does not inflate beyond its severity weight', () => {
    const findings = [makeFinding('low', 'xss_sink')]; // low = +5, no special escalation
    const { score, rationale } = calculateRiskScore(findings, false, false, false, false);
    expect(score).toBe(5);
    expect(rationale).toHaveLength(1);
    expect(rationale[0].points).toBe(5);
  });

  it('info-severity findings contribute zero', () => {
    const findings = [makeFinding('info', 'xss_sink')];
    const { score, rationale } = calculateRiskScore(findings, false, false, false, false);
    expect(score).toBe(0);
    expect(rationale).toHaveLength(0);
  });

  it('active project adds exactly +10', () => {
    const { score, rationale } = calculateRiskScore([], true, false, false, false);
    expect(score).toBe(10);
    const ctx = rationale.find(r => r.ruleId === 'CTX-001');
    expect(ctx?.points).toBe(10);
  });

  it('pre-Nov-2025 adds exactly +5', () => {
    const { score, rationale } = calculateRiskScore([], false, true, false, false);
    expect(score).toBe(5);
    expect(rationale.find(r => r.ruleId === 'LOV-006')?.points).toBe(5);
  });

  it('caps the returned score at 100', () => {
    // bola_files (60) + bola_chat (60) = 120 raw → clamped to 100
    const { score, rationale } = calculateRiskScore([], false, false, true, true);
    expect(score).toBe(MAX_SCORE);
    expect(sumPoints(rationale)).toBeGreaterThan(MAX_SCORE); // raw breakdown preserved
  });

  it('service_role exposure escalates to the +50 vector weight', () => {
    const findings = [makeFinding('catastrophic', 'service_role_exposed')];
    const { rationale } = calculateRiskScore(findings, false, false, false, false);
    expect(rationale[0].points).toBe(50);
  });

  it('is deterministic across 100 runs', () => {
    const findings = [
      makeFinding('critical', 'hardcoded_secret'),
      makeFinding('high', 'security_headers'),
      makeFinding('medium', 'pii_in_code'),
    ];
    const baseline = calculateRiskScore(findings, true, true, true, false).score;
    for (let i = 0; i < 100; i++) {
      expect(calculateRiskScore(findings, true, true, true, false).score).toBe(baseline);
    }
  });
});

describe('getSeverityFromScore — boundaries', () => {
  it('clean at 0', () => expect(getSeverityFromScore(0)).toBe('clean'));
  it('low at 1 and 19', () => {
    expect(getSeverityFromScore(1)).toBe('low');
    expect(getSeverityFromScore(19)).toBe('low');
  });
  it('medium at boundary 20 and 49', () => {
    expect(getSeverityFromScore(20)).toBe('medium');
    expect(getSeverityFromScore(49)).toBe('medium');
  });
  it('high at boundary 50 and 79', () => {
    expect(getSeverityFromScore(50)).toBe('high');
    expect(getSeverityFromScore(79)).toBe('high');
  });
  it('critical at boundary 80 and 99', () => {
    expect(getSeverityFromScore(80)).toBe('critical');
    expect(getSeverityFromScore(99)).toBe('critical');
  });
  it('catastrophic only at the 100 cap', () => {
    expect(getSeverityFromScore(100)).toBe('catastrophic');
  });
});
