// ============================================================
// P11 — Diff-alert webhook payload builder (pure)
// ============================================================
import { describe, it, expect } from 'vitest';
import { buildWebhookPayload, WEBHOOK_SCHEMA } from '../src/engines/webhook';
import type { DeltaSummary, DeltaItem } from '../src/engines/baseline';

function item(partial: Partial<DeltaItem>): DeltaItem {
  return {
    fingerprint: 'fp', projectId: 'p1', ruleId: 'R-1', severity: 'high',
    title: 'finding', first_seen_at: 'T0', last_seen_at: 'T1', drift_state: 'new',
    ...partial,
  };
}

const delta: DeltaSummary = {
  newCount: 2, resolvedCount: 1, unchangedCount: 1,
  items: [
    item({ ruleId: 'LOV-001', title: 'BOLA files', severity: 'critical', projectId: 'pA', drift_state: 'new' }),
    item({ ruleId: 'DB-012', title: 'service role', severity: 'catastrophic', projectId: 'pB', drift_state: 'new' }),
    item({ ruleId: 'H-1', title: 'header', severity: 'low', projectId: 'pA', drift_state: 'resolved' }),
    item({ ruleId: 'U-1', title: 'unchanged one', severity: 'medium', projectId: 'pA', drift_state: 'unchanged' }),
  ],
};

describe('buildWebhookPayload', () => {
  const payload = buildWebhookPayload(delta, '2026-06-26T00:00:00.000Z');

  it('uses the stable schema + supplied timestamp', () => {
    expect(payload.schema).toBe(WEBHOOK_SCHEMA);
    expect(payload.generatedAt).toBe('2026-06-26T00:00:00.000Z');
  });

  it('carries the drift counts', () => {
    expect(payload.counts).toEqual({ new: 2, resolved: 1, unchanged: 1 });
  });

  it('lists new + resolved finding identifiers (ruleId/title/severity/project)', () => {
    expect(payload.new.map(f => f.ruleId)).toEqual(['LOV-001', 'DB-012']);
    expect(payload.resolved.map(f => f.ruleId)).toEqual(['H-1']);
    expect(payload.new[0]).toEqual({
      ruleId: 'LOV-001', title: 'BOLA files', severity: 'critical', projectId: 'pA',
    });
  });

  it('omits unchanged findings from new/resolved lists', () => {
    const all = [...payload.new, ...payload.resolved].map(f => f.ruleId);
    expect(all).not.toContain('U-1');
  });

  it('excludes every secret-bearing / raw-evidence field', () => {
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toMatch(/fingerprint/);
    expect(serialized).not.toMatch(/evidence/i);
    expect(serialized).not.toMatch(/token|secret|hash|authorization|bearer/i);
    // only the whitelisted keys appear on a finding
    for (const f of [...payload.new, ...payload.resolved]) {
      expect(Object.keys(f).sort()).toEqual(['projectId', 'ruleId', 'severity', 'title']);
    }
  });
});
