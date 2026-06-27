// ============================================================
// E2 — report + fix-prompt: saved-report loader & extractors
// ============================================================
import { describe, it, expect } from 'vitest';
import {
  parseSavedReport,
  collectFixPrompts,
  formatFixPrompts,
} from '../src/engines/saved-report';

const VALID = JSON.stringify({
  schema: 'nxlv-shield/v1',
  scanTimestamp: '2026-06-26T00:00:00.000Z',
  summary: { totalProjects: 1, scannedProjects: 1 },
  results: [
    {
      projectId: 'p1', projectName: 'Alpha', severity: 'critical', riskScore: 90,
      findings: [
        { ruleId: 'LOV-001', title: 'BOLA files', evidence: 'm', aiPrompt: 'Fix BOLA on files.' },
        { ruleId: 'DB-012', title: 'service role', evidence: 'm', aiPrompt: 'Rotate the key.' },
        { ruleId: 'X-1', title: 'no prompt', evidence: 'm', aiPrompt: '' },
      ],
    },
    {
      projectId: 'p2', projectName: 'Beta', severity: 'low', riskScore: 5,
      findings: [
        { ruleId: 'H-1', title: 'header', evidence: 'm', aiPrompt: 'Add CSP.' },
      ],
    },
  ],
});

describe('parseSavedReport', () => {
  it('parses a valid nxlv-shield/v1 report', () => {
    const r = parseSavedReport(VALID);
    expect(r.schema).toBe('nxlv-shield/v1');
    expect(r.results).toHaveLength(2);
  });

  it('throws on invalid JSON', () => {
    expect(() => parseSavedReport('{not json')).toThrow(/not valid JSON/);
  });

  it('throws on a wrong/missing schema', () => {
    expect(() => parseSavedReport(JSON.stringify({ results: [], summary: {} })))
      .toThrow(/nxlv-shield/);
  });

  it('throws when results is not an array', () => {
    expect(() => parseSavedReport(JSON.stringify({ schema: 'nxlv-shield/v1', summary: {}, results: 'x' })))
      .toThrow(/results/);
  });
});

describe('collectFixPrompts', () => {
  it('collects only findings with a non-empty aiPrompt', () => {
    const blocks = collectFixPrompts(parseSavedReport(VALID));
    expect(blocks.map(b => b.ruleId)).toEqual(['LOV-001', 'DB-012', 'H-1']);
    expect(blocks.find(b => b.ruleId === 'X-1')).toBeUndefined();
  });

  it('carries project + finding identity', () => {
    const blocks = collectFixPrompts(parseSavedReport(VALID));
    expect(blocks[0]).toMatchObject({ projectName: 'Alpha', projectId: 'p1', ruleId: 'LOV-001' });
  });
});

describe('formatFixPrompts', () => {
  it('renders grouped, fenced, copy-pasteable blocks', () => {
    const text = formatFixPrompts(collectFixPrompts(parseSavedReport(VALID)));
    expect(text).toContain('# Alpha (p1)');
    expect(text).toContain('## [LOV-001] BOLA files');
    expect(text).toContain('Fix BOLA on files.');
    expect(text).toContain('# Beta (p2)');
    // fenced code blocks present
    expect(text.match(/```/g)?.length).toBe(6); // 3 prompts × open+close
  });

  it('handles a report with no prompts gracefully', () => {
    const empty = parseSavedReport(JSON.stringify({
      schema: 'nxlv-shield/v1', summary: {}, results: [],
    }));
    expect(formatFixPrompts(collectFixPrompts(empty))).toMatch(/No AI fix prompts/);
  });
});
