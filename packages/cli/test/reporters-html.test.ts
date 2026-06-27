// ============================================================
// E1 — toHTML reporter (self-contained, escaped, no network)
// ============================================================
import { describe, it, expect } from 'vitest';
import { toHTML, escapeHtml } from '../src/reporters/index';
import type { Finding, ProjectScanResult, ScanSummary } from '../src/types';

function finding(partial: Partial<Finding> = {}): Finding {
  return {
    id: 'f-1', ruleId: 'LOV-001', vector: 'bola_files', severity: 'critical',
    confidence: 'confirmed', lovableLevel: 'L1', title: 'BOLA: Files Endpoint Exposed',
    description: '', evidence: 'GET /projects/abc/git/files -> HTTP 200',
    recommendation: 'Enforce ownership checks on the files endpoint.', aiPrompt: 'fix it',
    ...partial,
  };
}

function project(partial: Partial<ProjectScanResult> = {}): ProjectScanResult {
  return {
    projectId: 'proj-abc', projectName: 'My Production App', createdAt: '', updatedAt: '',
    isPreNov2025: true, scanTimestamp: '', riskScore: 90, severity: 'critical',
    lovableLevel: 'L1', findings: [finding()], rationale: [
      { ruleId: 'LOV-001', vector: 'bola_files', points: 60, reason: 'Files endpoint returned HTTP 200' },
    ],
    filesScanned: 0, chatMessagesScanned: 0, scanDurationMs: 0,
    bolaFilesProbe: { endpoint: '', status: 200, signature: 'vulnerable' },
    bolaChatProbe: { endpoint: '', status: 403, signature: 'patched' },
    supabaseDetected: false, sourceMapsExposed: false,
    ...partial,
  };
}

const summary: ScanSummary = {
  totalProjects: 1, scannedProjects: 1, catastrophicCount: 0, criticalCount: 1,
  highCount: 0, mediumCount: 0, lowCount: 0, cleanCount: 0, preNov2025Count: 1,
  bolaVulnerableCount: 1, topFindings: [], scanStartTime: '', scanEndTime: '',
  totalDurationMs: 0,
};

describe('escapeHtml', () => {
  it('escapes all HTML-significant characters', () => {
    expect(escapeHtml(`<script>"&'`)).toBe('&lt;script&gt;&quot;&amp;&#39;');
  });
  it('coerces nullish to empty string', () => {
    expect(escapeHtml(undefined)).toBe('');
    expect(escapeHtml(null)).toBe('');
  });
});

describe('toHTML', () => {
  const html = toHTML([project()], summary, { scanTimestamp: '2026-06-26T00:00:00.000Z' });

  it('contains the project name', () => {
    expect(html).toContain('My Production App');
  });

  it('contains a finding ruleId', () => {
    expect(html).toContain('LOV-001');
  });

  it('includes the reproducible rationale', () => {
    expect(html).toContain('Score rationale');
    expect(html).toContain('Files endpoint returned HTTP 200');
  });

  it('has NO external script references (no network deps)', () => {
    expect(html).not.toMatch(/<script\s+src=/i);
    expect(html).not.toMatch(/<link\b[^>]*href=/i);
    expect(html).not.toMatch(/https?:\/\/[^"']*\.(js|css)/i);
  });

  it('escapes evidence so no XSS leaks through', () => {
    const evil = finding({ evidence: '<img src=x onerror=alert(1)>', title: '<b>pwn</b>' });
    const out = toHTML([project({ findings: [evil] })], summary, { scanTimestamp: 'T' });
    expect(out).not.toContain('<img src=x onerror=alert(1)>');
    expect(out).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(out).not.toContain('<b>pwn</b>');
  });

  it('is a single self-contained document', () => {
    expect(html.trimStart().startsWith('<!DOCTYPE html>')).toBe(true);
    expect(html).toContain('</html>');
  });

  it('uses the passed timestamp deterministically', () => {
    const a = toHTML([project()], summary, { scanTimestamp: '2026-06-26T00:00:00.000Z' });
    const b = toHTML([project()], summary, { scanTimestamp: '2026-06-26T00:00:00.000Z' });
    expect(a).toBe(b);
    expect(a).toContain('2026-06-26T00:00:00.000Z');
  });
});
