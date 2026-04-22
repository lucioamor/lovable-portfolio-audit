import { describe, it, expect } from 'vitest';
import { computeRiskScore, getSeverity } from '../extension/lib/health-scorer.js';

describe('computeRiskScore', () => {
  it('caps at 100', () => {
    const result = {
      updatedAt: new Date(Date.now() - 40 * 86400000).toISOString(), // >30d old
      findings: [
        { severity: 'critical' }, { severity: 'critical' },
        { severity: 'critical' }, { severity: 'critical' }
      ]
    };
    expect(computeRiskScore(result)).toBe(100);
  });

  it('adds 60 for GitFilesResponse vulnerable', () => {
    const result = {
      updatedAt: new Date(Date.now() - 40 * 86400000).toISOString(), // >30d old
      probeResults: [{ label: 'GitFilesResponse', signature: 'vulnerable' }],
      findings: []
    };
    expect(computeRiskScore(result)).toBe(60);
  });

  it('adds 60 for GetProjectMessagesOutputBody vulnerable', () => {
    const result = {
      updatedAt: new Date(Date.now() - 40 * 86400000).toISOString(), // >30d old
      probeResults: [{ label: 'GetProjectMessagesOutputBody', signature: 'vulnerable' }],
      findings: []
    };
    expect(computeRiskScore(result)).toBe(60);
  });

  it('adds 30 for GetProject vulnerable', () => {
    const result = {
      updatedAt: new Date(Date.now() - 40 * 86400000).toISOString(), // >30d old
      probeResults: [{ label: 'GetProject', signature: 'vulnerable' }],
      findings: []
    };
    expect(computeRiskScore(result)).toBe(30);
  });

  it('adds 10 temporal bonus if updated recently and not all patched', () => {
    const result = {
      updatedAt: new Date().toISOString(), // Just now
      probeResults: [{ label: 'GetProject', signature: 'inconclusive' }],
      findings: []
    };
    expect(computeRiskScore(result)).toBe(10);
  });

  it('zeroes temporal bonus if all patched', () => {
    const result = {
      updatedAt: new Date().toISOString(), // Just now
      probeResults: [{ label: 'GetProject', signature: 'patched' }],
      findings: []
    };
    expect(computeRiskScore(result)).toBe(0);
  });

  it('sums findings correctly', () => {
    const result = {
      updatedAt: new Date(Date.now() - 40 * 86400000).toISOString(), // >30d old
      findings: [
        { severity: 'critical' }, // 30
        { severity: 'high' },     // 20
        { severity: 'medium' }    // 10
      ]
    };
    expect(computeRiskScore(result)).toBe(60);
  });
});

describe('getSeverity', () => {
  it('returns critical for >= 80', () => {
    expect(getSeverity(80)).toBe('critical');
    expect(getSeverity(100)).toBe('critical');
  });

  it('returns high for 50-79', () => {
    expect(getSeverity(50)).toBe('high');
    expect(getSeverity(79)).toBe('high');
  });

  it('returns medium for 20-49', () => {
    expect(getSeverity(20)).toBe('medium');
    expect(getSeverity(49)).toBe('medium');
  });

  it('returns low for 1-19', () => {
    expect(getSeverity(1)).toBe('low');
    expect(getSeverity(19)).toBe('low');
  });

  it('returns clean for 0', () => {
    expect(getSeverity(0)).toBe('clean');
  });
});
