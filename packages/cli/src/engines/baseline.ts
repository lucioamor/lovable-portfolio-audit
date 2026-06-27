// ============================================================
// @nxlv/shield — Baseline + Delta (H4 parity for the CLI)
// ============================================================
// Persists findings to .nxlv-baseline.json so re-runs can report drift:
//   new       — fingerprint not in the baseline
//   unchanged — fingerprint present in both
//   resolved  — fingerprint in the baseline but gone now
//
// Dedup is by SHA-256 fingerprint (secret hash when available, else a stable
// hash of ruleId+vector+location+masked-evidence). No raw secret is stored.
// ============================================================

import { createHash } from 'crypto';
import type { Finding, ProjectScanResult, Severity } from '../types.js';

export const DEFAULT_BASELINE_PATH = '.nxlv-baseline.json';
export type DriftState = 'new' | 'unchanged' | 'resolved';

export interface BaselineEntry {
  fingerprint: string;
  projectId: string;
  ruleId: string;
  severity: Severity;
  title: string;
  first_seen_at: string;
  last_seen_at: string;
}

export interface BaselineFile {
  schema: 'nxlv-baseline/v1';
  createdAt: string;
  updatedAt: string;
  findings: Record<string, BaselineEntry>;
}

export interface DeltaItem extends BaselineEntry {
  drift_state: DriftState;
}

export interface DeltaSummary {
  newCount: number;
  resolvedCount: number;
  unchangedCount: number;
  items: DeltaItem[];
}

/** Stable per-finding identity. Uses the secret hash when present (already
 *  SHA-256 of the raw value), otherwise a hash of non-sensitive metadata. */
export function fingerprintFinding(projectId: string, f: Finding): string {
  const basis = f.hash
    ? `${projectId}|${f.ruleId}|${f.vector}|hash:${f.hash}`
    : `${projectId}|${f.ruleId}|${f.vector}|${f.file || ''}|${f.line ?? ''}|${f.evidence}`;
  return createHash('sha256').update(basis).digest('hex');
}

export function emptyBaseline(now: string): BaselineFile {
  return { schema: 'nxlv-baseline/v1', createdAt: now, updatedAt: now, findings: {} };
}

/** Flatten current scan results into fingerprinted entries (deduped). */
function currentEntries(results: ProjectScanResult[], now: string): Map<string, BaselineEntry> {
  const map = new Map<string, BaselineEntry>();
  for (const r of results) {
    for (const f of r.findings) {
      const fingerprint = fingerprintFinding(r.projectId, f);
      if (map.has(fingerprint)) continue; // dedupe
      map.set(fingerprint, {
        fingerprint,
        projectId: r.projectId,
        ruleId: f.ruleId,
        severity: f.severity,
        title: f.title,
        first_seen_at: now,
        last_seen_at: now,
      });
    }
  }
  return map;
}

/** Compare current results against a baseline (does not mutate it). */
export function computeDelta(
  results: ProjectScanResult[],
  baseline: BaselineFile | null,
  now: string,
): DeltaSummary {
  const current = currentEntries(results, now);
  const base = baseline?.findings ?? {};
  const items: DeltaItem[] = [];

  for (const [fp, entry] of current) {
    const prior = base[fp];
    if (prior) {
      items.push({ ...entry, first_seen_at: prior.first_seen_at, last_seen_at: now, drift_state: 'unchanged' });
    } else {
      items.push({ ...entry, drift_state: 'new' });
    }
  }
  for (const [fp, prior] of Object.entries(base)) {
    if (!current.has(fp)) {
      items.push({ ...prior, drift_state: 'resolved' });
    }
  }

  return {
    newCount: items.filter(i => i.drift_state === 'new').length,
    resolvedCount: items.filter(i => i.drift_state === 'resolved').length,
    unchangedCount: items.filter(i => i.drift_state === 'unchanged').length,
    items,
  };
}

/** Produce the next baseline: keep first_seen_at for survivors, bump
 *  last_seen_at, add new findings, drop resolved ones. */
export function nextBaseline(
  results: ProjectScanResult[],
  baseline: BaselineFile | null,
  now: string,
): BaselineFile {
  const current = currentEntries(results, now);
  const base = baseline?.findings ?? {};
  const findings: Record<string, BaselineEntry> = {};

  for (const [fp, entry] of current) {
    const prior = base[fp];
    findings[fp] = {
      ...entry,
      first_seen_at: prior?.first_seen_at ?? now,
      last_seen_at: now,
    };
  }

  return {
    schema: 'nxlv-baseline/v1',
    createdAt: baseline?.createdAt ?? now,
    updatedAt: now,
    findings,
  };
}
