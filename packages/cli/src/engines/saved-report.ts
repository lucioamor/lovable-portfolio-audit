// ============================================================
// @nxlv/audit — Saved-report loader (E2: report + fix-prompt)
// ============================================================
// Parses a previously written `nxlv-audit/v1` JSON report (the shape produced
// by toJSON) so reports can be regenerated and AI fix prompts extracted WITHOUT
// re-scanning. Pure functions; the CLI layer handles file IO and exit codes.
// ============================================================

import type { ProjectScanResult, ScanSummary } from '../types.js';

export interface SavedReport {
  schema: string;
  scanTimestamp?: string;
  summary: ScanSummary;
  results: ProjectScanResult[];
  [k: string]: unknown;
}

/**
 * Parse + validate a saved JSON report. Throws a clean Error with a
 * human-readable message on malformed/unexpected input.
 */
export function parseSavedReport(raw: string): SavedReport {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new Error('Report file is not valid JSON.');
  }
  if (typeof data !== 'object' || data === null) {
    throw new Error('Report file is not a JSON object.');
  }
  const obj = data as Record<string, unknown>;
  if (typeof obj.schema !== 'string' || !obj.schema.startsWith('nxlv-audit/')) {
    throw new Error('Unrecognized report: missing "nxlv-audit/*" schema. Pass a report produced by `scan --format json`.');
  }
  if (!Array.isArray(obj.results)) {
    throw new Error('Report is missing a "results" array.');
  }
  if (typeof obj.summary !== 'object' || obj.summary === null) {
    throw new Error('Report is missing a "summary" object.');
  }
  return obj as unknown as SavedReport;
}

export interface PromptBlock {
  projectName: string;
  projectId: string;
  ruleId: string;
  title: string;
  prompt: string;
}

/** Collect every finding that carries a non-empty aiPrompt, in report order. */
export function collectFixPrompts(report: SavedReport): PromptBlock[] {
  const blocks: PromptBlock[] = [];
  for (const r of report.results) {
    for (const f of r.findings ?? []) {
      if (f.aiPrompt && f.aiPrompt.trim().length > 0) {
        blocks.push({
          projectName: r.projectName,
          projectId: r.projectId,
          ruleId: f.ruleId,
          title: f.title,
          prompt: f.aiPrompt,
        });
      }
    }
  }
  return blocks;
}

/** Render fix-prompt blocks as isolated, copy-pasteable text. */
export function formatFixPrompts(blocks: PromptBlock[]): string {
  if (blocks.length === 0) {
    return 'No AI fix prompts found in this report.';
  }
  const out: string[] = [];
  let currentProject: string | null = null;
  for (const b of blocks) {
    if (b.projectId !== currentProject) {
      currentProject = b.projectId;
      out.push(`# ${b.projectName} (${b.projectId})`);
      out.push('');
    }
    out.push(`## [${b.ruleId}] ${b.title}`);
    out.push('');
    out.push('```');
    out.push(b.prompt);
    out.push('```');
    out.push('');
  }
  return out.join('\n').trimEnd() + '\n';
}
