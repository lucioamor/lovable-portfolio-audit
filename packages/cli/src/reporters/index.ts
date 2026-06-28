// ============================================================
// @nxlv/audit — Reporters (Console + JSON + SARIF + Markdown)
// ============================================================

import { createHash } from 'crypto';
import type { ProjectScanResult, Finding, ScanSummary } from '../types.js';
import { getSeverityEmoji, getSeverityColor } from '../engines/scorer.js';

// ---- HTML escaping (no XSS from evidence / project names) ----

/** Escape every character that is significant in HTML text or attributes.
 *  Applied to ALL interpolated values in the HTML report. */
export function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ---- Console Reporter ----

export function formatConsoleReport(
  result: ProjectScanResult,
  chalk: {
    red: (s: string) => string;
    yellow: (s: string) => string;
    green: (s: string) => string;
    cyan: (s: string) => string;
    gray: (s: string) => string;
    bold: (s: string) => string;
    white: (s: string) => string;
  }
): string {
  const lines: string[] = [];
  const emoji = getSeverityEmoji(result.severity);

  lines.push('');
  lines.push(chalk.bold(`${emoji} ${result.projectName}`));
  lines.push(chalk.gray(`   ID: ${result.projectId} | Score: ${result.riskScore}/100 | ${result.severity.toUpperCase()}`));

  if (result.isPreNov2025) {
    lines.push(chalk.yellow('   ⚠️  Created before Nov 2025 — potentially affected by BOLA vulnerability'));
  }

  if (result.bolaFilesProbe.signature === 'vulnerable') {
    lines.push(chalk.red('   🚨 BOLA: Files endpoint EXPOSED (HTTP 200)'));
  }
  if (result.bolaChatProbe.signature === 'vulnerable') {
    lines.push(chalk.red('   🚨 BOLA: Chat endpoint EXPOSED (HTTP 200)'));
  }

  for (const finding of result.findings) {
    const color =
      finding.severity === 'catastrophic' || finding.severity === 'critical' ? chalk.red :
      finding.severity === 'high' ? chalk.yellow :
      chalk.gray;

    lines.push(color(`   [${finding.ruleId}] ${finding.title}`));
    lines.push(chalk.gray(`           ${finding.evidence}`));
  }

  if (result.findings.length === 0 && result.severity === 'clean') {
    lines.push(chalk.green('   ✅ No issues found'));
  }

  return lines.join('\n');
}

export function formatScanSummary(
  summary: ScanSummary,
  chalk: {
    red: (s: string) => string;
    yellow: (s: string) => string;
    green: (s: string) => string;
    cyan: (s: string) => string;
    bold: (s: string) => string;
    white: (s: string) => string;
    gray: (s: string) => string;
  }
): string {
  const durationSec = (summary.totalDurationMs / 1000).toFixed(1);
  const lines: string[] = [
    '',
    chalk.bold('═══════════════════════════════════════════════'),
    chalk.bold('  🛡️  NXLV Audit — Scan Complete'),
    chalk.bold('═══════════════════════════════════════════════'),
    '',
    `  Projects scanned:    ${summary.scannedProjects}/${summary.totalProjects}`,
    `  Duration:            ${durationSec}s`,
    '',
    chalk.red(`  💀 Catastrophic:     ${summary.catastrophicCount}`),
    chalk.red(`  🔴 Critical:         ${summary.criticalCount}`),
    chalk.yellow(`  🟠 High:             ${summary.highCount}`),
    chalk.yellow(`  🟡 Medium:           ${summary.mediumCount}`),
    `  🔵 Low:              ${summary.lowCount}`,
    chalk.green(`  🟢 Clean:            ${summary.cleanCount}`),
    '',
    `  Pre-Nov-2025 (BOLA): ${summary.preNov2025Count} projects`,
    `  BOLA Vulnerable:     ${summary.bolaVulnerableCount} projects`,
    '',
  ];

  if (summary.catastrophicCount > 0 || summary.criticalCount > 0) {
    lines.push(chalk.red('  ⚡ ACTION REQUIRED: Critical findings detected.'));
    lines.push(chalk.red('     Run with --format json to get AI fix prompts.'));
  } else if (summary.highCount > 0) {
    lines.push(chalk.yellow('  ⚠️  High severity findings require attention.'));
  } else {
    lines.push(chalk.green('  ✅ No critical issues found in this scan.'));
  }

  lines.push('');
  lines.push(chalk.bold('═══════════════════════════════════════════════'));

  return lines.join('\n');
}

// ---- JSON Reporter ----

export function toJSON(
  results: ProjectScanResult[],
  summary: ScanSummary,
  extra?: Record<string, unknown>,
): string {
  return JSON.stringify({
    schema: 'nxlv-shield/v1',
    scanTimestamp: new Date().toISOString(),
    summary,
    results,
    ...extra,
  }, null, 2);
}

// ---- SARIF Reporter (GitHub Security tab compatible) ----

interface SARIFResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number };
    };
  }>;
  properties?: { tags: string[]; severity: string; confidence: string };
}

function severityToSarifLevel(severity: Finding['severity']): 'error' | 'warning' | 'note' {
  if (severity === 'catastrophic' || severity === 'critical') return 'error';
  if (severity === 'high' || severity === 'medium') return 'warning';
  return 'note';
}

export function toSARIF(results: ProjectScanResult[]): string {
  const allFindings: SARIFResult[] = [];

  for (const result of results) {
    for (const finding of result.findings) {
      allFindings.push({
        ruleId: finding.ruleId,
        level: severityToSarifLevel(finding.severity),
        message: {
          text: `[${result.projectName}] ${finding.title}: ${finding.evidence}. ${finding.recommendation}`,
        },
        locations: [{
          physicalLocation: {
            artifactLocation: {
              uri: finding.file || `lovable-project/${result.projectId}`,
            },
            region: finding.line ? { startLine: finding.line } : undefined,
          },
        }],
        properties: {
          tags: [finding.vector, finding.lovableLevel, `score:${result.riskScore}`],
          severity: finding.severity,
          confidence: finding.confidence,
        },
      });
    }
  }

  const sarif = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'NXLV Audit',
          version: '0.1.0',
          informationUri: 'https://github.com/lucioamor/lovable-portfolio-audit',
          rules: [],
        },
      },
      results: allFindings,
    }],
  };

  return JSON.stringify(sarif, null, 2);
}

// ---- Markdown Reporter ----

export function toMarkdown(
  results: ProjectScanResult[],
  summary: ScanSummary,
  extra?: Record<string, unknown>,
): string {
  const scanDate = typeof extra?.scanTimestamp === 'string'
    ? extra.scanTimestamp
    : new Date().toISOString();
  const lines: string[] = [
    '# 🛡️ NXLV Audit — Security Audit Report',
    '',
    `**Scan Date:** ${scanDate}`,
    `**Projects Scanned:** ${summary.scannedProjects}/${summary.totalProjects}`,
    '',
    '## Summary',
    '',
    '| Severity | Count |',
    '|---|---|',
    `| 💀 Catastrophic | ${summary.catastrophicCount} |`,
    `| 🔴 Critical | ${summary.criticalCount} |`,
    `| 🟠 High | ${summary.highCount} |`,
    `| 🟡 Medium | ${summary.mediumCount} |`,
    `| 🔵 Low | ${summary.lowCount} |`,
    `| 🟢 Clean | ${summary.cleanCount} |`,
    '',
    `**BOLA Vulnerable (pre-Nov 2025):** ${summary.bolaVulnerableCount} projects`,
    '',
    '---',
    '',
    '## Projects',
    '',
  ];

  for (const result of results) {
    if (result.severity === 'clean') continue;

    const emoji = getSeverityEmoji(result.severity);
    lines.push(`### ${emoji} ${result.projectName}`);
    lines.push('');
    lines.push(`- **Score:** ${result.riskScore}/100 (${result.severity.toUpperCase()})`);
    lines.push(`- **Lovable Level Required:** ${result.lovableLevel}`);
    lines.push(`- **Pre-Nov 2025:** ${result.isPreNov2025 ? '⚠️ Yes' : 'No'}`);
    lines.push(`- **BOLA Files:** ${result.bolaFilesProbe.signature === 'vulnerable' ? '🚨 EXPOSED' : '✅ Protected'}`);
    lines.push(`- **BOLA Chat:** ${result.bolaChatProbe.signature === 'vulnerable' ? '🚨 EXPOSED' : '✅ Protected'}`);
    lines.push('');

    if (result.findings.length > 0) {
      lines.push('**Findings:**');
      lines.push('');
      lines.push('| Rule | Severity | Title | Evidence |');
      lines.push('|---|---|---|---|');
      for (const f of result.findings) {
        lines.push(`| ${f.ruleId} | ${f.severity} | ${f.title} | \`${f.evidence}\` |`);
      }
      lines.push('');

      // AI Fix Prompts
      const topFinding = result.findings[0];
      if (topFinding?.aiPrompt) {
        lines.push(`**🤖 AI Fix Prompt (paste in Lovable chat):**`);
        lines.push('');
        lines.push('```');
        lines.push(topFinding.aiPrompt);
        lines.push('```');
        lines.push('');
      }
    }

    lines.push('---');
    lines.push('');
  }

  lines.push('*Generated by [NXLV Audit](https://github.com/lucioamor/lovable-portfolio-audit) — The Lovable Production-Readiness Standard*');

  return lines.join('\n');
}

// ---- HTML Reporter (single self-contained file, no network) ----

const SEVERITY_ROWS: Array<{ key: keyof ScanSummary; emoji: string; label: string }> = [
  { key: 'catastrophicCount', emoji: '💀', label: 'Catastrophic' },
  { key: 'criticalCount', emoji: '🔴', label: 'Critical' },
  { key: 'highCount', emoji: '🟠', label: 'High' },
  { key: 'mediumCount', emoji: '🟡', label: 'Medium' },
  { key: 'lowCount', emoji: '🔵', label: 'Low' },
  { key: 'cleanCount', emoji: '🟢', label: 'Clean' },
];

function severityBadge(severity: Finding['severity'] | ProjectScanResult['severity']): string {
  const color = getSeverityColor(severity);
  return `<span class="badge" style="--badge:${escapeHtml(color)}">${escapeHtml(severity.toUpperCase())}</span>`;
}

function rationaleBlock(rationale: ProjectScanResult['rationale']): string {
  if (!rationale || rationale.length === 0) return '';
  const rows = rationale
    .map(r =>
      `<tr><td>${escapeHtml(r.ruleId)}</td><td>${escapeHtml(r.vector)}</td>` +
      `<td class="num">${escapeHtml(r.points)}</td><td>${escapeHtml(r.reason)}</td></tr>`)
    .join('');
  return [
    '<details class="rationale">',
    '<summary>Score rationale</summary>',
    '<table class="rtable"><thead><tr><th>Rule</th><th>Vector</th><th>Points</th><th>Reason</th></tr></thead>',
    `<tbody>${rows}</tbody></table>`,
    '</details>',
  ].join('');
}

function findingBlock(f: Finding): string {
  const parts = [
    '<div class="finding">',
    '<div class="finding-head">',
    `<code class="rule">${escapeHtml(f.ruleId)}</code>`,
    severityBadge(f.severity),
    `<span class="finding-title">${escapeHtml(f.title)}</span>`,
    '</div>',
    `<div class="row"><span class="k">Evidence</span><code class="evidence">${escapeHtml(f.evidence)}</code></div>`,
  ];
  if (f.recommendation) {
    parts.push(`<div class="row"><span class="k">Recommendation</span><span class="v">${escapeHtml(f.recommendation)}</span></div>`);
  }
  parts.push('</div>');
  return parts.join('');
}

function projectSection(result: ProjectScanResult): string {
  const cls = result.severity === 'clean' ? 'project is-clean' : 'project';
  const parts = [
    `<section class="${cls}">`,
    `<h3>${escapeHtml(getSeverityEmoji(result.severity))} ${escapeHtml(result.projectName)} ${severityBadge(result.severity)}</h3>`,
    '<div class="meta">',
    `<span>ID: <code>${escapeHtml(result.projectId)}</code></span>`,
    `<span>Score: ${escapeHtml(result.riskScore)}/100</span>`,
    `<span>Lovable level: ${escapeHtml(result.lovableLevel)}</span>`,
    `<span>Pre-Nov 2025: ${result.isPreNov2025 ? '⚠️ Yes' : 'No'}</span>`,
    `<span>BOLA files: ${escapeHtml(result.bolaFilesProbe.signature)}</span>`,
    `<span>BOLA chat: ${escapeHtml(result.bolaChatProbe.signature)}</span>`,
    '</div>',
  ];
  if (result.findings.length === 0) {
    parts.push('<p class="clean">✅ No issues found</p>');
  } else {
    parts.push('<div class="findings">');
    for (const f of result.findings) parts.push(findingBlock(f));
    parts.push('</div>');
  }
  parts.push(rationaleBlock(result.rationale));
  parts.push('</section>');
  return parts.join('');
}

/**
 * Render a single, self-contained HTML report (inline CSS + minimal inline JS,
 * no external/CDN/network references). Every interpolated value is HTML-escaped.
 * The timestamp is taken from `extra.scanTimestamp` when present so the output
 * can be made deterministic; otherwise it is stamped now (mirrors toJSON).
 */
export function toHTML(
  results: ProjectScanResult[],
  summary: ScanSummary,
  extra?: Record<string, unknown>,
): string {
  const timestamp = typeof extra?.scanTimestamp === 'string'
    ? extra.scanTimestamp
    : new Date().toISOString();

  const summaryRows = SEVERITY_ROWS
    .map(r => `<tr><td>${r.emoji} ${escapeHtml(r.label)}</td><td class="num">${escapeHtml(summary[r.key])}</td></tr>`)
    .join('');

  const sections = results.map(projectSection).join('\n');

  // Minimal inline JS: a filter toggle for clean projects. No network, no eval.
  const script = [
    '<script>',
    'document.addEventListener("click",function(e){',
    '  if(e.target&&e.target.id==="toggle-clean"){',
    '    document.body.classList.toggle("hide-clean",e.target.checked);',
    '  }',
    '});',
    '</script>',
  ].join('');

  return [
    '<!DOCTYPE html>',
    '<html lang="en"><head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<title>NXLV Audit — Security Audit Report</title>',
    '<style>',
    ':root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#e6edf3;--muted:#8b949e;--accent:#58a6ff;}',
    '*{box-sizing:border-box;}',
    'body{margin:0;padding:2rem;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}',
    'h1{font-size:1.6rem;margin:0 0 .25rem;}',
    'h3{font-size:1.15rem;margin:0 0 .5rem;}',
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#0b0f14;padding:.1rem .35rem;border-radius:4px;color:#c9d1d9;word-break:break-all;}',
    'a{color:var(--accent);}',
    '.sub{color:var(--muted);margin:0 0 1.5rem;}',
    'table{border-collapse:collapse;width:100%;max-width:420px;margin:0 0 2rem;}',
    'th,td{border:1px solid var(--border);padding:.4rem .6rem;text-align:left;}',
    'th{background:var(--panel);}',
    '.num{text-align:right;font-variant-numeric:tabular-nums;}',
    '.project{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:1rem 1.25rem;margin:0 0 1.25rem;}',
    '.meta{display:flex;flex-wrap:wrap;gap:.25rem 1rem;color:var(--muted);margin:0 0 .75rem;}',
    '.badge{display:inline-block;font-size:.7rem;font-weight:700;letter-spacing:.04em;padding:.1rem .45rem;border-radius:999px;color:#0d1117;background:var(--badge,#8b949e);vertical-align:middle;}',
    '.finding{border-left:3px solid var(--border);padding:.5rem .75rem;margin:.5rem 0;background:#0b0f14;border-radius:0 6px 6px 0;}',
    '.finding-head{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;margin-bottom:.35rem;}',
    '.finding-title{font-weight:600;}',
    '.rule{font-size:.8rem;}',
    '.row{display:flex;gap:.5rem;margin:.2rem 0;}',
    '.row .k{color:var(--muted);min-width:7rem;flex-shrink:0;}',
    '.evidence{background:#0d1117;}',
    '.clean{color:#3fb950;}',
    '.rationale{margin-top:.75rem;color:var(--muted);}',
    '.rationale summary{cursor:pointer;}',
    '.rtable{max-width:100%;margin:.5rem 0 0;font-size:.85rem;}',
    '.controls{margin:0 0 1.5rem;color:var(--muted);}',
    'body.hide-clean .project.is-clean{display:none;}',
    '</style>',
    '</head><body>',
    '<h1>🛡️ NXLV Audit — Security Audit Report</h1>',
    `<p class="sub">Scan date: ${escapeHtml(timestamp)} · Projects scanned: ${escapeHtml(summary.scannedProjects)}/${escapeHtml(summary.totalProjects)}</p>`,
    '<h2>Summary</h2>',
    '<table><thead><tr><th>Severity</th><th class="num">Count</th></tr></thead>',
    `<tbody>${summaryRows}</tbody></table>`,
    '<label class="controls"><input type="checkbox" id="toggle-clean"> Hide clean projects</label>',
    '<h2>Projects</h2>',
    sections,
    `<p class="sub">Generated by <a href="https://github.com/lucioamor/lovable-portfolio-audit">NXLV Audit</a> — The Lovable Production-Readiness Standard</p>`,
    script,
    '</body></html>',
  ].join('\n');
}
