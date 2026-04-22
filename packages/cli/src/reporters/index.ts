// ============================================================
// @nxlv/shield — Reporters (Console + JSON + SARIF + Markdown)
// ============================================================

import { createHash } from 'crypto';
import type { ProjectScanResult, Finding, ScanSummary } from '../types.js';
import { getSeverityEmoji } from '../engines/scorer.js';

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
    chalk.bold('  🛡️  NXLV Shield — Scan Complete'),
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

export function toJSON(results: ProjectScanResult[], summary: ScanSummary): string {
  return JSON.stringify({
    schema: 'nxlv-shield/v1',
    scanTimestamp: new Date().toISOString(),
    summary,
    results,
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
          name: 'NXLV Shield',
          version: '0.1.0',
          informationUri: 'https://github.com/nxlv/lovable-portfolio-audit',
          rules: [],
        },
      },
      results: allFindings,
    }],
  };

  return JSON.stringify(sarif, null, 2);
}

// ---- Markdown Reporter ----

export function toMarkdown(results: ProjectScanResult[], summary: ScanSummary): string {
  const lines: string[] = [
    '# 🛡️ NXLV Shield — Security Audit Report',
    '',
    `**Scan Date:** ${new Date().toISOString()}`,
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

  lines.push('*Generated by [NXLV Shield](https://github.com/nxlv/lovable-portfolio-audit) — The Lovable Production-Readiness Standard*');

  return lines.join('\n');
}
