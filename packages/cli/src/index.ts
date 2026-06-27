#!/usr/bin/env node
// ============================================================
// @nxlv/shield — CLI Entry Point
// ============================================================
// Usage:
//   npx @nxlv/shield scan [options]
//   npx @nxlv/shield scan --url https://myapp.lovable.app
//   npx @nxlv/shield scan --token <bearer> --deep
//   npx @nxlv/shield scan --format sarif --output results.sarif
// ============================================================

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { writeFileSync, readFileSync } from 'fs';
import { renderChecklist, parseRlsResult, classifyRlsAudit } from './engines/rls-checklist.js';
import {
  DEFAULT_BASELINE_PATH,
  emptyBaseline,
  computeDelta,
  nextBaseline,
  type BaselineFile,
  type DeltaSummary,
} from './engines/baseline.js';
import { runScan } from './commands/scan.js';
import { existsSync } from 'fs';
import { toJSON, toSARIF, toMarkdown, toHTML, formatScanSummary } from './reporters/index.js';
import { buildWebhookPayload, postWebhook } from './engines/webhook.js';
import { parseSavedReport, collectFixPrompts, formatFixPrompts } from './engines/saved-report.js';
import { extractPack, verifyPack } from './engines/evidence-verify.js';
import { createLogger, setGlobalLevel } from './util/logger.js';
import type { ScannerConfig, Finding } from './types.js';
import type { RLSPolicyCheck } from './engines/supabase-engine.js';

const VERSION = '0.1.0';
const log = createLogger({ tool: 'nxlv-shield' });

function resolveBaselinePath(opt: unknown): string | undefined {
  if (opt === undefined || opt === false) return undefined;
  if (opt === true) return DEFAULT_BASELINE_PATH;
  return String(opt);
}

function printDelta(delta: DeltaSummary): string {
  const lines: string[] = [
    '',
    chalk.bold('  ── Baseline drift ──'),
    chalk.red(`  + ${delta.newCount} new`) + chalk.gray('   ') +
      chalk.green(`✓ ${delta.resolvedCount} resolved`) + chalk.gray('   ') +
      chalk.gray(`= ${delta.unchangedCount} unchanged`),
  ];
  const changed = delta.items.filter(i => i.drift_state !== 'unchanged')
    .sort((a, b) => (a.drift_state === 'new' ? -1 : 1));
  for (const i of changed.slice(0, 20)) {
    const mark = i.drift_state === 'new' ? chalk.red('  + NEW     ') : chalk.green('  ✓ RESOLVED');
    lines.push(`${mark} [${i.ruleId}] ${i.title}`);
  }
  if (changed.length > 20) lines.push(chalk.gray(`  ... and ${changed.length - 20} more changes`));
  if (changed.length === 0) lines.push(chalk.gray('  (no change since baseline)'));
  lines.push('');
  return lines.join('\n');
}

function printRlsFindings(findings: Finding[], policyChecks: RLSPolicyCheck[]): string {
  const lines: string[] = [
    '',
    chalk.bold('═══════════════════════════════════════════════'),
    chalk.bold('  🛡️  NXLV Shield — Deep RLS Classification'),
    chalk.bold('═══════════════════════════════════════════════'),
    '',
    `  Tables analyzed:   ${policyChecks.length}`,
    `  Findings:          ${findings.length}`,
    '',
  ];

  if (findings.length === 0) {
    lines.push(chalk.green('  ✅ No deep-RLS issues found in the pasted result.'));
    lines.push('');
    return lines.join('\n');
  }

  const order = { catastrophic: 5, critical: 4, high: 3, medium: 2, low: 1, info: 0 } as const;
  const sorted = [...findings].sort((a, b) =>
    (order[b.severity as keyof typeof order] ?? 0) - (order[a.severity as keyof typeof order] ?? 0));

  for (const f of sorted) {
    const color = f.severity === 'catastrophic' || f.severity === 'critical' ? chalk.red
                : f.severity === 'high' ? chalk.yellow : chalk.gray;
    lines.push(color(`  [${f.ruleId}] ${f.title}`));
    lines.push(chalk.gray(`          ${f.evidence}`));
    if (f.remediationSql) {
      lines.push(chalk.cyan(`          fix: ${f.remediationSql.split('\n')[0]}`));
    }
  }
  lines.push('');
  lines.push(chalk.gray('  Run with --format json on a full scan to combine these with other findings.'));
  lines.push('');
  return lines.join('\n');
}

const BANNER = `
${chalk.cyan('█▄░█ ▀▄▀ █░░ █░█   ░░ █▀ █░█ █ █▀▀ █░░ █▀▄')}
${chalk.cyan('█░▀█ █░█ █▄▄ ▀▄▀   ░░ ▄█ █▀█ █ ██▄ █▄▄ █▄▀')}
${chalk.gray(`The Lovable Production-Readiness Standard — v${VERSION}`)}
${chalk.gray('https://github.com/nxlv/lovable-portfolio-audit')}
`;

async function main() {
  const program = new Command();

  program
    .name('nxlv-shield')
    .description('Security audit for Lovable apps — BOLA, RLS, secrets, and more')
    .version(VERSION);

  // ---- scan command ----
  program
    .command('scan')
    .description('Scan your Lovable projects for security vulnerabilities')
    .option('-t, --token <bearer>', 'Lovable Bearer token (or set LOVABLE_TOKEN env var)')
    .option('--audit-token <bearer>', 'Second Lovable account token for dual-probe BOLA confirmation (or set LOVABLE_AUDIT_TOKEN env var)')
    .option('-u, --url <url>', 'Target URL to scan security headers and source maps')
    .option('--supabase-url <url>', 'Supabase project URL for RLS testing')
    .option('--supabase-key <key>', 'Supabase anon key for RLS testing')
    .option('-p, --projects <ids>', 'Comma-separated project IDs to scan (default: all)')
    .option('-f, --format <type>', 'Output format: console|json|sarif|markdown|html|all (default: console)', 'console')
    .option('-o, --output <file>', 'Output file path (for json/sarif/markdown/html)')
    .option('--deep', 'Deep inspect: download and scan file contents (requires explicit consent)', false)
    .option('--no-chat', 'Skip scanning AI chat history')
    .option('--no-files', 'Skip scanning project file tree')
    .option('--no-rls', 'Skip Supabase RLS probing')
    .option('--rls-checklist', 'Print the deep-RLS audit SQL (copy-paste model — no DB connection) and exit', false)
    .option('--rls-result <file>', 'Classify a pasted deep-RLS audit JSON result (DB-003/004/005/008/009) and exit')
    .option('--no-headers', 'Skip security headers check')
    .option('--delay <ms>', 'Delay between API requests in ms (default: 500)', '500')
    .option('--baseline [file]', `Compare findings against a baseline (default: ${DEFAULT_BASELINE_PATH}) and report new/resolved drift`)
    .option('--update-baseline [file]', `Write the baseline after scanning (default: ${DEFAULT_BASELINE_PATH})`)
    .option('--webhook <url>', 'POST a compact baseline-drift summary (new/resolved finding identifiers, no secrets) to this URL after a --baseline scan')
    .option('--exit-zero', 'Always exit with code 0 (disable CI failure on findings)', false)
    .option('-v, --verbose', 'Verbose output', false)
    .action(async (opts) => {
      console.log(BANNER);

      // Verbose routes debug logs through the redacting logger — never raw console.
      if (opts.verbose) setGlobalLevel('debug');

      // ---- Deep RLS checklist (copy-paste model — no token, no DB connection) ----
      if (opts.rlsResult) {
        try {
          const raw = readFileSync(opts.rlsResult, 'utf-8');
          const { findings, policyChecks } = classifyRlsAudit(parseRlsResult(raw));
          console.log(printRlsFindings(findings, policyChecks));
          process.exit(findings.some(f => f.severity === 'high' || f.severity === 'critical' || f.severity === 'catastrophic') && !opts.exitZero ? 1 : 0);
        } catch (err) {
          console.error(chalk.red(`\n❌ ${(err as Error).message}`));
          process.exit(1);
        }
      }
      if (opts.rlsChecklist) {
        console.log(renderChecklist());
        process.exit(0);
      }

      // Resolve token
      const token = opts.token || process.env.LOVABLE_TOKEN;
      if (!token) {
        console.error(chalk.red('\n❌ No Lovable token provided.'));
        console.error(chalk.gray('\nHow to get your token:'));
        console.error(chalk.gray('1. Open lovable.dev and log in'));
        console.error(chalk.gray('2. Open DevTools (F12) → Network tab'));
        console.error(chalk.gray('3. Filter requests for api.lovable.dev'));
        console.error(chalk.gray('4. Copy the Authorization: Bearer <token> value'));
        console.error(chalk.gray('\nThen run: nxlv-shield scan --token <your-token>'));
        console.error(chalk.gray('Or set:   LOVABLE_TOKEN=<your-token> nxlv-shield scan'));
        process.exit(1);
      }

      const auditToken = opts.auditToken || process.env.LOVABLE_AUDIT_TOKEN;
      if (auditToken) {
        console.log(chalk.cyan('🔍 Dual-probe mode: BOLA confirmation enabled (audit token provided).'));
      }

      const config: ScannerConfig = {
        lovableToken: token,
        auditToken,
        targetUrl: opts.url,
        supabaseUrl: opts.supabaseUrl,
        supabaseAnonKey: opts.supabaseKey,
        projectIds: opts.projects ? opts.projects.split(',').map((s: string) => s.trim()) : undefined,
        scanDelay: parseInt(opts.delay) || 500,
        maxConcurrent: 1,
        includeChat: opts.chat !== false,
        includeFiles: opts.files !== false,
        testRLS: opts.rls !== false,
        testHeaders: opts.headers !== false && !!opts.url,
        testSourceMaps: !!opts.url,
        deepInspect: opts.deep,
        outputFormat: opts.format as ScannerConfig['outputFormat'],
        outputFile: opts.output,
        exitCodeOnCritical: !opts.exitZero,
        safeMode: true,
        verbose: opts.verbose,
      };

      // Deep inspect consent gate
      if (config.deepInspect) {
        console.log(chalk.yellow('\n⚠️  DEEP INSPECT MODE ENABLED'));
        console.log(chalk.gray('   File contents will be downloaded and scanned locally.'));
        console.log(chalk.gray('   No content is stored or transmitted externally.'));
        console.log(chalk.gray('   Only metadata (hashes, masked values) is retained.\n'));
      }

      const spinner = ora({ text: 'Initializing scan...', color: 'cyan' }).start();

      try {
        const { results, summary } = await runScan(config, (msg) => {
          spinner.text = msg;
        });

        spinner.stop();

        // ---- Baseline / delta (H4) ----
        let delta: DeltaSummary | undefined;
        const now = new Date().toISOString();
        const baselinePath = resolveBaselinePath(opts.baseline) ?? resolveBaselinePath(opts.updateBaseline);
        if (opts.baseline || opts.updateBaseline) {
          const path = baselinePath || DEFAULT_BASELINE_PATH;
          let baseline: BaselineFile | null = null;
          if (existsSync(path)) {
            try { baseline = JSON.parse(readFileSync(path, 'utf-8')) as BaselineFile; }
            catch { console.error(chalk.yellow(`⚠️  Could not parse baseline ${path}; treating as empty.`)); baseline = emptyBaseline(now); }
          }
          if (opts.baseline) {
            delta = computeDelta(results, baseline, now);
          }
          if (opts.updateBaseline) {
            const updated = nextBaseline(results, baseline, now);
            writeFileSync(path, JSON.stringify(updated, null, 2), 'utf-8');
          }
        }

        // ---- Output ----
        const format = config.outputFormat || 'console';

        if (format === 'console' || format === 'all') {
          // Print per-project results (only non-clean)
          for (const result of results) {
            if (result.severity !== 'clean' || config.verbose) {
              const emoji =
                result.severity === 'catastrophic' ? '💀' :
                result.severity === 'critical' ? '🔴' :
                result.severity === 'high' ? '🟠' :
                result.severity === 'medium' ? '🟡' :
                result.severity === 'low' ? '🔵' : '🟢';

              console.log(`\n${emoji} ${chalk.bold(result.projectName)}`);
              console.log(chalk.gray(`   Score: ${result.riskScore}/100 | ${result.severity.toUpperCase()} | BOLA-files: ${result.bolaFilesProbe.signature} | BOLA-chat: ${result.bolaChatProbe.signature}`));

              if (result.isPreNov2025) {
                console.log(chalk.yellow('   ⚠️  Pre-Nov 2025: potentially in BOLA vulnerability window'));
              }

              for (const f of result.findings.slice(0, 5)) {
                const color = f.severity === 'catastrophic' || f.severity === 'critical' ? chalk.red :
                              f.severity === 'high' ? chalk.yellow : chalk.gray;
                console.log(color(`   [${f.ruleId}] ${f.title}`));
                console.log(chalk.gray(`           Evidence: ${f.evidence}`));
              }

              if (result.findings.length > 5) {
                console.log(chalk.gray(`   ... and ${result.findings.length - 5} more findings. Use --format json for full details.`));
              }
            }
          }

          console.log(formatScanSummary(summary, chalk));
          if (delta) console.log(printDelta(delta));
        }

        if (format === 'json' || format === 'all') {
          const json = toJSON(results, summary, delta ? { delta } : undefined);
          if (config.outputFile) {
            writeFileSync(config.outputFile.replace('.sarif', '.json'), json, 'utf-8');
            console.log(chalk.cyan(`\n📄 JSON report saved to: ${config.outputFile}`));
          } else {
            console.log('\n' + json);
          }
        }

        if (format === 'sarif' || format === 'all') {
          const sarif = toSARIF(results);
          const sarifFile = config.outputFile || 'nxlv-shield-results.sarif';
          writeFileSync(sarifFile, sarif, 'utf-8');
          console.log(chalk.cyan(`\n📋 SARIF report saved to: ${sarifFile}`));
          console.log(chalk.gray('   Upload to GitHub Security tab or any SARIF-compatible tool.'));
        }

        if (format === 'markdown' || format === 'all') {
          const md = toMarkdown(results, summary);
          const mdFile = config.outputFile?.replace('.sarif', '.md') || 'nxlv-shield-report.md';
          writeFileSync(mdFile, md, 'utf-8');
          console.log(chalk.cyan(`\n📝 Markdown report saved to: ${mdFile}`));
        }

        if (format === 'html' || format === 'all') {
          const html = toHTML(results, summary, { scanTimestamp: now });
          const htmlFile = config.outputFile?.replace(/\.(sarif|json|md)$/, '.html') || 'nxlv-shield-report.html';
          writeFileSync(htmlFile, html, 'utf-8');
          console.log(chalk.cyan(`\n🖥️  HTML report saved to: ${htmlFile}`));
        }

        // ---- Diff-alert webhook (P11) — only meaningful with --baseline ----
        if (opts.webhook) {
          if (delta) {
            const payload = buildWebhookPayload(delta, now);
            const res = await postWebhook(opts.webhook, payload);
            if (res.ok) {
              console.log(chalk.cyan(`\n🔔 Drift webhook delivered (HTTP ${res.status}).`));
            } else {
              console.error(chalk.yellow(`\n⚠️  Drift webhook not delivered: ${res.error ?? `HTTP ${res.status}`}. Scan results are unaffected.`));
            }
          } else {
            console.error(chalk.yellow('\n⚠️  --webhook requires --baseline to compute drift; nothing posted.'));
          }
        }

        // ---- CI exit code ----
        if (config.exitCodeOnCritical) {
          if (summary.catastrophicCount > 0 || summary.criticalCount > 0) {
            console.error(chalk.red(`\n💥 Exiting with code 1: ${summary.catastrophicCount + summary.criticalCount} critical/catastrophic findings`));
            process.exit(1);
          }
        }

        process.exit(0);
      } catch (err) {
        spinner.stop();
        // Message + stack are routed through the redacting logger so a token
        // embedded in an error (e.g. a URL with credentials) can't leak.
        console.error(chalk.red(`\n❌ Scan failed.`));
        log.error('scan failed', err);
        process.exit(1);
      }
    });

  // ---- verify command (quick token check) ----
  program
    .command('verify')
    .description('Verify your Lovable token is valid')
    .option('-t, --token <bearer>', 'Lovable Bearer token (or LOVABLE_TOKEN env var)')
    .action(async (opts) => {
      const token = opts.token || process.env.LOVABLE_TOKEN;
      if (!token) {
        console.error(chalk.red('❌ No token provided. Use --token or set LOVABLE_TOKEN.'));
        process.exit(1);
      }

      const { LovableAPIClient } = await import('./engines/lovable-client.js');
      const client = new LovableAPIClient(token);
      const { valid, userId } = await client.validateToken();

      if (valid) {
        console.log(chalk.green(`✅ Token valid${userId ? ` (user: ${userId})` : ''}`));
      } else {
        console.error(chalk.red('❌ Token invalid or expired'));
        process.exit(1);
      }
    });

  // ---- report command (regenerate a report from a saved JSON, no re-scan) ----
  program
    .command('report <results.json>')
    .description('Regenerate a report from a saved nxlv-shield JSON report (no re-scan)')
    .option('-f, --format <type>', 'Output format: html|markdown|json|sarif', 'html')
    .option('-o, --output <file>', 'Output file path (defaults to stdout for json/markdown)')
    .action(async (file: string, opts) => {
      let report;
      try {
        report = parseSavedReport(readFileSync(file, 'utf-8'));
      } catch (err) {
        const reason = (err as NodeJS.ErrnoException).code === 'ENOENT'
          ? `Report file not found: ${file}`
          : (err as Error).message;
        console.error(chalk.red(`\n❌ ${reason}`));
        process.exit(1);
      }

      const stamp = report.scanTimestamp;
      const extra = stamp ? { scanTimestamp: stamp } : undefined;
      const format = String(opts.format).toLowerCase();
      let rendered: string;
      let defaultName: string;

      switch (format) {
        case 'html':     rendered = toHTML(report.results, report.summary, extra); defaultName = 'nxlv-shield-report.html'; break;
        case 'markdown': rendered = toMarkdown(report.results, report.summary, extra); defaultName = 'nxlv-shield-report.md'; break;
        case 'json':     rendered = toJSON(report.results, report.summary, extra); defaultName = 'nxlv-shield-report.json'; break;
        case 'sarif':    rendered = toSARIF(report.results); defaultName = 'nxlv-shield-results.sarif'; break;
        default:
          console.error(chalk.red(`\n❌ Unknown format "${opts.format}". Use html|markdown|json|sarif.`));
          process.exit(1);
      }

      if (opts.output) {
        writeFileSync(opts.output, rendered, 'utf-8');
        console.log(chalk.cyan(`📄 ${format.toUpperCase()} report saved to: ${opts.output}`));
      } else if (format === 'html' || format === 'sarif') {
        // Binary-ish/large formats default to a file so stdout stays usable.
        writeFileSync(defaultName, rendered, 'utf-8');
        console.log(chalk.cyan(`📄 ${format.toUpperCase()} report saved to: ${defaultName}`));
      } else {
        process.stdout.write(rendered + '\n');
      }
    });

  // ---- fix-prompt command (extract AI remediation prompts from a saved JSON) ----
  program
    .command('fix-prompt <results.json>')
    .description('Extract copy-pasteable AI fix prompts from a saved nxlv-shield JSON report')
    .option('-o, --output <file>', 'Write prompts to a file instead of stdout')
    .action(async (file: string, opts) => {
      let report;
      try {
        report = parseSavedReport(readFileSync(file, 'utf-8'));
      } catch (err) {
        const reason = (err as NodeJS.ErrnoException).code === 'ENOENT'
          ? `Report file not found: ${file}`
          : (err as Error).message;
        console.error(chalk.red(`\n❌ ${reason}`));
        process.exit(1);
      }

      const blocks = collectFixPrompts(report);
      const text = formatFixPrompts(blocks);

      if (opts.output) {
        writeFileSync(opts.output, text, 'utf-8');
        console.log(chalk.cyan(`📝 ${blocks.length} fix prompt(s) written to: ${opts.output}`));
      } else {
        process.stdout.write(text);
      }
    });

  // ---- verify-evidence command (P20: validate a signed evidence pack) ----
  program
    .command('verify-evidence <pack.json>')
    .description('Verify the HMAC-SHA256 signature of an exported evidence pack')
    .option('-p, --passphrase <p>', 'Passphrase / device key (or NXLV_EVIDENCE_PASSPHRASE env var)')
    .action(async (file: string, opts) => {
      const passphrase = opts.passphrase || process.env.NXLV_EVIDENCE_PASSPHRASE;
      if (!passphrase) {
        console.error(chalk.red('❌ No passphrase provided. Use --passphrase or set NXLV_EVIDENCE_PASSPHRASE.'));
        process.exit(1);
      }

      let parsed;
      try {
        const raw = readFileSync(file, 'utf-8');
        let json: unknown;
        try { json = JSON.parse(raw); }
        catch { throw new Error('Evidence pack is not valid JSON.'); }
        parsed = extractPack(json);
      } catch (err) {
        const reason = (err as NodeJS.ErrnoException).code === 'ENOENT'
          ? `Evidence pack not found: ${file}`
          : (err as Error).message;
        console.error(chalk.red(`\n❌ ${reason}`));
        process.exit(1);
      }

      try {
        const valid = await verifyPack(parsed, passphrase);
        if (valid) {
          console.log(chalk.green('✅ VALID — signature matches; pack is authentic and untampered.'));
          process.exit(0);
        } else {
          console.error(chalk.red('❌ INVALID — signature does not match (wrong passphrase or tampered pack).'));
          process.exit(1);
        }
      } catch (err) {
        console.error(chalk.red(`\n❌ ${(err as Error).message}`));
        process.exit(1);
      }
    });

  // ---- ci command (minimal output for pipelines) ----
  program
    .command('ci')
    .description('CI-optimized scan: SARIF output + exit code 1 on critical findings')
    .option('-t, --token <bearer>', 'Lovable Bearer token (or LOVABLE_TOKEN env var)')
    .option('-o, --output <file>', 'SARIF output file', 'nxlv-shield.sarif')
    .action(async (opts) => {
      const token = opts.token || process.env.LOVABLE_TOKEN;
      if (!token) {
        console.error('ERROR: No LOVABLE_TOKEN set');
        process.exit(1);
      }

      const config: ScannerConfig = {
        lovableToken: token,
        scanDelay: 500,
        maxConcurrent: 1,
        includeChat: true,
        includeFiles: true,
        testRLS: false, // No Supabase URL in CI without config
        testHeaders: false,
        testSourceMaps: false,
        deepInspect: false,
        outputFormat: 'sarif',
        outputFile: opts.output,
        exitCodeOnCritical: true,
        safeMode: true,
        verbose: false,
      };

      const { results, summary } = await runScan(config, (msg) => process.stderr.write(msg + '\n'));
      const sarif = toSARIF(results);
      writeFileSync(opts.output, sarif, 'utf-8');

      console.log(`NXLV Shield CI: ${summary.scannedProjects} projects, ${summary.criticalCount + summary.catastrophicCount} critical findings`);

      if (summary.catastrophicCount > 0 || summary.criticalCount > 0) {
        process.exit(1);
      }
    });

  await program.parseAsync(process.argv);
}

main().catch(err => {
  console.error(chalk.red(`Fatal: ${err.message}`));
  process.exit(1);
});
