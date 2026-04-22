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
import { writeFileSync } from 'fs';
import { runScan } from './commands/scan.js';
import { toJSON, toSARIF, toMarkdown, formatScanSummary } from './reporters/index.js';
import type { ScannerConfig } from './types.js';

const VERSION = '0.1.0';

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
    .option('-f, --format <type>', 'Output format: console|json|sarif|markdown|all (default: console)', 'console')
    .option('-o, --output <file>', 'Output file path (for json/sarif/markdown)')
    .option('--deep', 'Deep inspect: download and scan file contents (requires explicit consent)', false)
    .option('--no-chat', 'Skip scanning AI chat history')
    .option('--no-files', 'Skip scanning project file tree')
    .option('--no-rls', 'Skip Supabase RLS probing')
    .option('--no-headers', 'Skip security headers check')
    .option('--delay <ms>', 'Delay between API requests in ms (default: 500)', '500')
    .option('--exit-zero', 'Always exit with code 0 (disable CI failure on findings)', false)
    .option('-v, --verbose', 'Verbose output', false)
    .action(async (opts) => {
      console.log(BANNER);

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
        }

        if (format === 'json' || format === 'all') {
          const json = toJSON(results, summary);
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
        console.error(chalk.red(`\n❌ Scan failed: ${(err as Error).message}`));
        if (opts.verbose) {
          console.error((err as Error).stack);
        }
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
