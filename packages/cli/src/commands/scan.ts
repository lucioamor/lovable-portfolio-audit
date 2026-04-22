// ============================================================
// @nxlv/shield — Scan Command
// ============================================================
// Main orchestrator: lists projects → probes BOLA → scans secrets
// → tests RLS → generates findings → scores → reports.
// ============================================================

import { randomUUID } from 'crypto';
import { LovableAPIClient } from '../engines/lovable-client.js';
import {
  scanForSecrets,
  scanForPII,
  SENSITIVE_FILE_PATHS,
  maskSecret,
} from '../engines/patterns.js';
import {
  checkSecurityHeaders,
  scanSupabase,
  extractProjectRef,
  extractSupabaseUrl,
  extractSupabaseAnonKey,
} from '../engines/supabase-engine.js';
import {
  calculateRiskScore,
  getSeverityFromScore,
  getLovableLevelRequired,
} from '../engines/scorer.js';
import type {
  ScannerConfig,
  ProjectScanResult,
  Finding,
  ScanSummary,
  LovableProject,
} from '../types.js';

// ---- Finding builder helpers ----

function makeFinding(
  ruleId: string,
  vector: Finding['vector'],
  severity: Finding['severity'],
  title: string,
  description: string,
  evidence: string,
  recommendation: string,
  aiPrompt: string,
  extra?: Partial<Finding>,
): Finding {
  return {
    id: randomUUID(),
    ruleId,
    vector,
    severity,
    confidence: 'confirmed',
    lovableLevel: severity === 'catastrophic' || severity === 'critical' ? 'L0' :
                  severity === 'high' ? 'L1' : 'L2',
    title,
    description,
    evidence,
    recommendation,
    aiPrompt,
    ...extra,
  };
}

// ---- Per-project scan ----

async function scanProject(
  project: LovableProject,
  client: LovableAPIClient,
  config: ScannerConfig,
  onProgress?: (msg: string) => void,
): Promise<ProjectScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  let filesScanned = 0;
  let chatMessagesScanned = 0;

  const isPreNov2025 = LovableAPIClient.isPreNov2025(project);
  const isActive = LovableAPIClient.isActiveProject(project);

  onProgress?.(`  Probing BOLA endpoints...`);

  // ---- BOLA Probe (LOV-001) ----
  // Use dual-probe when audit token available (proves cross-account access).
  // Without audit token, 200 → owner_only (access confirmed, BOLA unproven).
  const auditToken = config.auditToken;
  const [bolaFilesProbe, bolaChatProbe] = await Promise.all([
    auditToken
      ? client.probeFilesEndpointDual(project.id, auditToken)
      : client.probeFilesEndpoint(project.id),
    auditToken
      ? client.probeChatEndpointDual(project.id, auditToken)
      : client.probeChatEndpoint(project.id),
  ]);

  // Add BOLA findings — severity and confidence differ by signature.
  if (bolaFilesProbe.signature === 'vulnerable') {
    findings.push(makeFinding(
      'LOV-001', 'bola_files', 'critical',
      'BOLA Confirmed: Project Files Accessible by Any Account',
      'Dual-probe confirmed: a second Lovable account (audit token) received HTTP 200 on the /git/files endpoint. Any authenticated Lovable user can access source code of this project.',
      `Owner→HTTP ${bolaFilesProbe.status} | Audit→HTTP 200 | GET /projects/${project.id}/git/files`,
      'Contact Lovable support immediately. Do not share project IDs publicly.',
      'In Lovable, set this project to Private and contact Lovable support to apply the retroactive ownership fix. Rotate any secrets found in source code.',
      { confidence: 'confirmed' },
    ));
  } else if (bolaFilesProbe.signature === 'owner_only') {
    findings.push(makeFinding(
      'LOV-001', 'bola_files', 'high',
      'BOLA Risk: Files Accessible (Cross-Account Not Verified)',
      'Your owner token received HTTP 200 on the /git/files endpoint. Cross-account access was not tested (no --audit-token provided). Projects created before Nov 2025 are likely affected by the BOLA vulnerability.',
      `Owner→HTTP ${bolaFilesProbe.status} | GET /projects/${project.id}/git/files | Run with --audit-token to confirm`,
      'Run nxlv-shield scan --audit-token <second-account-token> to confirm or rule out cross-account exposure.',
      'In Lovable, go to project settings and verify the project is set to Private. Run again with a second Lovable account token to get a confirmed result.',
      { confidence: 'likely' },
    ));
  }

  if (bolaChatProbe.signature === 'vulnerable') {
    findings.push(makeFinding(
      'LOV-001', 'bola_chat', 'critical',
      'BOLA Confirmed: Chat History Accessible by Any Account',
      'Dual-probe confirmed: a second Lovable account (audit token) received HTTP 200 on the /messages endpoint. AI conversation history is accessible cross-account and may contain credentials, schemas, or PII.',
      `Owner→HTTP ${bolaChatProbe.status} | Audit→HTTP 200 | GET /projects/${project.id}/messages`,
      'Delete sensitive messages. Contact Lovable support to secure this endpoint.',
      'Review exposed chat history for API keys, passwords, or connection strings. Rotate any credentials found. Contact Lovable support.',
      { confidence: 'confirmed' },
    ));
  } else if (bolaChatProbe.signature === 'owner_only') {
    findings.push(makeFinding(
      'LOV-001', 'bola_chat', 'high',
      'BOLA Risk: Chat History Accessible (Cross-Account Not Verified)',
      'Your owner token received HTTP 200 on the /messages endpoint. Cross-account access not tested. Chat may contain credentials or PII shared during development.',
      `Owner→HTTP ${bolaChatProbe.status} | GET /projects/${project.id}/messages | Run with --audit-token to confirm`,
      'Run nxlv-shield scan --audit-token <second-account-token> to confirm or rule out cross-account exposure.',
      'Avoid sharing credentials in Lovable chat. Run again with a second account token to confirm if this is a confirmed BOLA or owner-only access.',
      { confidence: 'likely' },
    ));
  }

  // LOV-006: Age flag
  if (isPreNov2025) {
    findings.push(makeFinding(
      'LOV-006', 'pre_nov2025', 'medium',
      'Project Created Before November 2025 (BOLA Window)',
      'Projects created before November 2025 may be affected by the BOLA vulnerability (CVE disclosed April 2026) that was fixed only for projects created after that date.',
      `Created: ${project.created_at}`,
      'Verify the BOLA probe results above. If files or chat are accessible, this project needs immediate attention.',
      'In Lovable, go to project settings and ensure Privacy is set to Private. If this project contains sensitive data, contact Lovable support immediately.',
      { confidence: 'likely', lovableLevel: 'L1' },
    ));
  }

  // ---- File scanning (if files endpoint accessible) ----
  const filesAccessible = bolaFilesProbe.signature === 'vulnerable' || bolaFilesProbe.signature === 'owner_only';
  if (filesAccessible && config.includeFiles) {
    onProgress?.(`  Scanning project files...`);

    const { files } = await client.getProjectFiles(project.id);
    if (files?.files) {
      filesScanned = files.files.length;

      // Check for sensitive file paths
      for (const fileEntry of files.files) {
        const sensitiveMatch = SENSITIVE_FILE_PATHS.find(sf =>
          fileEntry.path.includes(sf.path)
        );
        if (sensitiveMatch) {
          findings.push(makeFinding(
            'APP-010', 'sensitive_file',
            sensitiveMatch.severity as Finding['severity'],
            `Sensitive File Found: ${fileEntry.path}`,
            sensitiveMatch.reason,
            `File path: ${fileEntry.path}`,
            'Review the contents of this file for exposed credentials.',
            `In Lovable, this file (${fileEntry.path}) was found in the project. Ask the AI to ensure no credentials are hardcoded and that environment variables are used instead.`,
          ));
        }
      }

      // Deep inspect: download and scan file content (requires consent)
      if (config.deepInspect) {
        const targetFiles = files.files.filter(f =>
          !f.binary &&
          (f.path.endsWith('.ts') || f.path.endsWith('.js') ||
           f.path.endsWith('.tsx') || f.path.endsWith('.jsx') ||
           f.path.endsWith('.env') || f.path.endsWith('.toml') ||
           f.path.endsWith('.json'))
        ).slice(0, 20); // Limit to avoid excessive API calls

        for (const fileEntry of targetFiles) {
          const { content } = await client.getFileContent(project.id, fileEntry.path);
          if (!content) continue;

          // Secret scan
          const secretMatches = scanForSecrets(content, fileEntry.path);
          for (const match of secretMatches) {
            findings.push(makeFinding(
              match.patternId, 'hardcoded_secret',
              match.isServiceRole ? 'catastrophic' : match.severity,
              match.label,
              `Potential secret detected in ${fileEntry.path}`,
              `${match.masked} (${fileEntry.path}:${match.lineNumber})`,
              'Remove this credential from source code immediately and rotate it.',
              match.aiPrompt,
              { hash: match.hash, file: fileEntry.path, line: match.lineNumber },
            ));
          }

          // PII scan
          const piiMatches = scanForPII(content, fileEntry.path);
          for (const match of piiMatches) {
            findings.push(makeFinding(
              match.patternId, 'pii_in_code', match.severity,
              `PII Detected: ${match.label}`,
              `Personal Identifiable Information found in ${fileEntry.path}`,
              `${match.masked} (${fileEntry.path}:${match.lineNumber})`,
              'Remove or anonymize PII from source code.',
              'In Lovable, ask the AI to refactor this code to not hardcode personal information. Use environment variables or fetch data from a properly secured database.',
              { hash: match.hash, file: fileEntry.path, line: match.lineNumber },
            ));
          }

          // Extract Supabase credentials for RLS check
          if (!config.supabaseUrl) {
            const extractedUrl = extractSupabaseUrl(content);
            const extractedKey = extractSupabaseAnonKey(content);
            if (extractedUrl) config.supabaseUrl = extractedUrl;
            if (extractedKey) config.supabaseAnonKey = extractedKey;
          }
        }
      }
    }
  }

  // ---- Chat scan (if chat endpoint accessible) ----
  const chatAccessible = bolaChatProbe.signature === 'vulnerable' || bolaChatProbe.signature === 'owner_only';
  if (chatAccessible && config.includeChat) {
    onProgress?.(`  Scanning chat history...`);

    const { messages } = await client.getProjectMessages(project.id);
    if (messages?.events) {
      chatMessagesScanned = messages.events.length;

      for (const message of messages.events) {
        if (!message.content) continue;

        const secretMatches = scanForSecrets(message.content, `chat:${message.id}`);
        for (const match of secretMatches) {
          findings.push(makeFinding(
            match.patternId, 'pii_in_chat',
            match.isServiceRole ? 'catastrophic' : match.severity,
            `${match.label} in AI Chat History`,
            `A potential credential was found in the AI conversation history. This data may be accessible via BOLA vulnerability.`,
            `${match.masked} (chat message ${message.id})`,
            'Rotate this credential immediately. Never share API keys or passwords in AI chat prompts.',
            match.aiPrompt,
            { hash: match.hash },
          ));
        }
      }
    }
  }

  // ---- Supabase RLS check ----
  if (config.testRLS && config.supabaseUrl && config.supabaseAnonKey) {
    onProgress?.(`  Testing Supabase RLS...`);

    const { masked } = maskSecret(config.supabaseAnonKey);
    const supaResult = await scanSupabase(
      config.supabaseUrl,
      config.supabaseAnonKey,
      undefined,
      10, // limit for CLI speed
    );

    if (supaResult.isServiceRole) {
      findings.push(makeFinding(
        'DB-012', 'service_role_exposed', 'catastrophic',
        'CATASTROPHIC: Supabase service_role Key in Frontend',
        'The provided key decodes to role=service_role, which bypasses ALL Row Level Security policies. This is the most critical possible Supabase misconfiguration.',
        `Key type: service_role (${supaResult.anonKeyMasked}) — Project: ${supaResult.credentialSummary.projectRef}`,
        'Rotate this key IMMEDIATELY in Supabase dashboard. Remove from frontend code. Never use service_role in client-side JavaScript.',
        'URGENT: In your Supabase dashboard, go to Settings > API and regenerate your service_role key. In Lovable, ask the AI to refactor all database operations to use the anon key with proper RLS policies instead of service_role.',
      ));
    }

    for (const tableResult of supaResult.tablesProbed) {
      if (tableResult.rlsStatus === 'exposed' || tableResult.rlsStatus === 'partial') {
        const severity = tableResult.severity as Finding['severity'];
        findings.push(makeFinding(
          'LOV-002', 'rls_missing', severity,
          `RLS Missing/Permissive: Table "${tableResult.table}"`,
          `The "${tableResult.table}" table returned ${tableResult.totalCount} rows when queried with the anon key without authentication. ${tableResult.sensitiveFields.length > 0 ? `Sensitive fields exposed: ${tableResult.sensitiveFields.join(', ')}` : ''}`,
          `${tableResult.rowCount} rows returned (total: ${tableResult.totalCount})`,
          'Enable Row Level Security and add appropriate policies.',
          `In Lovable, ask the AI: "Please enable Row Level Security on the ${tableResult.table} table and add policies so users can only access their own data. Use (select auth.uid()) = user_id as the USING clause."`,
          {
            remediationSql: tableResult.remediationSql,
          },
        ));
      }
    }

    if (supaResult.storageExposed) {
      findings.push(makeFinding(
        'DB-011', 'storage_bucket_exposed', 'critical',
        `Storage Bucket Exposed: ${supaResult.storageDetails.join(', ')}`,
        `Supabase Storage buckets are accessible without authentication.`,
        `Buckets: ${supaResult.storageDetails.join(', ')}`,
        'Configure storage.objects RLS policies to restrict access.',
        `In Lovable, ask the AI: "Please add Row Level Security policies to the Supabase storage.objects table to restrict bucket '${supaResult.storageDetails[0]}' access to authenticated users only."`,
      ));
    }
  }

  // ---- Security Headers (if URL provided) ----
  if (config.testHeaders && config.targetUrl) {
    onProgress?.(`  Checking security headers...`);
    const headersResult = await checkSecurityHeaders(config.targetUrl);

    if (!headersResult.csp || !headersResult.hsts || !headersResult.xContentTypeOptions) {
      findings.push(makeFinding(
        'APP-009', 'security_headers', 'medium',
        `Security Headers Missing (Grade ${headersResult.grade})`,
        `Missing headers: ${headersResult.missing.join(', ')}`,
        `Security Headers Score: ${headersResult.score}/100 (${headersResult.grade})`,
        'Add the missing security headers to your deployment configuration.',
        `In Lovable, ask the AI: "Please add security headers to this application including Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options: nosniff, and X-Frame-Options: DENY. Configure these in the Vercel/deployment settings."`,
      ));
    }

    if (headersResult.sourceMapsExposed) {
      findings.push(makeFinding(
        'APP-010', 'source_map_exposed', 'high',
        'Source Maps Exposed in Production',
        'JavaScript source maps are publicly accessible, revealing your original unminified source code.',
        `Source map accessible at ${config.targetUrl}`,
        'Disable source map generation in production builds.',
        'In Lovable, ask the AI: "Please configure the Vite build to not generate source maps in production. Add `build: { sourcemap: false }` to vite.config.ts"',
      ));
    }
  }

  // ---- Deduplicate findings by hash ----
  const seen = new Set<string>();
  const deduped = findings.filter(f => {
    const key = f.hash || `${f.ruleId}:${f.evidence}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // ---- Score ----
  const { score, rationale } = calculateRiskScore(
    deduped,
    isActive,
    isPreNov2025,
    filesAccessible,
    chatAccessible,
  );

  const severity = getSeverityFromScore(score);
  const lovableLevel = getLovableLevelRequired(deduped);

  return {
    projectId: project.id,
    projectName: project.name,
    createdAt: project.created_at,
    updatedAt: project.updated_at,
    isPreNov2025,
    scanTimestamp: new Date().toISOString(),
    riskScore: score,
    severity,
    lovableLevel,
    findings: deduped,
    rationale,
    filesScanned,
    chatMessagesScanned,
    scanDurationMs: Date.now() - startTime,
    bolaFilesProbe,
    bolaChatProbe,
    supabaseDetected: !!(config.supabaseUrl),
    supabaseUrl: config.supabaseUrl,
    supabaseAnonKey: config.supabaseAnonKey ? maskSecret(config.supabaseAnonKey).masked : undefined,
    rlsStatus: 'unknown',
    sourceMapsExposed: false,
  };
}

// ---- Main scan orchestrator ----

export async function runScan(
  config: ScannerConfig,
  onProgress?: (msg: string) => void,
): Promise<{ results: ProjectScanResult[]; summary: ScanSummary }> {
  const scanStart = new Date().toISOString();
  const startMs = Date.now();
  const results: ProjectScanResult[] = [];

  if (!config.lovableToken) {
    throw new Error('Lovable token is required. Set --token or LOVABLE_TOKEN env var.');
  }

  const client = new LovableAPIClient(config.lovableToken, config.scanDelay, config.verbose);

  onProgress?.('🔍 Validating Lovable token...');
  const { valid } = await client.validateToken();
  if (!valid) {
    throw new Error('Invalid or expired Lovable token. Get a fresh token from browser DevTools → Network → api.lovable.dev → Authorization: Bearer ...');
  }

  onProgress?.('📋 Fetching project list...');
  let projects = await client.listProjects();

  if (config.projectIds?.length) {
    projects = projects.filter(p => config.projectIds!.includes(p.id));
  }

  onProgress?.(`Found ${projects.length} projects. Starting scan...`);

  for (let i = 0; i < projects.length; i++) {
    const project = projects[i];
    onProgress?.(`\n[${i + 1}/${projects.length}] ${project.name}`);

    try {
      const result = await scanProject(project, client, { ...config }, onProgress);
      results.push(result);
    } catch (err) {
      onProgress?.(`  ⚠️  Error scanning ${project.name}: ${(err as Error).message}`);
    }
  }

  // Build summary
  const summary: ScanSummary = {
    totalProjects: projects.length,
    scannedProjects: results.length,
    catastrophicCount: results.filter(r => r.severity === 'catastrophic').length,
    criticalCount: results.filter(r => r.severity === 'critical').length,
    highCount: results.filter(r => r.severity === 'high').length,
    mediumCount: results.filter(r => r.severity === 'medium').length,
    lowCount: results.filter(r => r.severity === 'low').length,
    cleanCount: results.filter(r => r.severity === 'clean').length,
    preNov2025Count: results.filter(r => r.isPreNov2025).length,
    bolaVulnerableCount: results.filter(r =>
      r.bolaFilesProbe.signature === 'vulnerable' ||
      r.bolaChatProbe.signature === 'vulnerable' ||
      r.bolaFilesProbe.signature === 'owner_only' ||
      r.bolaChatProbe.signature === 'owner_only'
    ).length,
    topFindings: results.flatMap(r => r.findings)
      .sort((a, b) => {
        const order = { catastrophic: 5, critical: 4, high: 3, medium: 2, low: 1, info: 0 };
        return (order[b.severity as keyof typeof order] || 0) - (order[a.severity as keyof typeof order] || 0);
      })
      .slice(0, 10),
    scanStartTime: scanStart,
    scanEndTime: new Date().toISOString(),
    totalDurationMs: Date.now() - startMs,
  };

  return { results, summary };
}
