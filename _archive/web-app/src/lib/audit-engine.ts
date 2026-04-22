// ============================================================
// Lovable Security Scanner — Scanner Engine (Orchestrator)
// ============================================================

import { LovableAPIClient } from './lovable-api-client';
import { scanForSecrets, scanForPII, isSensitiveFile } from './data-patterns';
import { calculateRiskScore, getSeverityFromScore, isPreCutoff, isActiveProject } from './health-scorer';
import { extractSupabaseCredentials, testRLS } from './supabase-inspector';
import type {
  ScannerConfig,
  ScanProgress,
  ProjectScanResult,
  ScanSummary,
  Finding,
  LovableProject,
  ScanVector,
} from './types';

type ProgressCallback = (progress: ScanProgress) => void;
type ResultCallback = (result: ProjectScanResult) => void;

export class ScannerEngine {
  private client: LovableAPIClient;
  private config: ScannerConfig;
  private aborted = false;
  private results: ProjectScanResult[] = [];

  constructor(config: ScannerConfig) {
    this.config = config;
    this.client = new LovableAPIClient(config.lovableToken, config.scanDelay);
  }

  /**
   * Abort a running scan
   */
  abort(): void {
    this.aborted = true;
  }

  /**
   * Get all results so far
   */
  getResults(): ProjectScanResult[] {
    return [...this.results];
  }

  /**
   * Generate a unique finding ID
   */
  private findingId(): string {
    return 'f_' + Math.random().toString(36).slice(2, 11);
  }

  /**
   * Run a full scan across all projects
   */
  async runScan(
    onProgress: ProgressCallback,
    onResult: ResultCallback,
  ): Promise<ScanSummary> {
    this.aborted = false;
    this.results = [];
    const startTime = new Date();

    // Step 1: List projects
    onProgress({
      status: 'running',
      currentProject: 'Listando projetos...',
      currentProjectIndex: 0,
      totalProjects: 0,
      percentage: 0,
      findings: 0,
      errors: [],
    });

    let projects: LovableProject[];
    try {
      projects = await this.client.listProjects();
    } catch (err) {
      onProgress({
        status: 'error',
        currentProject: '',
        currentProjectIndex: 0,
        totalProjects: 0,
        percentage: 0,
        findings: 0,
        errors: [`Falha ao listar projetos: ${(err as Error).message}`],
      });
      return this.buildSummary(startTime);
    }

    // Apply filter if provided
    if (this.config.projectFilter && this.config.projectFilter.length > 0) {
      projects = projects.filter(p => this.config.projectFilter!.includes(p.id));
    }

    const totalProjects = projects.length;
    const errors: string[] = [];

    // Step 2: Scan each project
    for (let i = 0; i < projects.length; i++) {
      if (this.aborted) break;

      const project = projects[i];
      const projectName = project.name || project.id;

      onProgress({
        status: 'running',
        currentProject: projectName,
        currentProjectIndex: i + 1,
        totalProjects,
        percentage: Math.round((i / totalProjects) * 100),
        findings: this.results.reduce((sum, r) => sum + r.findings.length, 0),
        errors,
      });

      try {
        const result = await this.scanProject(project);
        this.results.push(result);
        onResult(result);
      } catch (err) {
        errors.push(`Erro em ${projectName}: ${(err as Error).message}`);
      }
    }

    onProgress({
      status: this.aborted ? 'paused' : 'completed',
      currentProject: '',
      currentProjectIndex: totalProjects,
      totalProjects,
      percentage: 100,
      findings: this.results.reduce((sum, r) => sum + r.findings.length, 0),
      errors,
    });

    return this.buildSummary(startTime);
  }

  /**
   * Scan a single project
   */
  async scanProject(project: LovableProject): Promise<ProjectScanResult> {
    const startMs = Date.now();
    const findings: Finding[] = [];
    let filesScanned = 0;
    let chatMessagesScanned = 0;
    let bolaFileStatus: ProjectScanResult['bolaFileStatus'] = 'unknown';
    let bolaChatStatus: ProjectScanResult['bolaChatStatus'] = 'unknown';
    let supabaseDetected = false;
    let supabaseUrl: string | undefined;
    let rlsStatus: ProjectScanResult['rlsStatus'] = 'unknown';

    // Accumulated source code for credential extraction
    let allSourceCode = '';

    // Step A: Test file access (Exposure check)
    if (this.config.includeFiles) {
      const filesResult = await this.client.getProjectFiles(project.id);
      bolaFileStatus = filesResult.status === 200 ? 'vulnerable' : 'protected';

      if (filesResult.status === 200 && filesResult.files) {
        // Exposure vulnerability — files are accessible
        if (isPreCutoff(project.created_at)) {
          findings.push({
            id: this.findingId(),
            vector: 'bola_files',
            severity: 'critical',
            title: 'Exposure: Código-fonte acessível sem autorização',
            description: `O endpoint /projects/${project.id}/git/files retorna 200 OK. O código-fonte deste projeto está potencialmente acessível para qualquer usuário autenticado na plataforma.`,
            evidence: `HTTP ${filesResult.status} — ${filesResult.files.files.length} arquivos listados`,
            recommendation: 'Contate o suporte da Lovable para solicitar a aplicação do patch de ownership check neste projeto. Enquanto isso, rotacione todas as credenciais encontradas no código.',
          });
        }

        // Check for sensitive files in the tree
        for (const file of filesResult.files.files) {
          const sensitive = isSensitiveFile(file.path);
          if (sensitive) {
            findings.push({
              id: this.findingId(),
              vector: 'sensitive_file',
              severity: sensitive.severity,
              title: `Arquivo sensível exposto: ${file.path}`,
              description: sensitive.reason,
              evidence: `${file.path} (${file.size} bytes)`,
              file: file.path,
              recommendation: `Verifique o conteúdo de ${file.path} e remova credenciais hardcoded.`,
            });
          }
        }

        // Download and scan key files for secrets
        const filesToScan = filesResult.files.files.filter(f =>
          !f.binary &&
          f.size < 50000 && // Skip large files
          (f.path.endsWith('.ts') ||
           f.path.endsWith('.tsx') ||
           f.path.endsWith('.js') ||
           f.path.endsWith('.jsx') ||
           f.path.endsWith('.env') ||
           f.path.endsWith('.json') ||
           f.path.endsWith('.toml') ||
           f.path.endsWith('.yml') ||
           f.path.endsWith('.yaml') ||
           f.path.endsWith('.md') ||
           f.path === '.env.local' ||
           f.path === '.env.production' ||
           f.path.includes('supabase/') ||
           f.path.includes('client'))
        );

        // Limit to most important files to avoid rate limiting
        const priorityFiles = filesToScan.slice(0, 30);

        for (const file of priorityFiles) {
          if (this.aborted) break;

          const content = await this.client.getFileContent(project.id, file.path);
          if (content.content) {
            filesScanned++;
            allSourceCode += content.content + '\n';

            // Scan for secrets
            const secretMatches = scanForSecrets(content.content, file.path);
            for (const match of secretMatches) {
              findings.push({
                id: this.findingId(),
                vector: 'hardcoded_secret' as ScanVector,
                severity: match.severity,
                title: `${match.label} em ${file.path}`,
                description: match.description,
                evidence: match.masked,
                file: file.path,
                line: match.line,
                recommendation: `Remova a credencial de ${file.path}, rotacione a chave, e use variáveis de ambiente ou Lovable Cloud Secrets.`,
              });
            }

            // Scan for PII
            const piiMatches = scanForPII(content.content);
            for (const match of piiMatches) {
              findings.push({
                id: this.findingId(),
                vector: 'pii_in_code' as ScanVector,
                severity: match.severity,
                title: `${match.label} em ${file.path}`,
                description: `Dados pessoais encontrados no código-fonte`,
                evidence: match.masked,
                file: file.path,
                recommendation: `Remova dados pessoais hardcoded do código-fonte.`,
              });
            }
          }
        }
      }
    }

    // Step B: Test chat access (Exposure check)
    if (this.config.includeChat) {
      const chatResult = await this.client.getProjectMessages(project.id);
      bolaChatStatus = chatResult.status === 200 ? 'vulnerable' : 'protected';

      if (chatResult.status === 200 && chatResult.messages) {
        if (isPreCutoff(project.created_at)) {
          findings.push({
            id: this.findingId(),
            vector: 'bola_chat',
            severity: 'critical',
            title: 'Exposure: Histórico de chat acessível sem autorização',
            description: `O endpoint /projects/${project.id}/messages retorna 200 OK. Todas as conversas com a IA deste projeto estão potencialmente legíveis.`,
            evidence: `HTTP ${chatResult.status} — ${chatResult.messages.events?.length || 0} mensagens`,
            recommendation: 'Contate o suporte da Lovable. Revise o chat history para identificar credenciais compartilhadas e rotacione-as.',
          });
        }

        // Scan chat messages for secrets and PII
        const events = chatResult.messages.events || [];
        chatMessagesScanned = events.length;

        for (const event of events) {
          if (!event.content) continue;

          const secretMatches = scanForSecrets(event.content);
          for (const match of secretMatches) {
            findings.push({
              id: this.findingId(),
              vector: 'hardcoded_secret' as ScanVector,
              severity: match.severity,
              title: `${match.label} no chat (${event.role})`,
              description: `Credencial encontrada em mensagem de ${event.role} de ${event.created_at}`,
              evidence: match.masked,
              recommendation: `Rotacione esta credencial imediatamente — ela está exposta no histórico de chat.`,
            });
          }

          const piiMatches = scanForPII(event.content);
          for (const match of piiMatches) {
            findings.push({
              id: this.findingId(),
              vector: 'pii_in_chat' as ScanVector,
              severity: match.severity,
              title: `${match.label} no chat (${event.role})`,
              description: `Dados pessoais encontrados em mensagem de ${event.role}`,
              evidence: match.masked,
              recommendation: `Dados pessoais foram compartilhados no chat e podem estar expostos.`,
            });
          }
        }
      }
    }

    // Step C: Supabase RLS check
    if (this.config.testRLS && allSourceCode) {
      const creds = extractSupabaseCredentials(allSourceCode);
      if (creds.url) {
        supabaseDetected = true;
        supabaseUrl = creds.url;

        if (creds.serviceRoleKey) {
          findings.push({
            id: this.findingId(),
            vector: 'hardcoded_secret' as ScanVector,
            severity: 'critical',
            title: 'SUPABASE SERVICE ROLE KEY EXPOSTA NO CÓDIGO',
            description: 'A chave service_role do Supabase está hardcoded no código-fonte. Isso garante acesso TOTAL ao banco de dados, ignorando TODA política RLS.',
            evidence: `${creds.serviceRoleKey.slice(0, 10)}•••`,
            recommendation: 'URGENTE: Rotacione a service_role key IMEDIATAMENTE no Supabase Dashboard. Mova para variáveis de ambiente e use apenas em Edge Functions.',
          });
        }

        if (creds.anonKey) {
          try {
            const rlsResult = await testRLS(creds.url, creds.anonKey);
            rlsStatus = 'unknown'; // Manual audit required
            
            findings.push({
              id: this.findingId(),
              vector: 'rls_missing' as ScanVector,
              severity: 'high',
              title: `Auditoria RLS Manual Necessária`,
              description: `Copie o SQL e rode no seu banco de dados para verificar as políticas RLS.`,
              evidence: `SQL gerado para auditoria manual`,
              recommendation: `Rode no Supabase SQL Editor: \n\n${rlsResult.sqlToRun}`,
            });
          } catch {
            rlsStatus = 'unknown';
          }
        }
      }
    }

    // Deduplicate findings
    const dedupedFindings = this.deduplicateFindings(findings);

    // Calculate risk score
    const active = isActiveProject(project.updated_at || project.created_at);
    const riskScore = calculateRiskScore(dedupedFindings, active);
    const severity = getSeverityFromScore(riskScore);

    return {
      projectId: project.id,
      projectName: project.name || project.id,
      createdAt: project.created_at,
      updatedAt: project.updated_at || project.created_at,
      scanTimestamp: new Date().toISOString(),
      riskScore,
      severity,
      findings: dedupedFindings,
      filesScanned,
      chatMessagesScanned,
      scanDurationMs: Date.now() - startMs,
      bolaFileStatus,
      bolaChatStatus,
      supabaseDetected,
      supabaseUrl,
      rlsStatus,
    };
  }

  /**
   * Deduplicate findings by evidence
   */
  private deduplicateFindings(findings: Finding[]): Finding[] {
    const seen = new Set<string>();
    return findings.filter(f => {
      const key = `${f.vector}:${f.evidence}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  /**
   * Build summary from results
   */
  private buildSummary(startTime: Date): ScanSummary {
    const endTime = new Date();
    const allFindings = this.results.flatMap(r => r.findings);

    return {
      totalProjects: this.results.length,
      scannedProjects: this.results.length,
      criticalCount: this.results.filter(r => r.severity === 'critical').length,
      highCount: this.results.filter(r => r.severity === 'high').length,
      mediumCount: this.results.filter(r => r.severity === 'medium').length,
      lowCount: this.results.filter(r => r.severity === 'low').length,
      cleanCount: this.results.filter(r => r.severity === 'clean').length,
      topFindings: allFindings
        .sort((a, b) => {
          const order = { critical: 0, high: 1, medium: 2, low: 3 };
          return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
        })
        .slice(0, 20),
      scanStartTime: startTime.toISOString(),
      scanEndTime: endTime.toISOString(),
      totalDurationMs: endTime.getTime() - startTime.getTime(),
    };
  }
}

/**
 * Run a quick demo scan with mock data (for testing UI)
 */
export function generateDemoData(): ProjectScanResult[] {
  const now = new Date().toISOString();
  const oldDate = '2025-06-15T10:00:00Z';
  const newDate = '2026-03-01T10:00:00Z';
  const recentEdit = '2026-04-10T14:30:00Z';

  return [
    {
      projectId: 'demo-001',
      projectName: 'Admin Panel v2',
      createdAt: oldDate,
      updatedAt: recentEdit,
      scanTimestamp: now,
      riskScore: 95,
      severity: 'critical',
      findings: [
        { id: 'f1', vector: 'bola_files', severity: 'critical', title: 'Exposure: Código-fonte acessível', description: 'Endpoint retorna 200 OK sem verificação de ownership', evidence: 'HTTP 200 — 47 arquivos', recommendation: 'Contate suporte Lovable' },
        { id: 'f2', vector: 'bola_chat', severity: 'critical', title: 'Exposure: Chat acessível', description: 'Histórico de conversas exposto', evidence: 'HTTP 200 — 312 mensagens', recommendation: 'Contate suporte Lovable' },
        { id: 'f3', vector: 'hardcoded_secret', severity: 'critical', title: 'Supabase Service Role Key em client.ts', description: 'Chave de admin do banco de dados exposta', evidence: 'eyJh•••••Lz1', file: 'src/integrations/supabase/client.ts', line: 19, recommendation: 'Rotacione imediatamente' },
        { id: 'f4', vector: 'rls_missing', severity: 'critical', title: 'RLS ausente: users', description: 'Tabela users acessível sem autenticação', evidence: 'Tabela users retorna dados', recommendation: 'Habilite RLS' },
        { id: 'f5', vector: 'pii_in_chat', severity: 'medium', title: 'Email no chat', description: 'Email encontrado em conversa com IA', evidence: 'admi••••@gma••••', recommendation: 'Revise dados compartilhados' },
      ],
      filesScanned: 23,
      chatMessagesScanned: 312,
      scanDurationMs: 4500,
      bolaFileStatus: 'vulnerable',
      bolaChatStatus: 'vulnerable',
      supabaseDetected: true,
      supabaseUrl: 'https://abc123.supabase.co',
      rlsStatus: 'missing',
    },
    {
      projectId: 'demo-002',
      projectName: 'Landing Page Startup',
      createdAt: oldDate,
      updatedAt: '2025-12-20T10:00:00Z',
      scanTimestamp: now,
      riskScore: 55,
      severity: 'high',
      findings: [
        { id: 'f6', vector: 'bola_files', severity: 'critical', title: 'Exposure: Código-fonte acessível', description: 'Projeto pré-patch retorna 200', evidence: 'HTTP 200 — 18 arquivos', recommendation: 'Contate suporte' },
        { id: 'f7', vector: 'hardcoded_secret', severity: 'high', title: 'OpenAI Key em api.ts', description: 'Chave de API OpenAI exposta', evidence: 'sk-p••••••3xQ', file: 'src/api.ts', line: 5, recommendation: 'Rotacione a chave' },
      ],
      filesScanned: 12,
      chatMessagesScanned: 0,
      scanDurationMs: 2100,
      bolaFileStatus: 'vulnerable',
      bolaChatStatus: 'protected',
      supabaseDetected: false,
      rlsStatus: 'unknown',
    },
    {
      projectId: 'demo-003',
      projectName: 'CRM Dashboard',
      createdAt: oldDate,
      updatedAt: recentEdit,
      scanTimestamp: now,
      riskScore: 40,
      severity: 'medium',
      findings: [
        { id: 'f8', vector: 'sensitive_file', severity: 'high', title: 'Arquivo .env exposto', description: 'Arquivo de variáveis de ambiente na árvore', evidence: '.env (350 bytes)', file: '.env', recommendation: 'Remova secrets do .env' },
        { id: 'f9', vector: 'pii_in_code', severity: 'medium', title: 'LinkedIn URL em seed.ts', description: 'URL do LinkedIn encontrada', evidence: 'link••••.com/in/j••••', file: 'src/seed.ts', recommendation: 'Remova dados de teste com PII real' },
      ],
      filesScanned: 30,
      chatMessagesScanned: 89,
      scanDurationMs: 5200,
      bolaFileStatus: 'protected',
      bolaChatStatus: 'protected',
      supabaseDetected: true,
      supabaseUrl: 'https://xyz789.supabase.co',
      rlsStatus: 'enabled',
    },
    {
      projectId: 'demo-004',
      projectName: 'Blog Pessoal',
      createdAt: newDate,
      updatedAt: recentEdit,
      scanTimestamp: now,
      riskScore: 0,
      severity: 'clean',
      findings: [],
      filesScanned: 15,
      chatMessagesScanned: 45,
      scanDurationMs: 1800,
      bolaFileStatus: 'protected',
      bolaChatStatus: 'protected',
      supabaseDetected: false,
      rlsStatus: 'unknown',
    },
    {
      projectId: 'demo-005',
      projectName: 'E-commerce MVP',
      createdAt: '2025-09-01T10:00:00Z',
      updatedAt: recentEdit,
      scanTimestamp: now,
      riskScore: 88,
      severity: 'critical',
      findings: [
        { id: 'f10', vector: 'bola_files', severity: 'critical', title: 'Exposure: Código-fonte acessível', description: 'Projeto criado set/2025', evidence: 'HTTP 200 — 65 arquivos', recommendation: 'Contate suporte' },
        { id: 'f11', vector: 'hardcoded_secret', severity: 'critical', title: 'Stripe Live Key em payments.ts', description: 'Chave de pagamento real exposta', evidence: 'sk_l••••••9Kz', file: 'src/payments.ts', line: 12, recommendation: 'Rotacione URGENTE' },
        { id: 'f12', vector: 'hardcoded_secret', severity: 'critical', title: 'DB Connection String em config.ts', description: 'String de conexão PostgreSQL', evidence: 'post••••••:543••••', file: 'src/config.ts', recommendation: 'Rotacione credenciais' },
        { id: 'f13', vector: 'rls_missing', severity: 'critical', title: 'RLS ausente: orders', description: 'Tabela de pedidos acessível', evidence: 'Tabela orders sem RLS', recommendation: 'Habilite RLS' },
        { id: 'f14', vector: 'pii_in_chat', severity: 'high', title: 'CPF campo em schema', description: 'Campo de CPF discutido no chat', evidence: 'cpf VARCHAR(14)', recommendation: 'Verifique proteção de dados' },
      ],
      filesScanned: 42,
      chatMessagesScanned: 520,
      scanDurationMs: 8300,
      bolaFileStatus: 'vulnerable',
      bolaChatStatus: 'vulnerable',
      supabaseDetected: true,
      supabaseUrl: 'https://ecom456.supabase.co',
      rlsStatus: 'missing',
    },
  ];
}
