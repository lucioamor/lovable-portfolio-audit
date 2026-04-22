// ============================================================
// @nxlv/shield — Core Types (expanded from src/lib/types.ts)
// ============================================================

// ---- Rule DSL Types ----

export type RuleType = 'sast' | 'secret' | 'dast' | 'config' | 'lovable';
export type LovableLevel = 'L0' | 'L1' | 'L2';
export type Confidence = 'confirmed' | 'likely' | 'blocked' | 'noise';
export type Severity = 'catastrophic' | 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SecretPattern {
  id: string;
  label: string;
  regex: RegExp;
  severity: Severity;
  description: string;
  lovableLevel: LovableLevel;
  aiPrompt?: string;
}

export interface PIIPattern {
  id: string;
  label: string;
  regex: RegExp;
  severity: Severity;
}

// ---- Finding Types ----

export type ScanVector =
  | 'bola_files'
  | 'bola_chat'
  | 'hardcoded_secret'
  | 'rls_missing'
  | 'rls_permissive'
  | 'service_role_exposed'
  | 'pii_in_code'
  | 'pii_in_chat'
  | 'sensitive_file'
  | 'security_headers'
  | 'source_map_exposed'
  | 'cve_dependency'
  | 'xss_sink'
  | 'sql_injection'
  | 'mcp_poisoning'
  | 'ai_unvalidated_flow'
  | 'storage_bucket_exposed'
  | 'anon_key_irrestrito'
  | 'pre_nov2025'
  | 'pre_nov2025_bola';

export interface Finding {
  id: string;                     // UUID
  ruleId: string;                 // e.g. "LOV-001", "DB-012"
  vector: ScanVector;
  severity: Severity;
  confidence: Confidence;
  lovableLevel: LovableLevel;
  title: string;
  description: string;
  evidence: string;               // ALWAYS masked — never raw value
  hash?: string;                  // SHA-256 of raw value (for dedup)
  file?: string;
  line?: number;
  recommendation: string;
  aiPrompt: string;               // copy-paste for Lovable chat
  remediationSql?: string;        // for Supabase findings
  sarifLocation?: SARIFLocation;
}

export interface SARIFLocation {
  uri: string;
  startLine?: number;
  startColumn?: number;
}

// ---- Project Scan Types ----

export interface LovableProject {
  id: string;
  name: string;
  created_at: string;
  updated_at: string;
  visibility?: 'public' | 'private';
  description?: string;
  last_edited_at?: string;
  edit_count?: number;
}

export interface LovableFileEntry {
  path: string;
  size: number;
  binary: boolean;
}

export interface LovableFilesResponse {
  $schema: string;
  files: LovableFileEntry[];
}

export interface LovableChatMessage {
  id: string;
  created_at: string;
  tag: string;
  role: 'user' | 'ai' | 'system';
  content: string;
  user_id?: string;
}

export interface LovableMessagesResponse {
  $schema: string;
  events: LovableChatMessage[];
}

// ---- Response Signature (dual-probe) ----

// owner_only = owner token got 200, no audit token used — cross-account exposure unconfirmed
// vulnerable  = dual-probe confirmed: audit token also got 200 — BOLA proven cross-account
export type ResponseSignature = 'vulnerable' | 'owner_only' | 'patched' | 'error' | 'unknown';

export interface ProbeResult {
  endpoint: string;
  status: number;
  signature: ResponseSignature;
  contentLengthBytes?: number;
  sha256?: string;                // hash of response body (never the body itself)
}

// ---- Project Scan Result ----

export interface ProjectScanResult {
  projectId: string;
  projectName: string;
  createdAt: string;
  updatedAt: string;
  isPreNov2025: boolean;          // LOV-006: age flag
  scanTimestamp: string;
  riskScore: number;              // 0–100
  severity: 'catastrophic' | 'critical' | 'high' | 'medium' | 'low' | 'clean';
  lovableLevel: LovableLevel;     // highest level required
  findings: Finding[];
  rationale: RationaleEntry[];    // score breakdown (SKILL-06)
  filesScanned: number;
  chatMessagesScanned: number;
  scanDurationMs: number;
  bolaFilesProbe: ProbeResult;
  bolaChatProbe: ProbeResult;
  supabaseDetected: boolean;
  supabaseUrl?: string;
  supabaseAnonKey?: string;       // masked
  rlsStatus?: 'missing' | 'permissive' | 'partial' | 'enabled' | 'unknown';
  securityHeaders?: SecurityHeadersResult;
  sourceMapsExposed: boolean;
}

export interface RationaleEntry {
  ruleId: string;
  vector: ScanVector;
  points: number;
  reason: string;
}

export interface SecurityHeadersResult {
  csp: boolean;
  hsts: boolean;
  xFrameOptions: boolean;
  xContentTypeOptions: boolean;
  referrerPolicy: boolean;
  permissionsPolicy: boolean;
}

export interface ScanSummary {
  totalProjects: number;
  scannedProjects: number;
  catastrophicCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  cleanCount: number;
  preNov2025Count: number;        // LOV-006
  bolaVulnerableCount: number;    // LOV-001
  topFindings: Finding[];
  scanStartTime: string;
  scanEndTime: string;
  totalDurationMs: number;
}

export interface ScannerConfig {
  // Auth
  lovableToken?: string;
  auditToken?: string;             // second account token for dual-probe BOLA confirmation
  supabaseUrl?: string;
  supabaseAnonKey?: string;
  // Scan options
  targetUrl?: string;             // remote URL scan
  projectIds?: string[];          // specific project IDs
  scanDelay: number;              // ms between API calls
  maxConcurrent: number;
  // Feature toggles
  includeChat: boolean;
  includeFiles: boolean;
  testRLS: boolean;
  testHeaders: boolean;
  testSourceMaps: boolean;
  deepInspect: boolean;           // requires explicit consent
  // Output
  outputFormat: 'console' | 'json' | 'sarif' | 'markdown' | 'all';
  outputFile?: string;
  exitCodeOnCritical: boolean;
  // Privacy
  safeMode: boolean;              // default: true
  verbose: boolean;
}
