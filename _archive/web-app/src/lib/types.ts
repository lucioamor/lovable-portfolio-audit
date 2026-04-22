// ============================================================
// Lovable Security Scanner — Type Definitions
// ============================================================

export interface SecretPattern {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  regex: RegExp;
  label: string;
  description: string;
}

export interface PIIPattern {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  regex: RegExp;
  label: string;
}

export interface SensitiveFilePath {
  path: string;
  severity: 'critical' | 'high' | 'medium';
  reason: string;
}

export interface SecurityRules {
  secretPatterns: SecretPattern[];
  piiPatterns: PIIPattern[];
  sensitiveFilePaths: SensitiveFilePath[];
  riskWeights: RiskWeights;
  severityThresholds: SeverityThresholds;
}

export interface RiskWeights {
  unauthorized_file_access_200: number;
  unauthorized_chat_access_200: number;
  critical_secret_match: number;
  high_secret_match: number;
  pii_match: number;
  active_project_30d: number;
}

export interface SeverityThresholds {
  critical_min: number;
  high_min: number;
  medium_min: number;
}

// ---- Lovable API Types ----

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
  contains_error?: boolean;
  current_page?: string;
  graph_id?: string;
}

export interface LovableMessagesResponse {
  $schema: string;
  events: LovableChatMessage[];
}

// ---- Scan Result Types ----

export interface Finding {
  id: string;
  vector: ScanVector;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  evidence: string; // masked
  file?: string;
  line?: number;
  recommendation: string;
}

export type ScanVector =
  | 'bola_files'
  | 'bola_chat'
  | 'hardcoded_secret'
  | 'rls_missing'
  | 'pii_in_code'
  | 'pii_in_chat'
  | 'sensitive_file';

export interface ProjectScanResult {
  projectId: string;
  projectName: string;
  createdAt: string;
  updatedAt: string;
  scanTimestamp: string;
  riskScore: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'clean';
  findings: Finding[];
  filesScanned: number;
  chatMessagesScanned: number;
  scanDurationMs: number;
  bolaFileStatus: 'vulnerable' | 'protected' | 'unknown';
  bolaChatStatus: 'vulnerable' | 'protected' | 'unknown';
  supabaseDetected: boolean;
  supabaseUrl?: string;
  rlsStatus?: 'missing' | 'partial' | 'enabled' | 'unknown';
}

export interface ScanSummary {
  totalProjects: number;
  scannedProjects: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  cleanCount: number;
  topFindings: Finding[];
  scanStartTime: string;
  scanEndTime: string;
  totalDurationMs: number;
}

export interface ScannerConfig {
  lovableToken: string;
  scanDelay: number; // ms between API calls
  maxConcurrent: number;
  includeChat: boolean;
  includeFiles: boolean;
  testRLS: boolean;
  projectFilter?: string[]; // specific project IDs
}

export type ScanStatus = 'idle' | 'running' | 'paused' | 'completed' | 'error';

export interface ScanProgress {
  status: ScanStatus;
  currentProject: string;
  currentProjectIndex: number;
  totalProjects: number;
  percentage: number;
  findings: number;
  errors: string[];
}
