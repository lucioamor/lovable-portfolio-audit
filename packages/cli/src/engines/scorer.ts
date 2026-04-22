// ============================================================
// @nxlv/shield — Risk Scorer (expanded with rationale + LOV levels)
// ============================================================

import type { Finding, ProjectScanResult, RationaleEntry, LovableLevel, Severity } from '../types.js';

interface ScoringWeights {
  bola_files_vulnerable: number;
  bola_chat_vulnerable: number;
  catastrophic_finding: number;
  critical_finding: number;
  high_finding: number;
  medium_finding: number;
  low_finding: number;
  rls_missing: number;
  rls_permissive: number;
  service_role_exposed: number;
  storage_exposed: number;
  source_maps_exposed: number;
  active_project_30d: number;
  pre_nov2025: number;
}

const WEIGHTS: ScoringWeights = {
  bola_files_vulnerable:   60,
  bola_chat_vulnerable:    60,
  catastrophic_finding:    50,
  critical_finding:        30,
  high_finding:            20,
  medium_finding:          10,
  low_finding:              5,
  rls_missing:             30,
  rls_permissive:          20,
  service_role_exposed:    50,
  storage_exposed:         25,
  source_maps_exposed:     10,
  active_project_30d:      10,
  pre_nov2025:              5,
};

const SEVERITY_THRESHOLDS = {
  catastrophic: 120,
  critical: 80,
  high: 50,
  medium: 20,
  low: 1,
};

export function calculateRiskScore(
  findings: Finding[],
  isActive: boolean,
  isPreNov2025: boolean,
  bolaFilesVulnerable: boolean,
  bolaChatVulnerable: boolean,
): { score: number; rationale: RationaleEntry[] } {
  const rationale: RationaleEntry[] = [];
  let score = 0;

  const addPoints = (ruleId: string, vector: Finding['vector'], points: number, reason: string) => {
    score += points;
    rationale.push({ ruleId, vector, points, reason });
  };

  // BOLA probes
  if (bolaFilesVulnerable) {
    addPoints('LOV-001', 'bola_files', WEIGHTS.bola_files_vulnerable,
      'Files endpoint returned HTTP 200 — project files accessible without ownership check');
  }
  if (bolaChatVulnerable) {
    addPoints('LOV-001', 'bola_chat', WEIGHTS.bola_chat_vulnerable,
      'Chat endpoint returned HTTP 200 — AI conversation history accessible without ownership check');
  }

  // Per-finding scoring
  for (const finding of findings) {
    let points = 0;
    switch (finding.severity) {
      case 'catastrophic': points = WEIGHTS.catastrophic_finding; break;
      case 'critical':     points = WEIGHTS.critical_finding; break;
      case 'high':         points = WEIGHTS.high_finding; break;
      case 'medium':       points = WEIGHTS.medium_finding; break;
      case 'low':          points = WEIGHTS.low_finding; break;
    }

    // Special escalation for specific vectors
    if (finding.vector === 'service_role_exposed') {
      points = WEIGHTS.service_role_exposed;
    } else if (finding.vector === 'rls_missing') {
      points = WEIGHTS.rls_missing;
    } else if (finding.vector === 'rls_permissive') {
      points = WEIGHTS.rls_permissive;
    } else if (finding.vector === 'storage_bucket_exposed') {
      points = WEIGHTS.storage_exposed;
    } else if (finding.vector === 'source_map_exposed') {
      points = WEIGHTS.source_maps_exposed;
    }

    if (points > 0) {
      addPoints(finding.ruleId, finding.vector, points,
        `${finding.severity.toUpperCase()}: ${finding.title}`);
    }
  }

  // Context modifiers
  if (isActive) {
    addPoints('CTX-001', 'bola_files', WEIGHTS.active_project_30d,
      'Project was edited in the last 30 days — active exposure');
  }
  if (isPreNov2025) {
    addPoints('LOV-006', 'pre_nov2025', WEIGHTS.pre_nov2025,
      'Project created before November 2025 — potentially affected by BOLA vulnerability window');
  }

  return { score, rationale };
}

export function getSeverityFromScore(score: number): ProjectScanResult['severity'] {
  if (score >= SEVERITY_THRESHOLDS.catastrophic) return 'catastrophic';
  if (score >= SEVERITY_THRESHOLDS.critical) return 'critical';
  if (score >= SEVERITY_THRESHOLDS.high) return 'high';
  if (score >= SEVERITY_THRESHOLDS.medium) return 'medium';
  if (score > 0) return 'low';
  return 'clean';
}

export function getLovableLevelRequired(findings: Finding[]): LovableLevel {
  if (findings.some(f => f.lovableLevel === 'L2')) return 'L2';
  if (findings.some(f => f.lovableLevel === 'L1')) return 'L1';
  return 'L0';
}

export function getSeverityEmoji(severity: Severity | 'clean'): string {
  switch (severity) {
    case 'catastrophic': return '💀';
    case 'critical':     return '🔴';
    case 'high':         return '🟠';
    case 'medium':       return '🟡';
    case 'low':          return '🔵';
    case 'clean':        return '🟢';
    default:             return '⚪';
  }
}

export function getSeverityColor(severity: Severity | 'clean'): string {
  switch (severity) {
    case 'catastrophic': return '#ff0033';
    case 'critical':     return '#ff2e4c';
    case 'high':         return '#ff8c00';
    case 'medium':       return '#ffc107';
    case 'low':          return '#6ec6ff';
    case 'clean':        return '#4caf50';
    default:             return '#aaaaaa';
  }
}
