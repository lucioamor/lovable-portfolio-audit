// ============================================================
// Lovable Security Scanner — Risk Scorer
// ============================================================

import { SECURITY_RULES } from './data-patterns';
import type { Finding, ProjectScanResult } from './types';

/**
 * Calculate risk score for a set of findings
 */
export function calculateRiskScore(findings: Finding[], isActiveProject: boolean): number {
  const weights = SECURITY_RULES.riskWeights;
  let score = 0;

  for (const finding of findings) {
    switch (finding.vector) {
      case 'bola_files':
        score += weights.unauthorized_file_access_200;
        break;
      case 'bola_chat':
        score += weights.unauthorized_chat_access_200;
        break;
      case 'hardcoded_secret':
        score += finding.severity === 'critical'
          ? weights.critical_secret_match
          : weights.high_secret_match;
        break;
      case 'pii_in_code':
      case 'pii_in_chat':
        score += weights.pii_match;
        break;
      case 'rls_missing':
        score += weights.critical_secret_match;
        break;
      case 'sensitive_file':
        score += finding.severity === 'critical'
          ? weights.critical_secret_match
          : weights.high_secret_match;
        break;
    }
  }

  if (isActiveProject) {
    score += weights.active_project_30d;
  }

  // Cap at 100
  return Math.min(score, 100);
}

/**
 * Determine severity level from score
 */
export function getSeverityFromScore(score: number): ProjectScanResult['severity'] {
  const thresholds = SECURITY_RULES.severityThresholds;
  if (score >= thresholds.critical_min) return 'critical';
  if (score >= thresholds.high_min) return 'high';
  if (score >= thresholds.medium_min) return 'medium';
  if (score > 0) return 'low';
  return 'clean';
}

/**
 * Get severity color for UI display
 */
export function getSeverityColor(severity: ProjectScanResult['severity']): string {
  switch (severity) {
    case 'critical': return '#ff2e4c';
    case 'high': return '#ff8c00';
    case 'medium': return '#ffc107';
    case 'low': return '#6ec6ff';
    case 'clean': return '#4caf50';
  }
}

/**
 * Get severity emoji
 */
export function getSeverityEmoji(severity: ProjectScanResult['severity']): string {
  switch (severity) {
    case 'critical': return '🔴';
    case 'high': return '🟠';
    case 'medium': return '🟡';
    case 'low': return '🔵';
    case 'clean': return '🟢';
  }
}

/**
 * Get severity label in Portuguese
 */
export function getSeverityLabel(severity: ProjectScanResult['severity']): string {
  switch (severity) {
    case 'critical': return 'Crítico';
    case 'high': return 'Alto';
    case 'medium': return 'Médio';
    case 'low': return 'Baixo';
    case 'clean': return 'Limpo';
  }
}

/**
 * Get vector label in Portuguese
 */
export function getVectorLabel(vector: Finding['vector']): string {
  switch (vector) {
    case 'bola_files': return 'BOLA — Arquivos';
    case 'bola_chat': return 'BOLA — Chat';
    case 'hardcoded_secret': return 'Credencial Exposta';
    case 'rls_missing': return 'RLS Ausente';
    case 'pii_in_code': return 'PII no Código';
    case 'pii_in_chat': return 'PII no Chat';
    case 'sensitive_file': return 'Arquivo Sensível';
  }
}

/**
 * Check if project was edited within last 30 days
 */
export function isActiveProject(updatedAt: string): boolean {
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
  return new Date(updatedAt) > thirtyDaysAgo;
}
