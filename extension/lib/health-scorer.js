// ============================================================
// Risk Scorer
// ============================================================

export function computeRiskScore(result) {
  let score = 0;

  // --- Endpoint exposure ---
  if (result.probeResults && result.probeResults.length) {
    // Signature-aware scoring (from skill-dual-probe)
    for (const r of result.probeResults) {
      if (r.signature !== 'vulnerable') continue;
      if (r.label === 'GitFilesResponse' || r.label === 'GetProjectFile') score += 60;
      else if (r.label === 'GetProjectMessagesOutputBody') score += 60;
      else if (r.label === 'GetProject') score += 30;
    }
  } else {
    // Legacy fallback (demo data / pre-dual-probe scans)
    if (result.bolaFileStatus === 'vulnerable') score += 60;
    if (result.bolaChatStatus === 'vulnerable') score += 60;
  }

  // --- Content findings ---
  for (const f of result.findings) {
    if (f.severity === 'critical') score += 30;
    else if (f.severity === 'high') score += 20;
    else if (f.severity === 'medium') score += 10;
  }

  // --- RLS (extension-specific; roadmap keeps RLS as checklist only) ---
  if (result.rlsStatus === 'missing') score += 40;

  // --- Temporal signal: recently edited and not all-patched → +10 ---
  // Uses updatedAt (last edit), NOT createdAt (creation date).
  // Bonus is zeroed when every probe is patched (project is clean).
  const allPatched = result.probeResults?.length > 0
    && result.probeResults.every(r => r.signature === 'patched');
  const daysSinceEdit = (Date.now() - new Date(result.updatedAt).getTime()) / 86400000;
  if (daysSinceEdit < 30 && !allPatched) score += 10;

  return Math.min(100, score);
}


export function getSeverity(score) {
  if (score >= 80) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 20) return 'medium';
  if (score > 0) return 'low';
  return 'clean';
}

export function getSeverityColor(sev) {
  const m = { critical: '#ff4757', high: '#ff8c42', medium: '#ffd32a', low: '#3498db', clean: '#2ed573' };
  return m[sev] || '#888';
}

export function getSeverityLabel(sev) {
  const { t } = await_i18n();
  return t ? t(`severity.${sev}`) : sev;
}

// Lazy import to avoid circular dependency — caller provides t()
let _t = null;
export function setTranslator(fn) { _t = fn; }
function await_i18n() { return { t: _t }; }
