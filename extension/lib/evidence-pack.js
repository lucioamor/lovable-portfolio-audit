// ============================================================
// HMAC-SHA256 Signed Evidence Export (Chrome Extension)
// Pure, no fetch, no chrome.* calls inside core crypto functions
// ============================================================

const PACK_VERSION = 'nxlv-evidence-pack/v1';

/**
 * Generate an HMAC-SHA256 key from a passphrase using PBKDF2.
 * If no passphrase given, uses a deterministic device key from a random uuid
 * stored in chrome.storage.
 */
export async function deriveSigningKey(passphrase) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode('lpa-evidence-v1'), iterations: 100000, hash: 'SHA-256' },
    base,
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign', 'verify']
  );
}

/**
 * Build and sign an evidence pack.
 * Returns { pack: object, payload: string, signature: hex string }
 */
export async function buildEvidencePack(results, summary, signingKey) {
  const pack = {
    version: PACK_VERSION,
    generated_at: new Date().toISOString(),
    tool: 'lovable-portfolio-audit',
    tool_version: '1.0.0',
    summary: {
      total_projects: summary.totalProjects,
      scanned_projects: summary.scannedProjects,
      critical: summary.criticalCount,
      high: summary.highCount,
      medium: summary.mediumCount,
      low: summary.lowCount,
      clean: summary.cleanCount,
      scan_start: summary.scanStartTime,
      scan_end: summary.scanEndTime,
    },
    findings: results.map(r => ({
      project_id: r.projectId,
      project_name: r.projectName,
      severity: r.severity,
      risk_score: r.riskScore,
      probe_results: r.probeResults || [],
      bola_proof: r.bolaProof || [],
      findings: r.findings.map(f => ({
        id: f.id,
        rule_id: f.ruleId,
        severity: f.severity,
        title: f.title,
        vector: f.vector,
        source: f.source,
        evidence: f.evidence,          // masked only
        secret_hash: f.secret_hash,    // sha256[:16], never raw
        line: f.line,
        recommendation: f.recommendation,
      })),
      supabase_detected: r.supabaseDetected,
      files_scanned: r.filesScanned,
      chat_messages_scanned: r.chatMessagesScanned,
    })),
  };

  const payload = JSON.stringify(pack, null, 2);
  const sig = await crypto.subtle.sign(
    'HMAC',
    signingKey,
    new TextEncoder().encode(payload)
  );
  const sigHex = Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return { pack, payload, signature: sigHex };
}

/**
 * Verify a previously exported pack.
 * Returns true/false.
 */
export async function verifyEvidencePack(payload, sigHex, signingKey) {
  const sigBytes = new Uint8Array(sigHex.match(/.{2}/g).map(h => parseInt(h, 16)));
  return crypto.subtle.verify('HMAC', signingKey, sigBytes, new TextEncoder().encode(payload));
}
