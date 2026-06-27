// ============================================================
// Masking helpers — pure, no fetch, no chrome.*, no regex
// Aligned with SECURITY-ROADMAP §5.4
// ============================================================

/**
 * Mask a secret for display.
 *   length <= 12: first 3 chars + bullets
 *   else:         first 4 + bullets (filling to original length) + last 4
 */
export function maskSecret(value) {
  if (!value || typeof value !== 'string') return '•••';
  
  const len = value.length;
  if (len <= 3) return '•'.repeat(len);
  
  if (len <= 12) {
    return value.slice(0, 3) + '•'.repeat(len - 3);
  }
  
  return value.slice(0, 4) + '•'.repeat(len - 8) + value.slice(-4);
}

/**
 * sha256(value) → hex string → first 16 chars.
 * Uses Web Crypto API (available in MV3 service workers and extension pages).
 * Used ONLY for deduplication — never as a reversible identifier.
 */
export async function hashSecret(value) {
  if (!value || typeof value !== 'string') return '';
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(value)
  );
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 16);
}

/**
 * Compute 1-based line number for a match at byte offset `idx` within `content`.
 */
export function lineNumber(content, idx) {
  if (idx < 0 || idx > content.length) return 1;
  return (content.slice(0, idx).match(/\n/g) || []).length + 1;
}
