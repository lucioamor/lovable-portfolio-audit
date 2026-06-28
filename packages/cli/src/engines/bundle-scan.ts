// ============================================================
// @nxlv-ai/lovable-audit — Bundle / Runtime Scanner (P8/P9 · WS-4)
// ============================================================
// Read-only GETs of a deployed Lovable app to detect, in the shipped bundle:
//   • inline source maps (//# sourceMappingURL=data:...) — source exposed even
//     when no .map file is served (B1).
//   • external <script>/<link> without Subresource Integrity (B1 · SRI).
//   • Supabase project URL + anon/publishable key embedded in a chunk (B2),
//     which feeds the compound-risk correlation with the RLS checklist (A1).
//
// No credentials are used; nothing is written; raw bodies are never persisted.
// ============================================================

import { extractSupabaseUrl, extractSupabaseAnonKey } from './supabase-engine.js';
import { maskSecret, isServiceRoleJwt } from './patterns.js';

export interface SriIssue {
  url: string;
  tag: 'script' | 'link';
}

export interface BundleScanResult {
  url: string;
  reachable: boolean;
  sourceMapInline: boolean;          // data: URI map embedded in a chunk
  sourceMapExternalRefs: string[];   // //# sourceMappingURL=foo.js.map references
  scriptsWithoutSri: SriIssue[];
  chunksScanned: number;
  supabaseUrl?: string;
  supabaseAnonKeyMasked?: string;
  supabaseAnonKeyRaw?: string;       // returned for downstream RLS probe only — not persisted
  supabaseKeyIsServiceRole?: boolean;
}

const UA = 'nxlv-audit/0.1.0 (security-audit; read-only)';

async function getText(url: string, timeoutMs = 10000): Promise<{ ok: boolean; text: string; origin: string }> {
  try {
    const res = await fetch(url, { method: 'GET', headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(timeoutMs) });
    const text = res.ok ? await res.text() : '';
    return { ok: res.ok, text, origin: new URL(url).origin };
  } catch {
    return { ok: false, text: '', origin: '' };
  }
}

/** Extract external <script src> / <link href> lacking integrity= (cross-origin only). */
export function findMissingSri(html: string, pageUrl: string): SriIssue[] {
  const issues: SriIssue[] = [];
  let pageOrigin = '';
  try { pageOrigin = new URL(pageUrl).origin; } catch { /* noop */ }

  const tagRe = /<(script|link)\b[^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(html)) !== null) {
    const tag = m[1].toLowerCase() as 'script' | 'link';
    const attrs = m[0];
    const srcMatch = attrs.match(/\b(?:src|href)\s*=\s*["']([^"']+)["']/i);
    if (!srcMatch) continue;
    const ref = srcMatch[1];
    if (!/^https?:\/\//i.test(ref)) continue; // only absolute external refs

    // links: only subresource types that support SRI
    if (tag === 'link') {
      const rel = (attrs.match(/\brel\s*=\s*["']([^"']+)["']/i)?.[1] || '').toLowerCase();
      if (!/stylesheet|preload|modulepreload/.test(rel)) continue;
    }

    let refOrigin = '';
    try { refOrigin = new URL(ref).origin; } catch { continue; }
    if (refOrigin === pageOrigin) continue; // same-origin → lower risk, skip

    if (!/\bintegrity\s*=/i.test(attrs)) {
      issues.push({ url: ref, tag });
    }
  }
  return issues;
}

/** Collect same-origin JS chunk URLs referenced by the HTML (bounded). */
export function findChunkUrls(html: string, pageUrl: string, limit = 6): string[] {
  const urls = new Set<string>();
  const re = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+\.js)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null && urls.size < limit) {
    try { urls.add(new URL(m[1], pageUrl).toString()); } catch { /* noop */ }
  }
  return [...urls];
}

const SOURCEMAP_RE = /\/\/[#@]\s*sourceMappingURL=(\S+)/g;

export async function scanBundle(pageUrl: string, opts: { maxChunks?: number } = {}): Promise<BundleScanResult> {
  const result: BundleScanResult = {
    url: pageUrl,
    reachable: false,
    sourceMapInline: false,
    sourceMapExternalRefs: [],
    scriptsWithoutSri: [],
    chunksScanned: 0,
  };

  const page = await getText(pageUrl);
  if (!page.ok) return result;
  result.reachable = true;

  result.scriptsWithoutSri = findMissingSri(page.text, pageUrl);

  const chunks = findChunkUrls(page.text, pageUrl, opts.maxChunks ?? 6);
  for (const chunkUrl of chunks) {
    const chunk = await getText(chunkUrl);
    if (!chunk.ok) continue;
    result.chunksScanned += 1;

    // Source map references inside the body (inline data: or external file).
    SOURCEMAP_RE.lastIndex = 0;
    let sm: RegExpExecArray | null;
    while ((sm = SOURCEMAP_RE.exec(chunk.text)) !== null) {
      const ref = sm[1];
      if (ref.startsWith('data:')) result.sourceMapInline = true;
      else result.sourceMapExternalRefs.push(new URL(ref, chunkUrl).toString());
    }

    // Supabase URL + anon key embedded in the bundle.
    if (!result.supabaseUrl) {
      const u = extractSupabaseUrl(chunk.text);
      if (u) result.supabaseUrl = u;
    }
    if (!result.supabaseAnonKeyRaw) {
      const k = extractSupabaseAnonKey(chunk.text);
      if (k) {
        result.supabaseAnonKeyRaw = k;
        result.supabaseAnonKeyMasked = maskSecret(k).masked;
        result.supabaseKeyIsServiceRole = isServiceRoleJwt(k);
      }
    }
  }

  return result;
}
