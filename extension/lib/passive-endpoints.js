// ============================================================
// Passive sensor — Lovable endpoint registry (P7 5th-endpoint detection)
// ============================================================
// Pure, dependency-free. Single source of truth for the known Lovable API
// surface. The page-context interceptor mirrors normalizeLovablePath() inline
// (it cannot import in page world); keep the two in sync.
// ============================================================

// The 4 documented endpoints + the project-list call, normalized.
export const KNOWN_ENDPOINTS = Object.freeze([
  '/user/projects',
  '/projects/:id',
  '/projects/:id/messages',
  '/projects/:id/git/files',
  '/projects/:id/git/files/:file',
]);

const KNOWN_SET = new Set(KNOWN_ENDPOINTS);

/** Collapse ids so distinct paths normalize to a stable shape. */
export function normalizeLovablePath(urlStr, base = 'https://api.lovable.dev') {
  let pathname;
  try {
    pathname = new URL(urlStr, base).pathname;
  } catch {
    pathname = String(urlStr).split('?')[0];
  }
  let p = pathname;
  p = p.replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/:id'); // uuid
  p = p.replace(/\/git\/files\/.+$/i, '/git/files/:file');
  p = p.replace(/\/\d+(?=\/|$)/g, '/:n');
  return p;
}

export function isKnownEndpoint(normalizedPath) {
  return KNOWN_SET.has(normalizedPath);
}
