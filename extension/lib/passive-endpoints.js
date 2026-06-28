// ============================================================
// Passive sensor — Lovable endpoint registry (P7 5th-endpoint detection)
// ============================================================
// Pure, dependency-free. Single source of truth for the known Lovable API
// surface. The page-context interceptor mirrors normalizeLovablePath() inline
// (it cannot import in page world); keep the two in sync.
// ============================================================

// Known Lovable API surface — updated from passive sensor observations.
export const KNOWN_ENDPOINTS = Object.freeze([
  // User / account
  '/user/projects',
  '/user/projects/shared',
  '/user/projects/starred-projects',
  '/user/workspace-invitations',
  '/user/workspaces',
  '/v2/user/projects/shared',
  '/v2/user/projects/starred',
  // Workspace
  '/workspaces/:id/auto-topup/status',
  '/workspaces/:id/cloud-grant-status',
  '/workspaces/:id/connections/gitsync/:id/projects/:id/repo-accessibility',
  '/workspaces/:id/connectors/seamless',
  '/workspaces/:id/credit-balance',
  '/workspaces/:id/credit-limits',
  '/workspaces/:id/folders',
  '/workspaces/:id/memberships/search',
  '/workspaces/:id/project-access-requests',
  '/workspaces/:id/projects/:id/folder',
  '/workspaces/:id/projects/:id/gitsync',
  '/workspaces/:id/projects/search',
  '/workspaces/:id/projects/templates',
  '/workspaces/:id/registrar-domains/viewer-verification-banner',
  '/workspaces/:id/user-monthly-usage',
  '/workspaces/:id/workspace-access-requests',
  // Project
  '/projects/:id',
  '/projects/:id/analytics',
  '/projects/:id/analytics/trend',
  '/projects/:id/auth-token',
  '/projects/:id/cloud/config',
  '/projects/:id/cloud/db-proxy/v1/projects/:ref/database/query',
  '/projects/:id/cloud/db-proxy/v1/projects/:ref/functions',
  '/projects/:id/cloud/exhaustion/status',
  '/projects/:id/cloud/query',
  '/projects/:id/cloud/status',
  '/projects/:id/cloud/storage/buckets',
  '/projects/:id/collaborators',
  '/projects/:id/documents',
  '/projects/:id/edits',
  '/projects/:id/git/files',
  '/projects/:id/git/files/:file',
  '/projects/:id/health-check-findings/brief',
  '/projects/:id/health-checks/schedule',
  '/projects/:id/integrations/ai_gateway',
  '/projects/:id/integrations/roadmap',
  '/projects/:id/integrations/shopify',
  '/projects/:id/mark-viewed',
  '/projects/:id/messages',
  '/projects/:id/payments/integration-status',
  '/projects/:id/presence',
  '/projects/:id/sandbox/start',
  '/projects/:id/sandbox/url',
  '/projects/:id/security/data',
  '/projects/:id/security/hvt-status',
  '/projects/:id/seo-review',
  '/projects/:id/workspace',
  // Workspace (observed live, previously uncatalogued)
  '/workspaces/:id/ai-grant-status',
  '/workspaces/:id/lovable-cloud-monthly-usage',
  '/workspaces/:id/skills',
  // Global
  '/beta/tester-self/my-invites',
  '/consent/policy',
  '/files/generate-download-url',
  '/permissions',
  '/profile/:username',
  '/surveys/active',
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
  p = p.replace(/\/workspaces\/[A-Za-z0-9_-]+/g, '/workspaces/:id'); // any workspace ID (base62 or workspace_xxx)
  // Supabase project ref inside the cloud db-proxy path. Collapse it so the ref
  // (a real third-party identifier) never lands in observed-endpoint storage or
  // the "redacted" diagnostic report.
  p = p.replace(/(\/cloud\/db-proxy\/v\d+\/projects\/)[a-z0-9]{16,}/gi, '$1:ref');
  p = p.replace(/\/git\/files\/.+$/i, '/git/files/:file');
  // Public profile handle — /profile/<username> → /profile/:username, so the
  // three observed /profile/<name> variants collapse to the one known endpoint
  // instead of masquerading as unknown "new surface".
  p = p.replace(/\/profile\/[^/]+/i, '/profile/:username');
  p = p.replace(/\/\d+(?=\/|$)/g, '/:n');
  return p;
}

export function isKnownEndpoint(normalizedPath) {
  return KNOWN_SET.has(normalizedPath);
}
