// ============================================================
// @nxlv/shield — Supabase Security Engine
// ============================================================
// Checks: DB-001..015, APP-009 (security headers), LOV-002
// DAST uses anon key only — read-only, no data modification.
// ============================================================

import { createHash } from 'crypto';
import { maskSecret, isServiceRoleJwt, decodeJwtPayload } from './patterns.js';

export interface SupabaseProbeResult {
  url: string;
  table: string;
  status: number;
  rowCount: number;
  totalCount: number;
  rlsStatus: 'exposed' | 'partial' | 'protected' | 'error' | 'not_found';
  severity: 'catastrophic' | 'critical' | 'high' | 'medium' | 'low' | 'ok';
  sensitiveFields: string[];
  remediationSql: string;
}

export interface RLSPolicyCheck {
  table: string;
  hasRLS: boolean;
  hasPolicies: boolean;
  hasUsingTrue: boolean;    // DB-003
  hasMissingWithCheck: boolean; // DB-004
  hasForceRLS: boolean;     // DB-005
}

export interface SupabaseScanResult {
  url: string;
  anonKeyMasked: string;
  anonKeyHash: string;
  isServiceRole: boolean;   // CATASTROPHIC if true
  tablesProbed: SupabaseProbeResult[];
  storageExposed: boolean;
  storageDetails: string[];
  credentialSummary: {
    keyType: 'anon' | 'service_role' | 'unknown';
    projectRef: string;
  };
}

// Common table names to probe when .from() patterns not available
const COMMON_TABLES = [
  'users', 'profiles', 'accounts', 'sessions', 'orders', 'payments',
  'subscriptions', 'messages', 'notifications', 'settings', 'api_keys',
  'tokens', 'logs', 'events', 'products', 'categories', 'comments',
  'posts', 'files', 'documents', 'organizations', 'teams', 'roles',
  'permissions', 'invitations', 'transactions', 'invoices', 'customers',
];

const SENSITIVE_FIELD_NAMES = [
  'email', 'password', 'token', 'secret', 'key', 'ssn', 'cpf', 'cnpj',
  'credit_card', 'card_number', 'phone', 'address', 'birth_date', 'dob',
  'api_key', 'stripe_id', 'customer_id', 'bank_account', 'routing',
];

// ---- Supabase credential extraction ----

export function extractSupabaseUrl(code: string): string | null {
  const patterns = [
    /createClient\s*\(\s*["'`](https:\/\/[a-z0-9]+\.supabase\.co)["'`]/i,
    /VITE_SUPABASE_URL\s*[:=]\s*["'`]?(https:\/\/[a-z0-9]+\.supabase\.co)/i,
    /NEXT_PUBLIC_SUPABASE_URL\s*[:=]\s*["'`]?(https:\/\/[a-z0-9]+\.supabase\.co)/i,
    /(https:\/\/[a-z0-9]{20,}\.supabase\.co)/i,
  ];

  for (const pattern of patterns) {
    const match = code.match(pattern);
    if (match) return match[1];
  }
  return null;
}

export function extractProjectRef(url: string): string {
  const match = url.match(/https:\/\/([a-z0-9]+)\.supabase\.co/i);
  return match?.[1] || 'unknown';
}

export function extractSupabaseAnonKey(code: string): string | null {
  const patterns = [
    /createClient\s*\([^,]+,\s*["'`](eyJ[A-Za-z0-9_.-]{50,})["'`]/i,
    /VITE_SUPABASE_ANON_KEY\s*[:=]\s*["'`]?(eyJ[A-Za-z0-9_.-]{50,})["'`]?/i,
    /NEXT_PUBLIC_SUPABASE_ANON_KEY\s*[:=]\s*["'`]?(eyJ[A-Za-z0-9_.-]{50,})["'`]?/i,
    /["']apikey["']\s*:\s*["'`](eyJ[A-Za-z0-9_.-]{50,})["'`]/i,
  ];

  for (const pattern of patterns) {
    const match = code.match(pattern);
    if (match) return match[1];
  }
  return null;
}

// ---- Table discovery from JS bundles ----

export function discoverTablesFromCode(code: string): string[] {
  const tables = new Set<string>(COMMON_TABLES);

  // .from("tableName") or .from('tableName')
  const fromPattern = /\.from\s*\(\s*["'`]([a-zA-Z_][a-zA-Z0-9_]*)["'`]\s*\)/g;
  let match: RegExpExecArray | null;
  while ((match = fromPattern.exec(code)) !== null) {
    tables.add(match[1]);
  }

  // supabase.storage.from('bucket')
  const storagePattern = /storage\.from\s*\(\s*["'`]([a-zA-Z_][a-zA-Z0-9_-]*)["'`]\s*\)/g;
  while ((match = storagePattern.exec(code)) !== null) {
    tables.add(`storage:${match[1]}`);
  }

  return [...tables];
}

// ---- Remote RLS Probing ----

/**
 * Probe a Supabase table with the anon key to test RLS.
 * Read-only: SELECT only, no data modification.
 * Prefer: count=exact header to get total row count without fetching all data.
 */
async function probeTable(
  supabaseUrl: string,
  anonKey: string,
  tableName: string,
): Promise<SupabaseProbeResult> {
  const result: SupabaseProbeResult = {
    url: supabaseUrl,
    table: tableName,
    status: 0,
    rowCount: 0,
    totalCount: 0,
    rlsStatus: 'error',
    severity: 'ok',
    sensitiveFields: [],
    remediationSql: '',
  };

  try {
    // Fetch limited rows to check access, using count=exact to determine total
    const response = await fetch(
      `${supabaseUrl}/rest/v1/${tableName}?select=*&limit=5`,
      {
        method: 'GET',
        headers: {
          'apikey': anonKey,
          'Authorization': `Bearer ${anonKey}`,
          'Content-Type': 'application/json',
          'Prefer': 'count=exact',
        },
        signal: AbortSignal.timeout(10000),
      },
    );

    result.status = response.status;

    const contentRange = response.headers.get('content-range');
    const total = contentRange ? parseInt(contentRange.split('/')[1] || '0') : 0;
    result.totalCount = isNaN(total) ? 0 : total;

    if (response.ok) {
      const data = await response.json() as Record<string, unknown>[];
      result.rowCount = data.length;

      if (result.totalCount > 100 || result.rowCount >= 5) {
        result.rlsStatus = 'exposed';
        result.severity = 'critical';
      } else if (result.rowCount > 0 || result.totalCount > 0) {
        result.rlsStatus = 'partial';
        result.severity = 'high';
      } else {
        result.rlsStatus = 'protected';
        result.severity = 'ok';
      }

      // Check for sensitive fields in first row
      if (data.length > 0) {
        const sampleRow = data[0];
        result.sensitiveFields = Object.keys(sampleRow).filter(k =>
          SENSITIVE_FIELD_NAMES.some(sf => k.toLowerCase().includes(sf))
        );

        // Escalate if sensitive fields are exposed
        if (result.sensitiveFields.length > 0 && result.rlsStatus === 'exposed') {
          result.severity = 'catastrophic';
        }
      }

      // Generate remediation SQL
      if (result.rlsStatus !== 'protected') {
        result.remediationSql = generateRemediationSql(tableName, 'user-isolated');
      }
    } else if (response.status === 401 || response.status === 403) {
      result.rlsStatus = 'protected';
      result.severity = 'ok';
    } else if (response.status === 404) {
      result.rlsStatus = 'not_found';
    }
  } catch (err) {
    result.rlsStatus = 'error';
    result.severity = 'ok'; // Assume protected if can't reach
  }

  return result;
}

/**
 * Probe Supabase storage buckets.
 * Checks common bucket names for public access.
 */
async function probeStorage(supabaseUrl: string, anonKey: string): Promise<{
  exposed: boolean;
  buckets: string[];
}> {
  const exposedBuckets: string[] = [];
  const commonBuckets = ['avatars', 'uploads', 'images', 'documents', 'files', 'media', 'public', 'attachments'];

  for (const bucket of commonBuckets) {
    try {
      const response = await fetch(
        `${supabaseUrl}/storage/v1/object/list/${bucket}`,
        {
          method: 'GET',
          headers: {
            'apikey': anonKey,
            'Authorization': `Bearer ${anonKey}`,
          },
          signal: AbortSignal.timeout(5000),
        },
      );

      if (response.ok) {
        const data = await response.json() as unknown[];
        if (Array.isArray(data) && data.length > 0) {
          exposedBuckets.push(bucket);
        }
      }
    } catch {
      // Silently skip — network error means protected
    }
  }

  return { exposed: exposedBuckets.length > 0, buckets: exposedBuckets };
}

// ---- Remediation SQL Generator (from 0xsrb/supabase-ext pattern) ----

export function generateRemediationSql(
  tableName: string,
  pattern: 'user-isolated' | 'public-readonly' | 'multi-tenant' | 'generic',
): string {
  switch (pattern) {
    case 'user-isolated':
      return `-- Enable RLS and add user-isolation policy for: ${tableName}
ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tableName} FORCE ROW LEVEL SECURITY;

CREATE POLICY "${tableName}_user_select" ON ${tableName}
  FOR SELECT USING ((select auth.uid()) = user_id);

CREATE POLICY "${tableName}_user_insert" ON ${tableName}
  FOR INSERT WITH CHECK ((select auth.uid()) = user_id);

CREATE POLICY "${tableName}_user_update" ON ${tableName}
  FOR UPDATE USING ((select auth.uid()) = user_id)
  WITH CHECK ((select auth.uid()) = user_id);

CREATE POLICY "${tableName}_user_delete" ON ${tableName}
  FOR DELETE USING ((select auth.uid()) = user_id);`;

    case 'multi-tenant':
      return `-- Enable RLS with multi-tenant isolation for: ${tableName}
ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tableName} FORCE ROW LEVEL SECURITY;

CREATE POLICY "${tableName}_tenant_select" ON ${tableName}
  FOR SELECT USING (
    organization_id IN (
      SELECT organization_id FROM user_organizations
      WHERE user_id = (select auth.uid())
    )
  );`;

    case 'public-readonly':
      return `-- Enable RLS with public read-only access for: ${tableName}
ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;

CREATE POLICY "${tableName}_public_read" ON ${tableName}
  FOR SELECT USING (true);

-- All writes require authentication
CREATE POLICY "${tableName}_auth_write" ON ${tableName}
  FOR ALL USING ((select auth.uid()) IS NOT NULL)
  WITH CHECK ((select auth.uid()) IS NOT NULL);`;

    default:
      return `-- Enable RLS for: ${tableName}
ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tableName} FORCE ROW LEVEL SECURITY;
-- TODO: Add appropriate policies based on your access requirements`;
  }
}

// ---- Main Supabase Scanner ----

export async function scanSupabase(
  supabaseUrl: string,
  anonKey: string,
  codeContent?: string,
  maxTables = 20,
): Promise<SupabaseScanResult> {
  const { masked: anonKeyMasked, hash: anonKeyHash } = maskSecret(anonKey);
  const isServiceRole = isServiceRoleJwt(anonKey);
  const projectRef = extractProjectRef(supabaseUrl);

  // Determine key type
  const payload = decodeJwtPayload(anonKey);
  const keyType = isServiceRole ? 'service_role' : (payload?.role === 'anon' ? 'anon' : 'unknown');

  // Discover tables from code if available
  const tables = codeContent
    ? discoverTablesFromCode(codeContent).slice(0, maxTables)
    : COMMON_TABLES.slice(0, maxTables);

  // Filter out storage entries
  const regularTables = tables.filter(t => !t.startsWith('storage:'));

  // Probe tables (rate-limited)
  const tablesProbed: SupabaseProbeResult[] = [];
  for (const table of regularTables) {
    const result = await probeTable(supabaseUrl, anonKey, table);
    // Only include non-404 results
    if (result.rlsStatus !== 'not_found') {
      tablesProbed.push(result);
    }
    // Rate limit between probes
    await new Promise(r => setTimeout(r, 300));
  }

  // Probe storage
  const storageResult = await probeStorage(supabaseUrl, anonKey);

  return {
    url: supabaseUrl,
    anonKeyMasked,
    anonKeyHash,
    isServiceRole,
    tablesProbed,
    storageExposed: storageResult.exposed,
    storageDetails: storageResult.buckets,
    credentialSummary: { keyType: keyType as 'anon' | 'service_role' | 'unknown', projectRef },
  };
}

// ---- Security Headers Check (APP-009) ----

export interface SecurityHeadersResult {
  url: string;
  csp: boolean;
  hsts: boolean;
  xFrameOptions: boolean;
  xContentTypeOptions: boolean;
  referrerPolicy: boolean;
  permissionsPolicy: boolean;
  sourceMapsExposed: boolean;
  score: number;          // 0–100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  missing: string[];
}

export async function checkSecurityHeaders(url: string): Promise<SecurityHeadersResult> {
  const missing: string[] = [];
  let sourceMapsExposed = false;

  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'User-Agent': 'nxlv-shield/0.1.0 (security-audit; read-only)' },
      signal: AbortSignal.timeout(10000),
    });

    const headers = response.headers;

    const csp = headers.has('content-security-policy');
    const hsts = headers.has('strict-transport-security');
    const xFrameOptions = headers.has('x-frame-options') || (headers.get('content-security-policy') || '').includes('frame-ancestors');
    const xContentTypeOptions = headers.get('x-content-type-options') === 'nosniff';
    const referrerPolicy = headers.has('referrer-policy');
    const permissionsPolicy = headers.has('permissions-policy') || headers.has('feature-policy');

    if (!csp) missing.push('Content-Security-Policy');
    if (!hsts) missing.push('Strict-Transport-Security');
    if (!xFrameOptions) missing.push('X-Frame-Options / frame-ancestors CSP');
    if (!xContentTypeOptions) missing.push('X-Content-Type-Options: nosniff');
    if (!referrerPolicy) missing.push('Referrer-Policy');
    if (!permissionsPolicy) missing.push('Permissions-Policy');

    // Check for source maps (APP-010)
    // Try to find a .js URL from the page and probe for .map
    const text = await response.text().catch(() => '');
    const jsMatch = text.match(/src=["']([^"']+\.js)["']/);
    if (jsMatch) {
      const jsUrl = new URL(jsMatch[1], url).toString();
      try {
        const mapResponse = await fetch(`${jsUrl}.map`, {
          method: 'HEAD',
          signal: AbortSignal.timeout(5000),
        });
        sourceMapsExposed = mapResponse.ok;
      } catch {
        sourceMapsExposed = false;
      }
    }

    const score = Math.round(
      ([csp, hsts, xFrameOptions, xContentTypeOptions, referrerPolicy, permissionsPolicy]
        .filter(Boolean).length / 6) * 100
    );

    const grade =
      score >= 90 ? 'A' :
      score >= 75 ? 'B' :
      score >= 60 ? 'C' :
      score >= 40 ? 'D' : 'F';

    return { url, csp, hsts, xFrameOptions, xContentTypeOptions, referrerPolicy, permissionsPolicy, sourceMapsExposed, score, grade, missing };
  } catch (err) {
    return {
      url, csp: false, hsts: false, xFrameOptions: false,
      xContentTypeOptions: false, referrerPolicy: false, permissionsPolicy: false,
      sourceMapsExposed: false, score: 0, grade: 'F',
      missing: ['Could not connect to URL'],
    };
  }
}
