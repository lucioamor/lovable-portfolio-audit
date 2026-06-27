// ============================================================
// @nxlv/shield — Deep RLS Checklist (DB-003/004/005/008/009)
// ============================================================
// pg_policies / pg_class introspection CANNOT be done with the anon key, and
// the roadmap (§9) forbids running SQL automatically against third-party
// Supabase projects. So this is a strict COPY-PASTE model:
//
//   1. renderChecklist() prints read-only audit SQL.
//   2. The user runs it in their own Supabase SQL editor.
//   3. They paste the JSON result back; classifyRlsAudit() classifies it.
//
// Nothing here ever connects to Supabase.
// ============================================================

import { randomUUID } from 'crypto';
import type { Finding, Severity, ScanVector } from '../types.js';
import type { RLSPolicyCheck } from './supabase-engine.js';

// ---- The audit query (single statement → single JSON cell, easy to paste) ----

export const RLS_AUDIT_SQL = `-- nxlv-shield deep RLS audit (read-only introspection)
-- Run in Supabase SQL Editor, then copy the single 'audit' cell value.
select jsonb_build_object(
  'policies', (select coalesce(jsonb_agg(p), '[]'::jsonb) from (
     select schemaname, tablename, policyname, cmd,
            roles::text as roles, permissive,
            qual as using_expr, with_check as with_check_expr
     from pg_policies
     where schemaname not in ('pg_catalog','information_schema')) p),
  'tables', (select coalesce(jsonb_agg(t), '[]'::jsonb) from (
     select n.nspname as schema, c.relname as table_name,
            c.relrowsecurity as rls_enabled, c.relforcerowlevel as force_rls
     from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where c.relkind = 'r'
       and n.nspname not in ('pg_catalog','information_schema')) t),
  'grants', (select coalesce(jsonb_agg(g), '[]'::jsonb) from (
     select table_schema, table_name, grantee, privilege_type
     from information_schema.role_table_grants
     where grantee in ('anon','authenticated','public')
       and table_schema not in ('pg_catalog','information_schema')) g),
  'roles', (select coalesce(jsonb_agg(r), '[]'::jsonb) from (
     select rolname, rolbypassrls, rolsuper
     from pg_roles
     where rolbypassrls or rolsuper) r)
) as audit;`;

export function renderChecklist(): string {
  return [
    '═══════════════════════════════════════════════════════════',
    '  🛡️  NXLV Shield — Deep RLS Checklist (copy-paste audit)',
    '═══════════════════════════════════════════════════════════',
    '',
    'This audits RLS depth (DB-003/004/005/008/009) WITHOUT touching your',
    'database from this tool. Steps:',
    '',
    '  1. Open your Supabase project → SQL Editor.',
    '  2. Run the query below (it is read-only).',
    '  3. Copy the value of the single "audit" cell into a file, e.g. rls.json',
    '  4. Classify it:  nxlv-shield scan --rls-result rls.json',
    '',
    '----------------------------- SQL -------------------------------',
    RLS_AUDIT_SQL,
    '-----------------------------------------------------------------',
    '',
    'Checks performed on the pasted result:',
    '  • DB-003  USING (true) tautological policy',
    '  • DB-004  UPDATE/ALL policy missing WITH CHECK',
    '  • DB-005  RLS enabled but FORCE ROW LEVEL SECURITY absent',
    '  • DB-008  table privileges granted to public (or anon writes)',
    '  • DB-009  non-default roles with BYPASSRLS / SUPERUSER',
    '',
  ].join('\n');
}

// ---- Pasted-result shapes ----

export interface RlsPolicyRow {
  schemaname?: string;
  tablename?: string;
  policyname?: string;
  cmd?: string;              // SELECT | INSERT | UPDATE | DELETE | ALL
  roles?: string;
  permissive?: string;       // PERMISSIVE | RESTRICTIVE
  using_expr?: string | null;
  with_check_expr?: string | null;
}
export interface RlsTableRow {
  schema?: string;
  table_name?: string;
  rls_enabled?: boolean;
  force_rls?: boolean;
}
export interface RlsGrantRow {
  table_schema?: string;
  table_name?: string;
  grantee?: string;
  privilege_type?: string;   // SELECT | INSERT | UPDATE | DELETE | ...
}
export interface RlsRoleRow {
  rolname?: string;
  rolbypassrls?: boolean;
  rolsuper?: boolean;
}
export interface RlsAuditInput {
  policies: RlsPolicyRow[];
  tables: RlsTableRow[];
  grants: RlsGrantRow[];
  roles: RlsRoleRow[];
}

/**
 * Tolerant parse: accepts the raw object, the Supabase single-row array
 * [{ audit: {...} }], a bare { audit: {...} }, or a stringified JSON cell.
 */
export function parseRlsResult(raw: string): RlsAuditInput {
  let data: unknown;
  try {
    data = JSON.parse(raw.trim());
  } catch {
    throw new Error('RLS result is not valid JSON. Paste the value of the "audit" cell exactly.');
  }

  // Unwrap [{ audit: {...} }] or { audit: {...} }
  if (Array.isArray(data)) data = data[0];
  if (data && typeof data === 'object' && 'audit' in (data as Record<string, unknown>)) {
    data = (data as Record<string, unknown>).audit;
  }
  // audit cell may itself be a JSON string
  if (typeof data === 'string') {
    try { data = JSON.parse(data); } catch { /* leave as-is → fails below */ }
  }

  const obj = (data ?? {}) as Record<string, unknown>;
  return {
    policies: Array.isArray(obj.policies) ? (obj.policies as RlsPolicyRow[]) : [],
    tables: Array.isArray(obj.tables) ? (obj.tables as RlsTableRow[]) : [],
    grants: Array.isArray(obj.grants) ? (obj.grants as RlsGrantRow[]) : [],
    roles: Array.isArray(obj.roles) ? (obj.roles as RlsRoleRow[]) : [],
  };
}

// ---- Classification ----

/** Normalize a policy expression for tautology detection: lowercased, paren/space-stripped. */
export function normalizeExpr(expr: string | null | undefined): string {
  if (expr === null || expr === undefined) return '';
  return String(expr).toLowerCase().replace(/\s+/g, '').replace(/^\(+|\)+$/g, '');
}

function isTautology(expr: string | null | undefined): boolean {
  return normalizeExpr(expr) === 'true';
}

const DEFAULT_BYPASS_ROLES = new Set(['postgres', 'supabase_admin', 'supabase_auth_admin', 'supabase_storage_admin', 'rds_superuser']);
const WRITE_PRIVS = new Set(['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']);

function lovableLevelFor(sev: Severity): Finding['lovableLevel'] {
  return sev === 'catastrophic' || sev === 'critical' ? 'L0' : sev === 'high' ? 'L1' : 'L2';
}

function mkFinding(
  ruleId: string, vector: ScanVector, severity: Severity,
  title: string, description: string, evidence: string,
  recommendation: string, aiPrompt: string, remediationSql?: string,
): Finding {
  return {
    id: randomUUID(), ruleId, vector, severity, confidence: 'confirmed',
    lovableLevel: lovableLevelFor(severity),
    title, description, evidence, recommendation, aiPrompt, remediationSql,
  };
}

export interface RlsClassification {
  findings: Finding[];
  policyChecks: RLSPolicyCheck[];  // per-table aggregate — wires the real hasUsingTrue
}

export function classifyRlsAudit(input: RlsAuditInput): RlsClassification {
  const findings: Finding[] = [];

  // ---- Per-table aggregate (this is what wires the formerly-phantom flags) ----
  const byTable = new Map<string, RLSPolicyCheck>();
  const tableKey = (schema: string | undefined, table: string | undefined) => `${schema || 'public'}.${table || '?'}`;

  const tableInfo = new Map<string, RlsTableRow>();
  for (const t of input.tables) tableInfo.set(tableKey(t.schema, t.table_name), t);

  const ensure = (schema: string | undefined, table: string | undefined): RLSPolicyCheck => {
    const key = tableKey(schema, table);
    let chk = byTable.get(key);
    if (!chk) {
      const info = tableInfo.get(key);
      chk = {
        table: key,
        hasRLS: info?.rls_enabled ?? false,
        hasPolicies: false,
        hasUsingTrue: false,
        hasMissingWithCheck: false,
        hasForceRLS: info?.force_rls ?? false,
      };
      byTable.set(key, chk);
    }
    return chk;
  };
  // Seed from table list so tables without policies are represented.
  for (const t of input.tables) ensure(t.schema, t.table_name);

  // ---- DB-003 / DB-004 from policies ----
  for (const p of input.policies) {
    const chk = ensure(p.schemaname, p.tablename);
    chk.hasPolicies = true;
    const cmd = (p.cmd || '').toUpperCase();

    if (isTautology(p.using_expr)) {
      chk.hasUsingTrue = true;
      findings.push(mkFinding(
        'DB-003', 'rls_permissive', 'high',
        `Tautological RLS policy: USING (true) on "${chk.table}"`,
        `Policy "${p.policyname}" (${cmd || 'ALL'}) uses USING (true), which matches every row — RLS is effectively disabled for this command.`,
        `${chk.table} · policy ${p.policyname} · cmd=${cmd || 'ALL'} · USING=(true)`,
        'Replace USING (true) with an ownership/tenant predicate, e.g. (select auth.uid()) = user_id.',
        `In Lovable, ask the AI: "The RLS policy ${p.policyname} on ${chk.table} uses USING (true) which exposes all rows. Replace it with a policy that restricts rows to the authenticated owner using (select auth.uid()) = user_id."`,
      ));
    }

    // DB-004: UPDATE/ALL policy that has a USING clause but no WITH CHECK.
    const isWriteScoped = cmd === 'UPDATE' || cmd === 'ALL' || cmd === '';
    const hasUsing = (p.using_expr ?? '') !== '';
    const missingWithCheck = (p.with_check_expr ?? null) === null || normalizeExpr(p.with_check_expr) === '';
    if (isWriteScoped && hasUsing && missingWithCheck) {
      chk.hasMissingWithCheck = true;
      findings.push(mkFinding(
        'DB-004', 'rls_permissive', 'high',
        `UPDATE policy missing WITH CHECK on "${chk.table}"`,
        `Policy "${p.policyname}" (${cmd || 'UPDATE'}) has a USING clause but no WITH CHECK. Rows can be mutated into a state that the USING predicate would otherwise forbid (e.g. reassigning user_id).`,
        `${chk.table} · policy ${p.policyname} · cmd=${cmd || 'UPDATE'} · WITH CHECK=missing`,
        'Add a WITH CHECK clause mirroring the USING predicate.',
        `In Lovable, ask the AI: "Add a WITH CHECK clause to the UPDATE policy ${p.policyname} on ${chk.table} that mirrors its USING predicate, so users cannot reassign rows they don't own."`,
      ));
    }
  }

  // ---- DB-005: RLS on but FORCE RLS absent (+ RLS fully disabled) ----
  for (const chk of byTable.values()) {
    if (!chk.hasRLS) {
      findings.push(mkFinding(
        'DB-002', 'rls_missing', 'high',
        `Row Level Security disabled on "${chk.table}"`,
        'The table has RLS disabled — any role with table privileges reads/writes every row.',
        `${chk.table} · rls_enabled=false`,
        'Enable RLS and add ownership policies.',
        `In Lovable, ask the AI: "Enable Row Level Security on ${chk.table} and add policies restricting access to the row owner."`,
        `ALTER TABLE ${chk.table} ENABLE ROW LEVEL SECURITY;\nALTER TABLE ${chk.table} FORCE ROW LEVEL SECURITY;`,
      ));
    } else if (!chk.hasForceRLS) {
      findings.push(mkFinding(
        'DB-005', 'rls_missing', 'medium',
        `FORCE ROW LEVEL SECURITY absent on "${chk.table}"`,
        'RLS is enabled but not forced. The table owner (and definer-rights functions) bypass RLS, which can defeat policies in practice.',
        `${chk.table} · rls_enabled=true · force_rls=false`,
        'Run ALTER TABLE ... FORCE ROW LEVEL SECURITY.',
        `In Lovable, ask the AI: "Run ALTER TABLE ${chk.table} FORCE ROW LEVEL SECURITY so the table owner cannot bypass RLS policies."`,
        `ALTER TABLE ${chk.table} FORCE ROW LEVEL SECURITY;`,
      ));
    }
  }

  // ---- DB-008: grants to public / anon writes ----
  for (const g of input.grants) {
    const grantee = (g.grantee || '').toLowerCase();
    const priv = (g.privilege_type || '').toUpperCase();
    const key = tableKey(g.table_schema, g.table_name);
    if (grantee === 'public') {
      findings.push(mkFinding(
        'DB-008', 'rls_permissive', 'high',
        `Privilege granted to PUBLIC on "${key}"`,
        `${priv} is granted to PUBLIC, exposing the table to every role regardless of RLS intent.`,
        `${key} · grantee=public · ${priv}`,
        'Revoke from public; grant only to anon/authenticated as needed with RLS enforced.',
        `In Lovable, ask the AI: "Revoke ${priv} on ${key} from PUBLIC and grant it only to the roles that need it, with RLS enforced."`,
        `REVOKE ${priv} ON ${key} FROM PUBLIC;`,
      ));
    } else if (grantee === 'anon' && WRITE_PRIVS.has(priv)) {
      findings.push(mkFinding(
        'DB-008', 'rls_permissive', 'high',
        `anon role can ${priv} "${key}"`,
        `The anonymous role holds ${priv} on this table. Combined with weak RLS this allows unauthenticated writes.`,
        `${key} · grantee=anon · ${priv}`,
        'Revoke write privileges from anon; restrict to authenticated with ownership policies.',
        `In Lovable, ask the AI: "Revoke ${priv} on ${key} from the anon role so anonymous visitors cannot modify data."`,
        `REVOKE ${priv} ON ${key} FROM anon;`,
      ));
    }
  }

  // ---- DB-009: non-default roles with BYPASSRLS / SUPERUSER ----
  for (const r of input.roles) {
    const name = (r.rolname || '').toLowerCase();
    if (DEFAULT_BYPASS_ROLES.has(name)) continue;
    if (r.rolbypassrls || r.rolsuper) {
      findings.push(mkFinding(
        'DB-009', 'service_role_exposed', 'high',
        `Role "${r.rolname}" bypasses RLS`,
        `Role has ${r.rolsuper ? 'SUPERUSER' : 'BYPASSRLS'}. Any client connecting as this role ignores all RLS policies.`,
        `role=${r.rolname} · bypassrls=${!!r.rolbypassrls} · super=${!!r.rolsuper}`,
        'Remove BYPASSRLS/SUPERUSER from application-facing roles. Reserve it for trusted admin tooling only.',
        `In Lovable, ask the AI: "Ensure the role ${r.rolname} used by the app does not have BYPASSRLS or SUPERUSER, so RLS policies are always enforced."`,
      ));
    }
  }

  return { findings, policyChecks: [...byTable.values()] };
}
