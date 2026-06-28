// ============================================================
// @nxlv/audit — Deep RLS Checklist (DB-003/004/005/008/009)
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

export const RLS_AUDIT_SQL = `-- nxlv-audit deep RLS audit (read-only introspection)
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
            c.relrowsecurity as rls_enabled, c.relforcerowsecurity as force_rls
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
    '  🛡️  NXLV Audit — Deep RLS Checklist (copy-paste audit)',
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

// Schemas Supabase manages on the user's behalf — findings here are real but not
// fixable from the SQL editor, so they are surfaced as collapsed context.
export const SYSTEM_SCHEMAS = new Set([
  'auth', 'storage', 'realtime', 'vault', 'net', 'cron', 'supabase_migrations',
  'pgsodium', 'graphql', 'graphql_public', 'extensions', '_realtime', '_analytics',
  'pgbouncer', 'supabase_functions', 'pgtle',
]);
export const isManagedSchema = (schema: string | undefined): boolean =>
  SYSTEM_SCHEMAS.has(String(schema || '').toLowerCase());
const schemaOf = (key: string): string => String(key || '').split('.')[0];
const tableOf = (key: string): string => String(key || '').split('.').slice(1).join('.');

// Roles Supabase provisions that legitimately bypass RLS (service_role is used by
// your backend by design). Surfaced as context, never as an actionable fix.
const PLATFORM_BYPASS_ROLES = new Set(['service_role', 'supabase_read_only_user', 'supabase_etl_admin', 'supabase_realtime_admin', 'supabase_replication_admin', 'authenticator', 'pgbouncer']);
const isPlatformRole = (name: string): boolean =>
  PLATFORM_BYPASS_ROLES.has(name) || name.startsWith('sandbox_exec') || name.startsWith('supabase_');

// Rolling daily partitions, e.g. realtime.messages_2026_06_27 — regenerate daily.
const DATE_PARTITION_RE = /_(\d{4})_(\d{2})_(\d{2})$/;

const PRIV_ORDER = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'];
const sortPrivs = (privs: string[]): string[] =>
  [...new Set(privs)].sort((a, b) => {
    const ia = PRIV_ORDER.indexOf(a), ib = PRIV_ORDER.indexOf(b);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
  });

function lovableLevelFor(sev: Severity): Finding['lovableLevel'] {
  return sev === 'catastrophic' || sev === 'critical' ? 'L0' : sev === 'high' ? 'L1' : 'L2';
}

type FindingMeta = Partial<Pick<Finding, 'managed' | 'schema' | 'tableName' | 'grantee' | 'privileges' | 'partitionCount'>>;

function mkFinding(
  ruleId: string, vector: ScanVector, severity: Severity,
  title: string, description: string, evidence: string,
  recommendation: string, aiPrompt: string, remediationSql?: string,
  meta: FindingMeta = {},
): Finding {
  return {
    id: randomUUID(), ruleId, vector, severity, confidence: 'confirmed',
    lovableLevel: lovableLevelFor(severity),
    title, description, evidence, recommendation, aiPrompt, remediationSql,
    ...meta,
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
    const schema = schemaOf(chk.table);
    const managed = isManagedSchema(schema);

    if (isTautology(p.using_expr)) {
      chk.hasUsingTrue = true;
      findings.push(mkFinding(
        'DB-003', 'rls_permissive', 'high',
        `Tautological RLS policy: USING (true) on "${chk.table}"`,
        `Policy "${p.policyname}" (${cmd || 'ALL'}) uses USING (true), which matches every row — RLS is effectively disabled for this command.`,
        `${chk.table} · policy ${p.policyname} · cmd=${cmd || 'ALL'} · USING=(true)`,
        'Replace USING (true) with an ownership/tenant predicate, e.g. (select auth.uid()) = user_id.',
        `In Lovable, ask the AI: "The RLS policy ${p.policyname} on ${chk.table} uses USING (true) which exposes all rows. Replace it with a policy that restricts rows to the authenticated owner using (select auth.uid()) = user_id."`,
        undefined,
        { schema, tableName: chk.table, managed },
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
        undefined,
        { schema, tableName: chk.table, managed },
      ));
    }
  }

  // ---- DB-002 / DB-005, with rolling date-partitions collapsed ----
  const rlsIssues: Array<{ ruleId: 'DB-002' | 'DB-005'; table: string }> = [];
  for (const chk of byTable.values()) {
    if (!chk.hasRLS) rlsIssues.push({ ruleId: 'DB-002', table: chk.table });
    else if (!chk.hasForceRLS) rlsIssues.push({ ruleId: 'DB-005', table: chk.table });
  }
  const partitionGroups = new Map<string, { ruleId: 'DB-002' | 'DB-005'; schema: string; base: string; members: string[] }>();
  for (const it of rlsIssues) {
    const schema = schemaOf(it.table);
    const tbl = tableOf(it.table);
    const m = tbl.match(DATE_PARTITION_RE);
    if (isManagedSchema(schema) && m) {
      const base = tbl.slice(0, m.index);
      const gk = `${it.ruleId}|${schema}.${base}`;
      if (!partitionGroups.has(gk)) partitionGroups.set(gk, { ruleId: it.ruleId, schema, base, members: [] });
      partitionGroups.get(gk)!.members.push(it.table);
      continue;
    }
    findings.push(mkRlsIssue(it.ruleId, it.table, schema, isManagedSchema(schema)));
  }
  for (const g of partitionGroups.values()) {
    const repr = `${g.schema}.${g.base}_*`;
    const n = g.members.length;
    if (g.ruleId === 'DB-002') {
      findings.push(mkFinding(
        'DB-002', 'rls_missing', 'high',
        `Row Level Security disabled on "${repr}"`,
        `RLS is disabled on ${n} rolling daily partition(s) of ${g.schema}.${g.base}. These are platform-managed and regenerate daily.`,
        `${repr} · rls_enabled=false · ${n} rolling daily partition(s) collapsed`,
        'Managed by Supabase Realtime — no user action required.',
        `(Context only — ${g.schema}.${g.base} partitions are managed by Supabase.)`,
        undefined,
        { schema: g.schema, tableName: repr, managed: true, partitionCount: n },
      ));
    } else {
      findings.push(mkFinding(
        'DB-005', 'rls_missing', 'medium',
        `FORCE ROW LEVEL SECURITY absent on "${repr}"`,
        `FORCE RLS is absent on ${n} rolling daily partition(s) of ${g.schema}.${g.base}.`,
        `${repr} · force_rls=false · ${n} rolling daily partition(s) collapsed`,
        'Managed by Supabase Realtime — no user action required.',
        `(Context only — ${g.schema}.${g.base} partitions are managed by Supabase.)`,
        undefined,
        { schema: g.schema, tableName: repr, managed: true, partitionCount: n },
      ));
    }
  }

  // ---- DB-008: collapse grants to ONE finding per (table, grantee) ----
  const grantMap = new Map<string, { table: string; grantee: string; privs: Set<string> }>();
  for (const g of input.grants) {
    const grantee = (g.grantee || '').toLowerCase();
    const priv = (g.privilege_type || '').toUpperCase();
    const key = tableKey(g.table_schema, g.table_name);
    const relevant = grantee === 'public' ? !!priv : (grantee === 'anon' && WRITE_PRIVS.has(priv));
    if (!relevant) continue;
    const mk = `${key}|${grantee}`;
    if (!grantMap.has(mk)) grantMap.set(mk, { table: key, grantee, privs: new Set() });
    grantMap.get(mk)!.privs.add(priv);
  }
  for (const { table, grantee, privs } of grantMap.values()) {
    const schema = schemaOf(table);
    const managed = isManagedSchema(schema);
    const list = sortPrivs([...privs]);
    const privStr = list.join(', ');
    const target = grantee === 'public' ? 'PUBLIC' : 'anon';
    if (grantee === 'public') {
      findings.push(mkFinding(
        'DB-008', 'rls_permissive', 'high',
        `Privileges granted to PUBLIC on "${table}" (${list.join('/')})`,
        `${privStr} ${list.length > 1 ? 'are' : 'is'} granted to PUBLIC, exposing the table to every role regardless of RLS intent.`,
        `${table} · grantee=public · ${privStr}`,
        'Revoke from public; grant only to anon/authenticated as needed with RLS enforced.',
        `In Lovable, ask the AI: "Revoke ${privStr} on ${table} from PUBLIC and grant it only to the roles that need it, with RLS enforced."`,
        `REVOKE ${privStr} ON ${table} FROM ${target};`,
        { schema, tableName: table, managed, grantee, privileges: list },
      ));
    } else {
      findings.push(mkFinding(
        'DB-008', 'rls_permissive', 'high',
        `anon role can write to "${table}" (${list.join('/')})`,
        `The anonymous role holds ${privStr} on this table. Combined with weak RLS this allows unauthenticated writes.`,
        `${table} · grantee=anon · ${privStr}`,
        'Revoke write privileges from anon; restrict to authenticated with ownership policies.',
        `In Lovable, ask the AI: "Revoke ${privStr} on ${table} from the anon role so anonymous visitors cannot modify data."`,
        `REVOKE ${privStr} ON ${table} FROM ${target};`,
        { schema, tableName: table, managed, grantee, privileges: list },
      ));
    }
  }

  // ---- DB-009: non-default roles with BYPASSRLS / SUPERUSER ----
  for (const r of input.roles) {
    const name = (r.rolname || '').toLowerCase();
    if (DEFAULT_BYPASS_ROLES.has(name)) continue;
    if (r.rolbypassrls || r.rolsuper) {
      const platform = isPlatformRole(name);
      findings.push(mkFinding(
        'DB-009', 'service_role_exposed', platform ? 'info' : 'high',
        `Role "${r.rolname}" bypasses RLS`,
        `Role has ${r.rolsuper ? 'SUPERUSER' : 'BYPASSRLS'}. Any client connecting as this role ignores all RLS policies.${platform ? ' This is a Supabase platform role and is expected.' : ''}`,
        `role=${r.rolname} · bypassrls=${!!r.rolbypassrls} · super=${!!r.rolsuper}${platform ? ' · platform role (expected)' : ''}`,
        'Remove BYPASSRLS/SUPERUSER from application-facing roles. Reserve it for trusted admin tooling only.',
        `In Lovable, ask the AI: "Ensure the role ${r.rolname} used by the app does not have BYPASSRLS or SUPERUSER, so RLS policies are always enforced."`,
        undefined,
        { managed: platform },
      ));
    }
  }

  return { findings, policyChecks: [...byTable.values()] };
}

function mkRlsIssue(ruleId: 'DB-002' | 'DB-005', table: string, schema: string, managed: boolean): Finding {
  if (ruleId === 'DB-002') {
    return mkFinding(
      'DB-002', 'rls_missing', 'high',
      `Row Level Security disabled on "${table}"`,
      'The table has RLS disabled — any role with table privileges reads/writes every row.',
      `${table} · rls_enabled=false`,
      'Enable RLS and add ownership policies.',
      `In Lovable, ask the AI: "Enable Row Level Security on ${table} and add policies restricting access to the row owner."`,
      `ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;\nALTER TABLE ${table} FORCE ROW LEVEL SECURITY;`,
      { schema, tableName: table, managed },
    );
  }
  return mkFinding(
    'DB-005', 'rls_missing', 'medium',
    `FORCE ROW LEVEL SECURITY absent on "${table}"`,
    'RLS is enabled but not forced. The table owner (and definer-rights functions) bypass RLS, which can defeat policies in practice.',
    `${table} · rls_enabled=true · force_rls=false`,
    'Run ALTER TABLE ... FORCE ROW LEVEL SECURITY.',
    `In Lovable, ask the AI: "Run ALTER TABLE ${table} FORCE ROW LEVEL SECURITY so the table owner cannot bypass RLS policies."`,
    `ALTER TABLE ${table} FORCE ROW LEVEL SECURITY;`,
    { schema, tableName: table, managed },
  );
}

// ============================================================
// Aggregation layer — short, ordered remediation plan
// ============================================================

export interface RlsSummary {
  tables: number;
  total: number;
  actionable: number;
  managed: number;
  managedRaw: number;
  byRule: Record<string, number>;
  bySeverity: Record<string, number>;
}

export function summarizeRlsAudit(findings: Finding[], policyChecks: RLSPolicyCheck[] = []): RlsSummary {
  const actionable = findings.filter((f) => !f.managed);
  const managed = findings.filter((f) => f.managed);
  const byRule: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const f of actionable) {
    byRule[f.ruleId] = (byRule[f.ruleId] || 0) + 1;
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  }
  const managedRaw = managed.reduce((n, f) => n + (f.partitionCount || 1), 0);
  return { tables: policyChecks.length, total: findings.length, actionable: actionable.length, managed: managed.length, managedRaw, byRule, bySeverity };
}

export interface RemediationStep {
  ruleId: string;
  label: string;
  severity: Severity;
  count: number;
  tables: string[];
  sql: string | null;
  prompt: string;
}

const RULE_META: Record<string, { label: string; sev: Severity }> = {
  'DB-002': { label: 'Enable Row Level Security on exposed tables', sev: 'high' },
  'DB-008': { label: 'Revoke anonymous / public write access', sev: 'high' },
  'DB-003': { label: 'Replace tautological USING (true) policies', sev: 'high' },
  'DB-004': { label: 'Add WITH CHECK to UPDATE policies', sev: 'high' },
  'DB-005': { label: 'Force RLS so table owners cannot bypass it', sev: 'medium' },
  'DB-009': { label: 'Remove BYPASSRLS / SUPERUSER from app roles', sev: 'high' },
};
const PLAN_ORDER = ['DB-002', 'DB-008', 'DB-003', 'DB-004', 'DB-005', 'DB-009'];
const uniq = (arr: Array<string | null | undefined>): string[] => [...new Set(arr.filter((x): x is string => !!x))];

export function buildRemediationPlan(findings: Finding[]): RemediationStep[] {
  const actionable = findings.filter((f) => !f.managed);
  const groups = new Map<string, Finding[]>();
  for (const f of actionable) {
    if (!groups.has(f.ruleId)) groups.set(f.ruleId, []);
    groups.get(f.ruleId)!.push(f);
  }
  const steps: RemediationStep[] = [];
  for (const ruleId of PLAN_ORDER) {
    const items = groups.get(ruleId);
    if (!items || !items.length) continue;
    const meta = RULE_META[ruleId] || { label: ruleId, sev: 'medium' as Severity };
    const tables = uniq(items.map((f) => f.tableName)).sort();
    const sql = uniq(items.map((f) => f.remediationSql)).join('\n');
    steps.push({ ruleId, label: meta.label, severity: meta.sev, count: items.length, tables, sql: sql || null, prompt: buildPrompt(ruleId, items, tables) });
  }
  return steps;
}

function buildPrompt(ruleId: string, items: Finding[], tables: string[]): string {
  const list = tables.join(', ');
  switch (ruleId) {
    case 'DB-002':
      return `Enable and FORCE Row Level Security on these tables, then add owner-scoped policies so each user only reads/writes their own rows: ${list}.`;
    case 'DB-005':
      return `Run ALTER TABLE … FORCE ROW LEVEL SECURITY on these tables so the table owner cannot bypass RLS policies: ${list}.`;
    case 'DB-008': {
      const anon = uniq(items.filter((f) => f.grantee === 'anon').map((f) => f.tableName)).sort();
      const pub = uniq(items.filter((f) => f.grantee === 'public').map((f) => f.tableName)).sort();
      const parts: string[] = [];
      if (anon.length) parts.push(`revoke all write access (INSERT, UPDATE, DELETE, TRUNCATE) from the anon role on: ${anon.join(', ')}`);
      if (pub.length) parts.push(`revoke privileges granted to PUBLIC on: ${pub.join(', ')}`);
      return `Lock down table privileges — ${parts.join('; and ')}. Anonymous visitors should never be able to modify these tables.`;
    }
    case 'DB-003':
      return `These RLS policies use USING (true) and expose every row. Replace each with an owner check like (select auth.uid()) = user_id: ${items.map((f) => f.evidence.split(' · ')[1] || f.tableName).join('; ')}.`;
    case 'DB-004':
      return `Add a WITH CHECK clause mirroring the USING predicate to these UPDATE policies so users can't reassign rows they don't own: ${items.map((f) => f.evidence.split(' · ')[1] || f.tableName).join('; ')}.`;
    case 'DB-009':
      return `These roles bypass RLS (BYPASSRLS / SUPERUSER). Make sure the app never connects as them and reserve them for trusted admin tooling: ${items.map((f) => (f.evidence.match(/role=([^ ]+)/) || [, f.title])[1]).join(', ')}.`;
    default:
      return items.map((f) => f.aiPrompt).filter(Boolean).join(' ');
  }
}
