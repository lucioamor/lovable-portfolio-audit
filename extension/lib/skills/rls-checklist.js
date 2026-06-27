// ============================================================
// SKILL: rls-checklist — Deep RLS audit (DB-003/004/005/008/009)
// ============================================================
// Copy-paste model. The extension NEVER runs SQL against a third-party
// Supabase project (roadmap §9). It generates read-only introspection SQL;
// the user runs it in their own SQL editor and pastes the JSON result back
// for classification. Mirrors packages/cli/src/engines/rls-checklist.ts.
// ============================================================

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

export function parseRlsResult(raw) {
  let data;
  try {
    data = JSON.parse(String(raw).trim());
  } catch {
    throw new Error('RLS result is not valid JSON. Paste the value of the "audit" cell exactly.');
  }
  if (Array.isArray(data)) data = data[0];
  if (data && typeof data === 'object' && 'audit' in data) data = data.audit;
  if (typeof data === 'string') { try { data = JSON.parse(data); } catch { /* noop */ } }
  const obj = data ?? {};
  return {
    policies: Array.isArray(obj.policies) ? obj.policies : [],
    tables: Array.isArray(obj.tables) ? obj.tables : [],
    grants: Array.isArray(obj.grants) ? obj.grants : [],
    roles: Array.isArray(obj.roles) ? obj.roles : [],
  };
}

export function normalizeExpr(expr) {
  if (expr === null || expr === undefined) return '';
  return String(expr).toLowerCase().replace(/\s+/g, '').replace(/^\(+|\)+$/g, '');
}
const isTautology = (e) => normalizeExpr(e) === 'true';

const DEFAULT_BYPASS_ROLES = new Set(['postgres', 'supabase_admin', 'supabase_auth_admin', 'supabase_storage_admin', 'rds_superuser']);
const WRITE_PRIVS = new Set(['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']);

function mk(ruleId, severity, title, evidence, remediationSql) {
  return { id: crypto.randomUUID(), ruleId, kind: 'rls', severity, title, evidence, remediationSql: remediationSql || null };
}

export function classifyRlsAudit(input) {
  const findings = [];
  const byTable = new Map();
  const key = (s, t) => `${s || 'public'}.${t || '?'}`;
  const tableInfo = new Map();
  for (const t of input.tables) tableInfo.set(key(t.schema, t.table_name), t);

  const ensure = (s, t) => {
    const k = key(s, t);
    let chk = byTable.get(k);
    if (!chk) {
      const info = tableInfo.get(k);
      chk = { table: k, hasRLS: info?.rls_enabled ?? false, hasPolicies: false, hasUsingTrue: false, hasMissingWithCheck: false, hasForceRLS: info?.force_rls ?? false };
      byTable.set(k, chk);
    }
    return chk;
  };
  for (const t of input.tables) ensure(t.schema, t.table_name);

  for (const p of input.policies) {
    const chk = ensure(p.schemaname, p.tablename);
    chk.hasPolicies = true;
    const cmd = (p.cmd || '').toUpperCase();
    if (isTautology(p.using_expr)) {
      chk.hasUsingTrue = true;
      findings.push(mk('DB-003', 'high', `Tautological RLS policy: USING (true) on "${chk.table}"`,
        `${chk.table} · policy ${p.policyname} · cmd=${cmd || 'ALL'} · USING=(true)`));
    }
    const isWriteScoped = cmd === 'UPDATE' || cmd === 'ALL' || cmd === '';
    const hasUsing = (p.using_expr ?? '') !== '';
    const missingWithCheck = (p.with_check_expr ?? null) === null || normalizeExpr(p.with_check_expr) === '';
    if (isWriteScoped && hasUsing && missingWithCheck) {
      chk.hasMissingWithCheck = true;
      findings.push(mk('DB-004', 'high', `UPDATE policy missing WITH CHECK on "${chk.table}"`,
        `${chk.table} · policy ${p.policyname} · cmd=${cmd || 'UPDATE'} · WITH CHECK=missing`));
    }
  }

  for (const chk of byTable.values()) {
    if (!chk.hasRLS) {
      findings.push(mk('DB-002', 'high', `Row Level Security disabled on "${chk.table}"`,
        `${chk.table} · rls_enabled=false`,
        `ALTER TABLE ${chk.table} ENABLE ROW LEVEL SECURITY;\nALTER TABLE ${chk.table} FORCE ROW LEVEL SECURITY;`));
    } else if (!chk.hasForceRLS) {
      findings.push(mk('DB-005', 'medium', `FORCE ROW LEVEL SECURITY absent on "${chk.table}"`,
        `${chk.table} · rls_enabled=true · force_rls=false`,
        `ALTER TABLE ${chk.table} FORCE ROW LEVEL SECURITY;`));
    }
  }

  for (const g of input.grants) {
    const grantee = (g.grantee || '').toLowerCase();
    const priv = (g.privilege_type || '').toUpperCase();
    const k = key(g.table_schema, g.table_name);
    if (grantee === 'public') {
      findings.push(mk('DB-008', 'high', `Privilege granted to PUBLIC on "${k}"`,
        `${k} · grantee=public · ${priv}`, `REVOKE ${priv} ON ${k} FROM PUBLIC;`));
    } else if (grantee === 'anon' && WRITE_PRIVS.has(priv)) {
      findings.push(mk('DB-008', 'high', `anon role can ${priv} "${k}"`,
        `${k} · grantee=anon · ${priv}`, `REVOKE ${priv} ON ${k} FROM anon;`));
    }
  }

  for (const r of input.roles) {
    const name = (r.rolname || '').toLowerCase();
    if (DEFAULT_BYPASS_ROLES.has(name)) continue;
    if (r.rolbypassrls || r.rolsuper) {
      findings.push(mk('DB-009', 'high', `Role "${r.rolname}" bypasses RLS`,
        `role=${r.rolname} · bypassrls=${!!r.rolbypassrls} · super=${!!r.rolsuper}`));
    }
  }

  return { findings, policyChecks: [...byTable.values()] };
}
