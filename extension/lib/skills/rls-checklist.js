// ============================================================
// SKILL: rls-checklist — Deep RLS audit (DB-002/003/004/005/008/009)
// ============================================================
// Copy-paste model. The extension NEVER runs SQL against a third-party
// Supabase project (roadmap §9). It generates read-only introspection SQL;
// the user runs it in their own SQL editor and pastes the JSON result back
// for classification. Mirrors packages/cli/src/engines/rls-checklist.ts.
//
// Output philosophy (v2): a raw schema dump produces hundreds of near-identical
// rows (one per privilege, one per daily partition, one per Supabase-managed
// system table). That is not actionable. So classification now:
//   • collapses DB-008 to ONE finding per (table, grantee) with a single REVOKE;
//   • tags every finding with its schema and whether it lives in a
//     Supabase-managed schema (auth/storage/realtime/…) the user can't ALTER;
//   • collapses rolling date partitions (realtime.messages_YYYY_MM_DD → _*);
//   • exposes buildRemediationPlan() so the UI shows a short list of
//     copy-paste migrations + Lovable prompts instead of line-by-line fixes.
// ============================================================

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

// Schemas Supabase manages on the user's behalf. Findings here are real, but the
// user generally cannot (and should not) ALTER them from the SQL editor, so they
// are surfaced as collapsed context rather than as actionable line items.
export const SYSTEM_SCHEMAS = new Set([
  'auth', 'storage', 'realtime', 'vault', 'net', 'cron', 'supabase_migrations',
  'pgsodium', 'graphql', 'graphql_public', 'extensions', '_realtime', '_analytics',
  'pgbouncer', 'supabase_functions', 'pgtle',
]);

export const isManagedSchema = (schema) => SYSTEM_SCHEMAS.has(String(schema || '').toLowerCase());
const schemaOf = (key) => String(key || '').split('.')[0];
const tableOf = (key) => String(key || '').split('.').slice(1).join('.');

// Rolling daily partitions, e.g. realtime.messages_2026_06_27 — these regenerate
// every day, so listing each one is pure noise. Collapse to one representative.
const DATE_PARTITION_RE = /_(\d{4})_(\d{2})_(\d{2})$/;

// Canonical privilege ordering for stable, readable REVOKE statements.
const PRIV_ORDER = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'];
const sortPrivs = (privs) =>
  [...new Set(privs)].sort((a, b) => {
    const ia = PRIV_ORDER.indexOf(a), ib = PRIV_ORDER.indexOf(b);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
  });

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
// Roles Supabase provisions that legitimately bypass RLS (service_role is used
// by your backend by design). Surfaced as context, never as an actionable fix.
const PLATFORM_BYPASS_ROLES = new Set(['service_role', 'supabase_read_only_user', 'supabase_etl_admin', 'supabase_realtime_admin', 'supabase_replication_admin', 'authenticator', 'pgbouncer']);
const isPlatformRole = (name) => PLATFORM_BYPASS_ROLES.has(name) || name.startsWith('sandbox_exec') || name.startsWith('supabase_');
const WRITE_PRIVS = new Set(['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']);

function mk(ruleId, severity, title, evidence, opts = {}) {
  return {
    id: crypto.randomUUID(),
    ruleId,
    kind: 'rls',
    severity,
    title,
    evidence,
    remediationSql: opts.remediationSql || null,
    aiPrompt: opts.aiPrompt || null,
    schema: opts.schema || null,
    table: opts.table || null,
    managed: !!opts.managed,
    grantee: opts.grantee || null,
    privileges: opts.privileges || null,
    partitionCount: opts.partitionCount || null,
  };
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

  // ---- DB-003 / DB-004 from policies (one per policy — already low-volume) ----
  for (const p of input.policies) {
    const chk = ensure(p.schemaname, p.tablename);
    chk.hasPolicies = true;
    const schema = schemaOf(chk.table);
    const managed = isManagedSchema(schema);
    const cmd = (p.cmd || '').toUpperCase();
    if (isTautology(p.using_expr)) {
      chk.hasUsingTrue = true;
      findings.push(mk('DB-003', 'high', `Tautological RLS policy: USING (true) on "${chk.table}"`,
        `${chk.table} · policy ${p.policyname} · cmd=${cmd || 'ALL'} · USING=(true)`,
        { schema, table: chk.table, managed,
          aiPrompt: `The RLS policy ${p.policyname} on ${chk.table} uses USING (true), which exposes every row. Replace it with an owner check such as (select auth.uid()) = user_id.` }));
    }
    const isWriteScoped = cmd === 'UPDATE' || cmd === 'ALL' || cmd === '';
    const hasUsing = (p.using_expr ?? '') !== '';
    const missingWithCheck = (p.with_check_expr ?? null) === null || normalizeExpr(p.with_check_expr) === '';
    if (isWriteScoped && hasUsing && missingWithCheck) {
      chk.hasMissingWithCheck = true;
      findings.push(mk('DB-004', 'high', `UPDATE policy missing WITH CHECK on "${chk.table}"`,
        `${chk.table} · policy ${p.policyname} · cmd=${cmd || 'UPDATE'} · WITH CHECK=missing`,
        { schema, table: chk.table, managed,
          aiPrompt: `Add a WITH CHECK clause to the UPDATE policy ${p.policyname} on ${chk.table} that mirrors its USING predicate, so users cannot reassign rows they don't own.` }));
    }
  }

  // ---- DB-002 / DB-005, with rolling date-partitions collapsed ----
  const rlsIssues = [];
  for (const chk of byTable.values()) {
    if (!chk.hasRLS) rlsIssues.push({ ruleId: 'DB-002', table: chk.table });
    else if (!chk.hasForceRLS) rlsIssues.push({ ruleId: 'DB-005', table: chk.table });
  }
  const partitionGroups = new Map();
  for (const it of rlsIssues) {
    const schema = schemaOf(it.table);
    const tbl = tableOf(it.table);
    const m = tbl.match(DATE_PARTITION_RE);
    if (isManagedSchema(schema) && m) {
      const base = tbl.slice(0, m.index);
      const gk = `${it.ruleId}|${schema}.${base}`;
      if (!partitionGroups.has(gk)) partitionGroups.set(gk, { ruleId: it.ruleId, schema, base, members: [] });
      partitionGroups.get(gk).members.push(it.table);
      continue;
    }
    emitRlsIssue(findings, it.ruleId, it.table, schema, isManagedSchema(schema));
  }
  for (const g of partitionGroups.values()) {
    const repr = `${g.schema}.${g.base}_*`;
    const n = g.members.length;
    if (g.ruleId === 'DB-002') {
      findings.push(mk('DB-002', 'high', `Row Level Security disabled on "${repr}"`,
        `${repr} · rls_enabled=false · ${n} rolling daily partition(s) collapsed`,
        { schema: g.schema, table: repr, managed: true, partitionCount: n }));
    } else {
      findings.push(mk('DB-005', 'medium', `FORCE ROW LEVEL SECURITY absent on "${repr}"`,
        `${repr} · force_rls=false · ${n} rolling daily partition(s) collapsed`,
        { schema: g.schema, table: repr, managed: true, partitionCount: n }));
    }
  }

  // ---- DB-008: collapse grants to ONE finding per (table, grantee) ----
  const grantMap = new Map(); // `${table}|${grantee}` -> { table, grantee, privs:Set }
  for (const g of input.grants) {
    const grantee = (g.grantee || '').toLowerCase();
    const priv = (g.privilege_type || '').toUpperCase();
    const k = key(g.table_schema, g.table_name);
    const relevant = grantee === 'public' ? !!priv : (grantee === 'anon' && WRITE_PRIVS.has(priv));
    if (!relevant) continue;
    const mk2 = `${k}|${grantee}`;
    if (!grantMap.has(mk2)) grantMap.set(mk2, { table: k, grantee, privs: new Set() });
    grantMap.get(mk2).privs.add(priv);
  }
  for (const { table, grantee, privs } of grantMap.values()) {
    const schema = schemaOf(table);
    const managed = isManagedSchema(schema);
    const list = sortPrivs([...privs]);
    const privStr = list.join(', ');
    const target = grantee === 'public' ? 'PUBLIC' : 'anon';
    const title = grantee === 'public'
      ? `Privileges granted to PUBLIC on "${table}" (${list.join('/')})`
      : `anon role can write to "${table}" (${list.join('/')})`;
    findings.push(mk('DB-008', 'high', title,
      `${table} · grantee=${grantee} · ${privStr}`,
      { schema, table, managed, grantee, privileges: list,
        remediationSql: `REVOKE ${privStr} ON ${table} FROM ${target};`,
        aiPrompt: grantee === 'public'
          ? `Revoke ${privStr} on ${table} from PUBLIC and grant only the roles that need it, with RLS enforced.`
          : `Revoke ${privStr} on ${table} from the anon role so anonymous visitors cannot modify data.` }));
  }

  // ---- DB-009: non-default roles with BYPASSRLS / SUPERUSER ----
  for (const r of input.roles) {
    const name = (r.rolname || '').toLowerCase();
    if (DEFAULT_BYPASS_ROLES.has(name)) continue;
    if (r.rolbypassrls || r.rolsuper) {
      const platform = isPlatformRole(name);
      findings.push(mk('DB-009', platform ? 'info' : 'high', `Role "${r.rolname}" bypasses RLS`,
        `role=${r.rolname} · bypassrls=${!!r.rolbypassrls} · super=${!!r.rolsuper}${platform ? ' · platform role (expected)' : ''}`,
        { managed: platform,
          aiPrompt: `Ensure the role ${r.rolname} used by the app does not have BYPASSRLS or SUPERUSER, so RLS policies are always enforced.` }));
    }
  }

  return { findings, policyChecks: [...byTable.values()] };
}

function emitRlsIssue(findings, ruleId, table, schema, managed) {
  if (ruleId === 'DB-002') {
    findings.push(mk('DB-002', 'high', `Row Level Security disabled on "${table}"`,
      `${table} · rls_enabled=false`,
      { schema, table, managed,
        remediationSql: `ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;\nALTER TABLE ${table} FORCE ROW LEVEL SECURITY;`,
        aiPrompt: `Enable Row Level Security on ${table} and add policies restricting access to the row owner.` }));
  } else {
    findings.push(mk('DB-005', 'medium', `FORCE ROW LEVEL SECURITY absent on "${table}"`,
      `${table} · rls_enabled=true · force_rls=false`,
      { schema, table, managed,
        remediationSql: `ALTER TABLE ${table} FORCE ROW LEVEL SECURITY;`,
        aiPrompt: `Run ALTER TABLE ${table} FORCE ROW LEVEL SECURITY so the table owner cannot bypass RLS policies.` }));
  }
}

// ============================================================
// Aggregation layer — what the UI/report actually consume
// ============================================================

const SEV_WEIGHT = { catastrophic: 5, critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function summarizeRlsAudit(findings, policyChecks = []) {
  const actionable = findings.filter((f) => !f.managed);
  const managed = findings.filter((f) => f.managed);
  const byRule = {};
  const bySeverity = {};
  for (const f of actionable) {
    byRule[f.ruleId] = (byRule[f.ruleId] || 0) + 1;
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  }
  const managedRaw = managed.reduce((n, f) => n + (f.partitionCount || 1), 0);
  return {
    tables: policyChecks.length,
    total: findings.length,
    actionable: actionable.length,
    managed: managed.length,
    managedRaw,
    byRule,
    bySeverity,
  };
}

// Human label + ordering for each rule in the remediation plan.
const RULE_META = {
  'DB-002': { label: 'Enable Row Level Security on exposed tables', sev: 'high' },
  'DB-008': { label: 'Revoke anonymous / public write access', sev: 'high' },
  'DB-003': { label: 'Replace tautological USING (true) policies', sev: 'high' },
  'DB-004': { label: 'Add WITH CHECK to UPDATE policies', sev: 'high' },
  'DB-005': { label: 'Force RLS so table owners cannot bypass it', sev: 'medium' },
  'DB-009': { label: 'Remove BYPASSRLS / SUPERUSER from app roles', sev: 'high' },
};
const PLAN_ORDER = ['DB-002', 'DB-008', 'DB-003', 'DB-004', 'DB-005', 'DB-009'];

const uniqLines = (arr) => [...new Set(arr.filter(Boolean))];

/**
 * Turn the flat finding list into a short, ordered set of remediation steps —
 * one per rule, each with a single consolidated SQL migration and one Lovable
 * prompt covering every affected table. Managed-schema findings are excluded
 * (they are context, not user-actionable).
 */
export function buildRemediationPlan(findings) {
  const actionable = findings.filter((f) => !f.managed);
  const groups = new Map();
  for (const f of actionable) {
    if (!groups.has(f.ruleId)) groups.set(f.ruleId, []);
    groups.get(f.ruleId).push(f);
  }

  const steps = [];
  for (const ruleId of PLAN_ORDER) {
    const items = groups.get(ruleId);
    if (!items || !items.length) continue;
    const meta = RULE_META[ruleId] || { label: ruleId, sev: 'medium' };
    const tables = uniqLines(items.map((f) => f.table)).sort();
    const sql = uniqLines(items.map((f) => f.remediationSql)).join('\n');
    steps.push({
      ruleId,
      label: meta.label,
      severity: meta.sev,
      count: items.length,
      tables,
      sql: sql || null,
      prompt: buildPrompt(ruleId, items, tables),
    });
  }
  return steps;
}

function buildPrompt(ruleId, items, tables) {
  const list = tables.join(', ');
  switch (ruleId) {
    case 'DB-002':
      return `Enable and FORCE Row Level Security on these tables, then add owner-scoped policies so each user only reads/writes their own rows: ${list}.`;
    case 'DB-005':
      return `Run ALTER TABLE … FORCE ROW LEVEL SECURITY on these tables so the table owner cannot bypass RLS policies: ${list}.`;
    case 'DB-008': {
      const anon = items.filter((f) => f.grantee === 'anon').map((f) => f.table);
      const pub = items.filter((f) => f.grantee === 'public').map((f) => f.table);
      const parts = [];
      if (anon.length) parts.push(`revoke all write access (INSERT, UPDATE, DELETE, TRUNCATE) from the anon role on: ${uniqLines(anon).sort().join(', ')}`);
      if (pub.length) parts.push(`revoke privileges granted to PUBLIC on: ${uniqLines(pub).sort().join(', ')}`);
      return `Lock down table privileges — ${parts.join('; and ')}. Anonymous visitors should never be able to modify these tables.`;
    }
    case 'DB-003':
      return `These RLS policies use USING (true) and expose every row. Replace each with an owner check like (select auth.uid()) = user_id: ${items.map((f) => f.evidence.split(' · ')[1] || f.table).join('; ')}.`;
    case 'DB-004':
      return `Add a WITH CHECK clause mirroring the USING predicate to these UPDATE policies so users can't reassign rows they don't own: ${items.map((f) => f.evidence.split(' · ')[1] || f.table).join('; ')}.`;
    case 'DB-009':
      return `These roles bypass RLS (BYPASSRLS / SUPERUSER). Make sure the app never connects as them and reserve them for trusted admin tooling: ${items.map((f) => (f.evidence.match(/role=([^ ]+)/) || [, f.title])[1]).join(', ')}.`;
    default:
      return items.map((f) => f.aiPrompt).filter(Boolean).join(' ');
  }
}

/** A clean, copy-friendly markdown report: summary + remediation plan + collapsed context. */
export function renderRlsReportMarkdown(findings, policyChecks = []) {
  const s = summarizeRlsAudit(findings, policyChecks);
  const plan = buildRemediationPlan(findings);
  const out = [];
  out.push(`# Deep RLS audit`);
  out.push('');
  out.push(`${s.tables} tables analyzed · **${s.actionable} actionable** finding(s) · ${s.managedRaw} in Supabase-managed schemas (collapsed)`);
  out.push('');
  if (!plan.length) {
    out.push('✅ No actionable RLS issues in your application schemas.');
  } else {
    out.push(`## Remediation plan (${plan.length} step${plan.length === 1 ? '' : 's'})`);
    out.push('');
    plan.forEach((step, i) => {
      out.push(`### ${i + 1}. [${step.ruleId}] ${step.label} — ${step.count} item(s)`);
      out.push('');
      out.push(`**Prompt for Lovable:** ${step.prompt}`);
      out.push('');
      if (step.sql) {
        out.push('```sql');
        out.push(step.sql);
        out.push('```');
        out.push('');
      }
    });
  }
  if (s.managed) {
    out.push(`---`);
    out.push(`_${s.managed} finding(s) (${s.managedRaw} raw) sit in Supabase-managed schemas (auth, storage, realtime, …). These are controlled by the platform and are not fixable from the SQL editor — shown for context only._`);
  }
  return out.join('\n');
}
