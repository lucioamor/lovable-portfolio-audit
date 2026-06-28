// ============================================================
// A1 — Deep RLS checklist classifier (DB-003/004/005/008/009)
// ============================================================
import { describe, it, expect } from 'vitest';
import {
  parseRlsResult,
  classifyRlsAudit,
  normalizeExpr,
  isManagedSchema,
  summarizeRlsAudit,
  buildRemediationPlan,
  type RlsAuditInput,
} from '../src/engines/rls-checklist';

const base: RlsAuditInput = { policies: [], tables: [], grants: [], roles: [] };

describe('normalizeExpr', () => {
  it('treats (true) and TRUE as tautology core', () => {
    expect(normalizeExpr('(true)')).toBe('true');
    expect(normalizeExpr('  TRUE ')).toBe('true');
    expect(normalizeExpr('(select auth.uid()) = user_id')).not.toBe('true');
  });
});

describe('parseRlsResult', () => {
  it('unwraps the Supabase [{ audit: {...} }] shape', () => {
    const raw = JSON.stringify([{ audit: { policies: [], tables: [{ table_name: 't', rls_enabled: true, force_rls: true }], grants: [], roles: [] } }]);
    const parsed = parseRlsResult(raw);
    expect(parsed.tables).toHaveLength(1);
  });
  it('accepts a bare object', () => {
    expect(parseRlsResult('{"policies":[],"tables":[],"grants":[],"roles":[]}').policies).toEqual([]);
  });
  it('throws on non-JSON', () => {
    expect(() => parseRlsResult('not json')).toThrow();
  });
});

describe('classifyRlsAudit', () => {
  it('DB-003: USING (true) → high', () => {
    const { findings, policyChecks } = classifyRlsAudit({
      ...base,
      tables: [{ schema: 'public', table_name: 'notes', rls_enabled: true, force_rls: true }],
      policies: [{ schemaname: 'public', tablename: 'notes', policyname: 'all_read', cmd: 'SELECT', using_expr: 'true' }],
    });
    const db003 = findings.find(f => f.ruleId === 'DB-003');
    expect(db003?.severity).toBe('high');
    // phantom field is now genuinely wired
    expect(policyChecks.find(c => c.table === 'public.notes')?.hasUsingTrue).toBe(true);
  });

  it('DB-004: UPDATE policy with USING but no WITH CHECK → high', () => {
    const { findings } = classifyRlsAudit({
      ...base,
      tables: [{ schema: 'public', table_name: 'orders', rls_enabled: true, force_rls: true }],
      policies: [{ schemaname: 'public', tablename: 'orders', policyname: 'upd', cmd: 'UPDATE', using_expr: '(auth.uid() = user_id)', with_check_expr: null }],
    });
    expect(findings.find(f => f.ruleId === 'DB-004')?.severity).toBe('high');
  });

  it('DB-004 not raised when WITH CHECK present', () => {
    const { findings } = classifyRlsAudit({
      ...base,
      tables: [{ schema: 'public', table_name: 'orders', rls_enabled: true, force_rls: true }],
      policies: [{ schemaname: 'public', tablename: 'orders', policyname: 'upd', cmd: 'UPDATE', using_expr: '(auth.uid() = user_id)', with_check_expr: '(auth.uid() = user_id)' }],
    });
    expect(findings.find(f => f.ruleId === 'DB-004')).toBeUndefined();
  });

  it('DB-005: RLS enabled but FORCE absent → medium', () => {
    const { findings } = classifyRlsAudit({
      ...base,
      tables: [{ schema: 'public', table_name: 'profiles', rls_enabled: true, force_rls: false }],
    });
    expect(findings.find(f => f.ruleId === 'DB-005')?.severity).toBe('medium');
  });

  it('DB-002: RLS disabled → high', () => {
    const { findings } = classifyRlsAudit({
      ...base,
      tables: [{ schema: 'public', table_name: 'leaky', rls_enabled: false, force_rls: false }],
    });
    expect(findings.find(f => f.ruleId === 'DB-002')?.severity).toBe('high');
  });

  it('DB-008: grant to public → high; anon write → high; anon SELECT ignored', () => {
    const { findings } = classifyRlsAudit({
      ...base,
      grants: [
        { table_schema: 'public', table_name: 't', grantee: 'public', privilege_type: 'SELECT' },
        { table_schema: 'public', table_name: 't', grantee: 'anon', privilege_type: 'INSERT' },
        { table_schema: 'public', table_name: 't', grantee: 'anon', privilege_type: 'SELECT' },
      ],
    });
    const db008 = findings.filter(f => f.ruleId === 'DB-008');
    expect(db008).toHaveLength(2); // public SELECT + anon INSERT, NOT anon SELECT
  });

  it('DB-009: custom bypassrls role flagged, default roles ignored', () => {
    const { findings } = classifyRlsAudit({
      ...base,
      roles: [
        { rolname: 'postgres', rolbypassrls: true, rolsuper: true },     // default → ignored
        { rolname: 'app_admin', rolbypassrls: true, rolsuper: false },   // flagged
      ],
    });
    const db009 = findings.filter(f => f.ruleId === 'DB-009');
    expect(db009).toHaveLength(1);
    expect(db009[0].evidence).toContain('app_admin');
  });

  it('clean schema → no findings', () => {
    const { findings } = classifyRlsAudit({
      ...base,
      tables: [{ schema: 'public', table_name: 'ok', rls_enabled: true, force_rls: true }],
      policies: [{ schemaname: 'public', tablename: 'ok', policyname: 'own', cmd: 'ALL', using_expr: '(auth.uid() = user_id)', with_check_expr: '(auth.uid() = user_id)' }],
    });
    expect(findings).toEqual([]);
  });
});

// ============================================================
// v2 consolidation — collapse, managed tagging, remediation plan
// ============================================================
describe('isManagedSchema', () => {
  it('flags Supabase-managed schemas and not application schemas', () => {
    expect(isManagedSchema('auth')).toBe(true);
    expect(isManagedSchema('storage')).toBe(true);
    expect(isManagedSchema('realtime')).toBe(true);
    expect(isManagedSchema('public')).toBe(false);
    expect(isManagedSchema('app')).toBe(false);
  });
});

describe('DB-008 collapse per (table, grantee)', () => {
  it('four anon write privileges on one table → ONE finding with combined REVOKE', () => {
    const { findings } = classifyRlsAudit({
      ...base,
      grants: ['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE'].map(p => ({
        table_schema: 'public', table_name: 'notifications', grantee: 'anon', privilege_type: p,
      })),
    });
    const db008 = findings.filter(f => f.ruleId === 'DB-008');
    expect(db008).toHaveLength(1);
    expect(db008[0].privileges).toEqual(['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']);
    expect(db008[0].remediationSql).toBe('REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.notifications FROM anon;');
    expect(db008[0].managed).toBe(false);
  });

  it('separates anon and public grantees on the same table', () => {
    const { findings } = classifyRlsAudit({
      ...base,
      grants: [
        { table_schema: 'public', table_name: 't', grantee: 'anon', privilege_type: 'INSERT' },
        { table_schema: 'public', table_name: 't', grantee: 'anon', privilege_type: 'UPDATE' },
        { table_schema: 'public', table_name: 't', grantee: 'public', privilege_type: 'SELECT' },
      ],
    });
    expect(findings.filter(f => f.ruleId === 'DB-008')).toHaveLength(2);
  });
});

describe('managed-schema tagging', () => {
  it('RLS disabled on auth.users → managed (context, not actionable)', () => {
    const { findings } = classifyRlsAudit({
      ...base,
      tables: [{ schema: 'auth', table_name: 'users', rls_enabled: false, force_rls: false }],
    });
    const f = findings.find(x => x.ruleId === 'DB-002');
    expect(f?.managed).toBe(true);
    expect(summarizeRlsAudit(findings).actionable).toBe(0);
  });

  it('collapses rolling realtime.messages_YYYY_MM_DD partitions into one finding', () => {
    const { findings } = classifyRlsAudit({
      ...base,
      tables: [
        { schema: 'realtime', table_name: 'messages_2026_06_27', rls_enabled: false, force_rls: false },
        { schema: 'realtime', table_name: 'messages_2026_06_28', rls_enabled: false, force_rls: false },
        { schema: 'realtime', table_name: 'messages_2026_06_29', rls_enabled: false, force_rls: false },
      ],
    });
    const collapsed = findings.filter(f => f.partitionCount);
    expect(collapsed).toHaveLength(1);
    expect(collapsed[0].partitionCount).toBe(3);
    expect(collapsed[0].tableName).toBe('realtime.messages_*');
    expect(collapsed[0].managed).toBe(true);
  });

  it('service_role bypassing RLS is treated as expected platform context', () => {
    const { findings } = classifyRlsAudit({
      ...base,
      roles: [{ rolname: 'service_role', rolbypassrls: true, rolsuper: false }],
    });
    const f = findings.find(x => x.ruleId === 'DB-009');
    expect(f?.managed).toBe(true);
    expect(f?.severity).toBe('info');
    expect(summarizeRlsAudit(findings).actionable).toBe(0);
  });
});

describe('buildRemediationPlan', () => {
  it('produces one ordered step per actionable rule, covering all tables', () => {
    const { findings } = classifyRlsAudit({
      ...base,
      tables: [
        { schema: 'public', table_name: 'a', rls_enabled: true, force_rls: false },
        { schema: 'public', table_name: 'b', rls_enabled: true, force_rls: false },
        { schema: 'auth', table_name: 'users', rls_enabled: true, force_rls: false }, // managed → excluded
      ],
      grants: [
        { table_schema: 'public', table_name: 'a', grantee: 'anon', privilege_type: 'INSERT' },
        { table_schema: 'public', table_name: 'a', grantee: 'anon', privilege_type: 'DELETE' },
      ],
    });
    const plan = buildRemediationPlan(findings);
    const db005 = plan.find(s => s.ruleId === 'DB-005');
    const db008 = plan.find(s => s.ruleId === 'DB-008');
    expect(db005?.tables).toEqual(['public.a', 'public.b']);   // managed auth.users excluded
    expect(db008?.count).toBe(1);
    expect(db008?.sql).toBe('REVOKE INSERT, DELETE ON public.a FROM anon;');
    // DB-008 ordered before DB-005
    expect(plan.findIndex(s => s.ruleId === 'DB-008')).toBeLessThan(plan.findIndex(s => s.ruleId === 'DB-005'));
  });
});
