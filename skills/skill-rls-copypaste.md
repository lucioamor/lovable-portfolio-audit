# Skill: Copy-Paste RLS SQL Generation

> **Roadmap refs:** D1-D5, §21.3  
> **Complexity:** Small  
> **Files affected:** `src/lib/supabase-inspector.ts` (web app only)

---

## Problem

The roadmap explicitly marks direct SQL execution against a user's Supabase instance as an anti-pattern / non-goal (§1.3, §21.3), even when testing RLS. The current web app implementation (`supabase-inspector.ts`) attempts to run a test query. This should be changed to emit copy-paste SQL for the user to run themselves.

---

## Implementation

### 1. Refactor `supabase-inspector.ts`

```typescript
// src/lib/supabase-inspector.ts

export function generateRlsAuditSql(): string {
  return `
-- Run this in your Supabase SQL Editor to audit RLS policies

-- 1. Tables missing RLS
SELECT schemaname, tablename 
FROM pg_tables 
WHERE schemaname = 'public' AND rowsecurity = false;

-- 2. Permissive policies (USING (true))
SELECT schemaname, tablename, policyname, roles, cmd, qual 
FROM pg_policies 
WHERE schemaname = 'public' AND qual = 'true';
  `.trim();
}

export async function checkRlsConfiguration(supabaseUrl: string, anonKey: string) {
  // Do NOT execute queries.
  // We can verify the URL and Key format, but return the SQL for the user.
  
  return {
    status: 'manual_audit_required',
    sqlToRun: generateRlsAuditSql(),
    message: 'Direct SQL execution is disabled for safety. Run the provided SQL in your Supabase dashboard.'
  };
}
```

### 2. Update Web UI

In the web app UI components, when RLS testing is invoked, display the generated SQL in a `<pre><code>` block with a "Copy" button instead of showing a pass/fail indicator.

---

## Acceptance Criteria

- [ ] `supabase-inspector.ts` no longer attempts to execute `select count(*)`
- [ ] Returns a block of SQL to audit RLS
- [ ] Score bonus for "RLS missing" (+40) is either removed or gated behind a manual user input checklist
