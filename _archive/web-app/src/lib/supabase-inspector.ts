// ============================================================
// Lovable Security Scanner — Supabase RLS Scanner
// ============================================================
//
// Non-invasive scanner that checks if Supabase RLS policies
// are properly configured on your projects' databases.
// Uses only the anon (public) key — never the service_role.
// ============================================================

export interface RLSCheckResult {
  supabaseUrl: string;
  status: string;
  sqlToRun: string;
  message: string;
}

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

/**
 * Check RLS configuration by generating manual SQL audit queries
 * This is NON-INVASIVE — only outputs SQL for the user to run safely
 */
export async function testRLS(supabaseUrl: string, anonKey: string): Promise<RLSCheckResult> {
  // Do NOT execute queries against the user's DB.
  // We can verify the URL and Key format, but return the SQL for the user.
  
  return {
    supabaseUrl,
    status: 'manual_audit_required',
    sqlToRun: generateRlsAuditSql(),
    message: 'Direct SQL execution is disabled for safety. Run the provided SQL in your Supabase dashboard.'
  };
}
