import { createHash } from 'crypto';

// Inline types to avoid circular dependency
type Severity = 'catastrophic' | 'critical' | 'high' | 'medium' | 'low' | 'info';
type LovableLevel = 'L0' | 'L1' | 'L2';

export interface SecretPatternDef {
  id: string;
  label: string;
  regex: RegExp;
  severity: Severity;
  description: string;
  lovableLevel: LovableLevel;
  aiPrompt?: string;
}

export interface PIIPatternDef {
  id: string;
  label: string;
  regex: RegExp;
  severity: Severity;
}

// ---- Secret Patterns (APP-001 + DB-012 + LOV-004) ----

export const SECRET_PATTERNS: SecretPatternDef[] = [
  // Supabase — CATASTROPHIC tier
  {
    id: 'SUP-001',
    label: 'Supabase Service Role Key',
    regex: /\b(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b/g,
    severity: 'catastrophic',
    description: 'JWT with potential service_role claim — bypasses ALL RLS. Decode and verify.',
    lovableLevel: 'L0',
    aiPrompt: 'Remove the service_role key from the frontend code. It must only be used in server-side Edge Functions or backend services, never in client-side JavaScript. Generate a secure Edge Function that wraps the privileged operation.',
  },
  {
    id: 'SUP-002',
    label: 'Supabase Service Role Env Var',
    regex: /SUPABASE_SERVICE_ROLE_KEY\s*=\s*["']?([A-Za-z0-9._-]{30,})["']?/gi,
    severity: 'catastrophic',
    description: 'Supabase service_role key exposed in environment variable — full DB bypass.',
    lovableLevel: 'L0',
    aiPrompt: 'Move SUPABASE_SERVICE_ROLE_KEY to a server-only environment. In Lovable/Vite, never prefix privileged keys with VITE_ or NEXT_PUBLIC_. Create an Edge Function to handle privileged operations.',
  },
  {
    id: 'SUP-003',
    label: 'Supabase Anon Key (hardcoded)',
    regex: /(?:supabase[._]?anon[._]?key|NEXT_PUBLIC_SUPABASE_ANON_KEY|VITE_SUPABASE_ANON_KEY)\s*=\s*["']?(eyJ[A-Za-z0-9_-]{20,})["']?/gi,
    severity: 'high',
    description: 'Supabase anon key hardcoded. Public by design, but verify RLS policies.',
    lovableLevel: 'L1',
    aiPrompt: 'Move the Supabase anon key to an environment variable (VITE_SUPABASE_ANON_KEY or NEXT_PUBLIC_SUPABASE_ANON_KEY). Ensure Row Level Security is enabled on all tables.',
  },
  // OpenAI
  {
    id: 'OAI-001',
    label: 'OpenAI API Key',
    regex: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b/g,
    severity: 'critical',
    description: 'OpenAI API key — allows AI inference charges and data access.',
    lovableLevel: 'L0',
    aiPrompt: 'Remove the OpenAI key from frontend code immediately. Move all OpenAI API calls to a Supabase Edge Function or server-side route. The key should only exist as a server environment variable.',
  },
  // Anthropic
  {
    id: 'ANT-001',
    label: 'Anthropic API Key',
    regex: /\b(sk-ant-(?:api03-)?[A-Za-z0-9_-]{20,})\b/g,
    severity: 'critical',
    description: 'Anthropic Claude API key exposed.',
    lovableLevel: 'L0',
    aiPrompt: 'Remove the Anthropic key from frontend. Move Claude API calls to a server-side Edge Function. Never expose AI provider keys to browser clients.',
  },
  // AWS
  {
    id: 'AWS-001',
    label: 'AWS Access Key ID',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    severity: 'critical',
    description: 'AWS Access Key ID — can be used to access AWS services.',
    lovableLevel: 'L0',
    aiPrompt: 'Rotate this AWS key immediately via AWS IAM console. Remove it from the codebase. Use AWS Secrets Manager or environment variables server-side only.',
  },
  {
    id: 'AWS-002',
    label: 'AWS Secret Access Key',
    regex: /\b([A-Za-z0-9/+=]{40})\b(?=.*(?:aws|secret))/gi,
    severity: 'critical',
    description: 'Potential AWS Secret Access Key.',
    lovableLevel: 'L0',
    aiPrompt: 'If this is an AWS Secret Key, rotate it immediately via AWS IAM. Remove from codebase and store in server environment only.',
  },
  // Stripe
  {
    id: 'STR-001',
    label: 'Stripe Live Secret Key',
    regex: /\b(sk_live_[A-Za-z0-9]{24,})\b/g,
    severity: 'catastrophic',
    description: 'Stripe LIVE secret key — allows real financial transactions.',
    lovableLevel: 'L0',
    aiPrompt: 'CRITICAL: Rotate this Stripe key immediately at dashboard.stripe.com/apikeys. Remove from frontend. All Stripe payment logic must run server-side via Edge Functions.',
  },
  {
    id: 'STR-002',
    label: 'Stripe Test Secret Key',
    regex: /\b(sk_test_[A-Za-z0-9]{24,})\b/g,
    severity: 'high',
    description: 'Stripe test secret key — should not be in frontend code.',
    lovableLevel: 'L1',
    aiPrompt: 'Move Stripe test key to server environment. Even test keys should not be in client-side code. Use Stripe.js publishable key on the frontend instead.',
  },
  {
    id: 'STR-003',
    label: 'Stripe Publishable Key',
    regex: /\b(pk_(?:live|test)_[A-Za-z0-9]{24,})\b/g,
    severity: 'low',
    description: 'Stripe publishable key — public by design, but verify no secret keys nearby.',
    lovableLevel: 'L1',
    aiPrompt: 'Stripe publishable keys are safe to use in frontend code. Ensure no secret keys (sk_live_ or sk_test_) are also present.',
  },
  // GitHub
  {
    id: 'GH-001',
    label: 'GitHub Personal Access Token',
    regex: /\b(ghp_[A-Za-z0-9]{36,})\b/g,
    severity: 'critical',
    description: 'GitHub PAT — allows code repository access and modifications.',
    lovableLevel: 'L0',
    aiPrompt: 'Revoke this GitHub token immediately at github.com/settings/tokens. Remove from codebase. Use GitHub Actions secrets for CI workflows.',
  },
  {
    id: 'GH-002',
    label: 'GitHub OAuth Token',
    regex: /\b(gho_[A-Za-z0-9]{36,})\b/g,
    severity: 'critical',
    description: 'GitHub OAuth token exposed.',
    lovableLevel: 'L0',
    aiPrompt: 'Revoke this GitHub OAuth token immediately. Remove from codebase.',
  },
  {
    id: 'GH-003',
    label: 'GitHub App Token',
    regex: /\b(ghs_[A-Za-z0-9]{36,})\b/g,
    severity: 'critical',
    description: 'GitHub App installation token.',
    lovableLevel: 'L0',
    aiPrompt: 'Revoke this GitHub App token. Remove from codebase. Use short-lived tokens generated server-side.',
  },
  // Google
  {
    id: 'GCP-001',
    label: 'Google API Key',
    regex: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
    severity: 'high',
    description: 'Google API key — check which APIs are enabled.',
    lovableLevel: 'L1',
    aiPrompt: 'Restrict this Google API key in Google Cloud Console to specific APIs and HTTP referrers. Consider moving sensitive Google API calls server-side.',
  },
  // Slack
  {
    id: 'SLK-001',
    label: 'Slack Bot Token',
    regex: /\b(xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,})\b/g,
    severity: 'critical',
    description: 'Slack bot token — allows posting to channels and accessing workspace data.',
    lovableLevel: 'L0',
    aiPrompt: 'Revoke this Slack token at api.slack.com/apps. Remove from frontend. Move Slack notifications to a server-side Edge Function.',
  },
  {
    id: 'SLK-002',
    label: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g,
    severity: 'medium',
    description: 'Slack incoming webhook URL — allows posting to specific channel.',
    lovableLevel: 'L1',
    aiPrompt: 'Move Slack webhook calls to a server-side Edge Function to avoid exposing the webhook URL in client code.',
  },
  // SendGrid
  {
    id: 'SG-001',
    label: 'SendGrid API Key',
    regex: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,
    severity: 'critical',
    description: 'SendGrid API key — allows sending emails from your account.',
    lovableLevel: 'L0',
    aiPrompt: 'Rotate this SendGrid key at app.sendgrid.com/settings/api_keys. Move all email sending to a Supabase Edge Function.',
  },
  // Twilio
  {
    id: 'TWL-001',
    label: 'Twilio Auth Token',
    regex: /\b([a-f0-9]{32})\b(?=.*(?:twilio|TWILIO))/gi,
    severity: 'critical',
    description: 'Twilio auth token — allows SMS/voice API access.',
    lovableLevel: 'L0',
    aiPrompt: 'Rotate this Twilio token. Remove from frontend. Move Twilio calls to a server-side Edge Function.',
  },
  // Resend
  {
    id: 'RSN-001',
    label: 'Resend API Key',
    regex: /\b(re_[A-Za-z0-9_-]{24,})\b/g,
    severity: 'critical',
    description: 'Resend.com email API key.',
    lovableLevel: 'L0',
    aiPrompt: 'Move Resend API key to a server-side environment. Use a Supabase Edge Function for email sending.',
  },
  // Database connection strings
  {
    id: 'DB-001',
    label: 'PostgreSQL Connection String',
    regex: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^/]+\/\S+/gi,
    severity: 'catastrophic',
    description: 'Direct PostgreSQL connection string — exposes database credentials.',
    lovableLevel: 'L0',
    aiPrompt: 'CRITICAL: Remove this database connection string from frontend code immediately. Rotate the database password. Use Supabase client with anon/service_role keys instead of direct DB connections in client code.',
  },
  {
    id: 'DB-002',
    label: 'DATABASE_URL env var',
    regex: /DATABASE_URL\s*=\s*["']?(postgres[^"'\s]+)["']?/gi,
    severity: 'catastrophic',
    description: 'DATABASE_URL with credentials — must never be in client-side code.',
    lovableLevel: 'L0',
    aiPrompt: 'Remove DATABASE_URL from frontend environment. This must only be available server-side. Use Supabase client library instead of direct database connections in client code.',
  },
  // PEM / Private Keys
  {
    id: 'PEM-001',
    label: 'RSA/EC Private Key (PEM)',
    regex: /-----BEGIN (?:RSA|EC|OPENSSH|DSA)? ?PRIVATE KEY-----/g,
    severity: 'catastrophic',
    description: 'Private cryptographic key exposed in code.',
    lovableLevel: 'L0',
    aiPrompt: 'Remove this private key from the codebase immediately. Revoke/rotate the key pair. Private keys must be stored in secure secret management systems, never in code.',
  },
  // Firebase
  {
    id: 'FB-001',
    label: 'Firebase Service Account',
    regex: /"private_key":\s*"-----BEGIN PRIVATE KEY/g,
    severity: 'catastrophic',
    description: 'Firebase service account private key — full admin access.',
    lovableLevel: 'L0',
    aiPrompt: 'Remove this Firebase service account from frontend code. Regenerate service account credentials. Move Firebase admin operations to server-side only.',
  },
  // JWT generic
  {
    id: 'JWT-001',
    label: 'Generic JWT Token',
    regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    severity: 'medium',
    description: 'Generic JWT — decode to determine type (anon, service_role, user session).',
    lovableLevel: 'L1',
    aiPrompt: 'Decode this JWT to verify its claims. If role is service_role, this is CATASTROPHIC. If it is a long-lived token, rotate it.',
  },
  // Generic password patterns
  {
    id: 'PWD-001',
    label: 'Generic Password Assignment',
    regex: /(?:password|passwd|pwd|secret)\s*[:=]\s*["']([^"']{8,})["']/gi,
    severity: 'high',
    description: 'Hardcoded password detected.',
    lovableLevel: 'L1',
    aiPrompt: 'Remove hardcoded passwords from code. Use environment variables and ensure they are server-side only. Rotate any exposed credentials.',
  },
  // Next.js specific
  {
    id: 'NXT-001',
    label: 'NEXT_PUBLIC service_role key',
    regex: /NEXT_PUBLIC_[A-Z_]*SERVICE_ROLE[A-Z_]*\s*=/gi,
    severity: 'catastrophic',
    description: 'Service role key exposed via NEXT_PUBLIC_ prefix — visible to all users.',
    lovableLevel: 'L0',
    aiPrompt: 'CRITICAL: Remove NEXT_PUBLIC_ prefix from service_role key immediately. NEXT_PUBLIC_ variables are bundled into client JavaScript and visible to all users. Rename to a server-only variable.',
  },
  // Lovable-specific
  {
    id: 'LOV-001',
    label: 'Lovable Bearer Token',
    regex: /Authorization:\s*Bearer\s+(eyJ[A-Za-z0-9_-]{20,})/gi,
    severity: 'high',
    description: 'Lovable session bearer token — allows access to Lovable API.',
    lovableLevel: 'L1',
    aiPrompt: 'Remove Lovable bearer tokens from code. Session tokens should not be hardcoded. Use the Lovable SDK authentication flow.',
  },
];

// ---- PII Patterns ----

export const PII_PATTERNS: PIIPatternDef[] = [
  {
    id: 'PII-001',
    label: 'Email Address',
    regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
    severity: 'medium',
  },
  {
    id: 'PII-002',
    label: 'CPF (Brazilian)',
    regex: /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g,
    severity: 'high',
  },
  {
    id: 'PII-003',
    label: 'CNPJ (Brazilian)',
    regex: /\b\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}\b/g,
    severity: 'high',
  },
  {
    id: 'PII-004',
    label: 'SSN (US)',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    severity: 'high',
  },
  {
    id: 'PII-005',
    label: 'Credit Card Number',
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b/g,
    severity: 'critical',
  },
  {
    id: 'PII-006',
    label: 'Phone Number (BR)',
    regex: /\b(?:\+55\s?)?(?:\(?\d{2}\)?[\s-]?)(?:9?\d{4})[\s-]?\d{4}\b/g,
    severity: 'low',
  },
  {
    id: 'PII-007',
    label: 'LinkedIn URL',
    regex: /https?:\/\/(?:www\.)?linkedin\.com\/in\/[A-Za-z0-9_-]+/gi,
    severity: 'low',
  },
  {
    id: 'PII-008',
    label: 'Stripe Customer ID',
    regex: /\bcus_[A-Za-z0-9]{14,}\b/g,
    severity: 'medium',
  },
];

// ---- Sensitive File Paths ----

export const SENSITIVE_FILE_PATHS = [
  { path: '.env',               severity: 'critical' as const, reason: 'Environment variables file — may contain secrets' },
  { path: '.env.local',         severity: 'critical' as const, reason: 'Local environment variables' },
  { path: '.env.production',    severity: 'critical' as const, reason: 'Production environment variables' },
  { path: 'client.ts',          severity: 'critical' as const, reason: 'Supabase client with embedded credentials' },
  { path: 'supabase/config.toml', severity: 'critical' as const, reason: 'Supabase project configuration' },
  { path: '.git/config',        severity: 'high' as const,     reason: 'Git configuration — may contain credentials' },
  { path: 'firebase.json',      severity: 'high' as const,     reason: 'Firebase project configuration' },
  { path: 'serviceAccountKey.json', severity: 'catastrophic' as const, reason: 'Firebase service account — full admin' },
  { path: 'private.pem',        severity: 'catastrophic' as const, reason: 'Private cryptographic key' },
  { path: 'id_rsa',             severity: 'catastrophic' as const, reason: 'SSH private key' },
];

// ---- Masking (SKILL-01 equivalent) ----

/**
 * Mask a secret value for safe display.
 * Invariant: raw value NEVER leaves this function unmasked.
 */
export function maskSecret(raw: string): { masked: string; hash: string } {
  const hash = createHash('sha256').update(raw).digest('hex');

  let masked: string;
  if (raw.length <= 8) {
    masked = '••••••••';
  } else {
    const showStart = Math.min(4, Math.floor(raw.length * 0.15));
    const showEnd = Math.min(3, Math.floor(raw.length * 0.10));
    const middle = '•'.repeat(Math.max(4, raw.length - showStart - showEnd));
    masked = raw.slice(0, showStart) + middle + raw.slice(-showEnd);
  }

  return { masked, hash };
}

/**
 * Decode a JWT payload (base64url) without verifying signature.
 * Returns null if not a valid JWT.
 */
export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const decoded = Buffer.from(payload, 'base64').toString('utf-8');
    return JSON.parse(decoded) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Determine if a JWT is a Supabase service_role key (CATASTROPHIC).
 */
export function isServiceRoleJwt(token: string): boolean {
  const payload = decodeJwtPayload(token);
  if (!payload) return false;
  return payload.role === 'service_role' || payload.role === 'supabase_admin';
}

/**
 * Shannon entropy for false-positive filtering.
 * High entropy (>3.5) → likely a real secret.
 */
export function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ---- False Positive Allowlist ----

const FP_ALLOWLIST = [
  'your-api-key-here',
  'your_api_key',
  'insert_your_key',
  'xxxx',
  'example',
  'placeholder',
  'test_key',
  'dummy',
  'fake',
  'mock',
  'sk_test_xxxx',
  'sk_live_xxxx',
  'YOUR_SECRET_KEY',
];

export function isFalsePositive(value: string): boolean {
  const lower = value.toLowerCase();
  return FP_ALLOWLIST.some(fp => lower.includes(fp));
}

/**
 * Scan text content for secret patterns.
 * Returns findings with masked values — never raw.
 */
export function scanForSecrets(
  content: string,
  source: string,
): Array<{
  patternId: string;
  label: string;
  masked: string;
  hash: string;
  severity: Severity;
  lovableLevel: LovableLevel;
  aiPrompt: string;
  lineNumber?: number;
  isServiceRole?: boolean;
}> {
  const results = [];
  const lines = content.split('\n');

  for (const pattern of SECRET_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g');
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const raw = match[1] || match[0];

      // False positive filter
      if (isFalsePositive(raw)) continue;

      // Entropy filter for generic patterns
      if (['JWT-001', 'PWD-001'].includes(pattern.id) && shannonEntropy(raw) < 3.0) continue;

      const { masked, hash } = maskSecret(raw);

      // Special handling: detect service_role JWTs
      let isServiceRole = false;
      if (raw.startsWith('eyJ')) {
        isServiceRole = isServiceRoleJwt(raw);
      }

      // Find line number
      const beforeMatch = content.slice(0, match.index);
      const lineNumber = beforeMatch.split('\n').length;

      results.push({
        patternId: pattern.id,
        label: isServiceRole ? 'Supabase Service Role Key (CATASTROPHIC)' : pattern.label,
        masked,
        hash,
        severity: isServiceRole ? 'catastrophic' as const : pattern.severity,
        lovableLevel: pattern.lovableLevel,
        aiPrompt: pattern.aiPrompt || '',
        lineNumber,
        isServiceRole,
      });

      // Avoid duplicate matches at same position
      regex.lastIndex = match.index + 1;
    }
  }

  return results;
}

/**
 * Scan text for PII patterns.
 */
export function scanForPII(
  content: string,
  source: string,
): Array<{
  patternId: string;
  label: string;
  masked: string;
  hash: string;
  severity: Severity;
  lineNumber?: number;
}> {
  const results = [];

  for (const pattern of PII_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g');
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const raw = match[0];
      if (isFalsePositive(raw)) continue;

      const { masked, hash } = maskSecret(raw);
      const beforeMatch = content.slice(0, match.index);
      const lineNumber = beforeMatch.split('\n').length;

      results.push({
        patternId: pattern.id,
        label: pattern.label,
        masked,
        hash,
        severity: pattern.severity,
        lineNumber,
      });

      regex.lastIndex = match.index + 1;
    }
  }

  return results;
}
