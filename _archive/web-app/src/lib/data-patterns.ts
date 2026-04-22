// ============================================================
// Lovable Security Scanner — Security Rules Engine
// ============================================================

import type { SecretPattern, PIIPattern, SensitiveFilePath, SecurityRules, RiskWeights, SeverityThresholds } from './types';

// ---- Secret Patterns ----
const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'supabase_service_role',
    severity: 'critical',
    regex: /eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}(?=.*service_role)[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{20,}/g,
    label: 'Supabase Service Role Key',
    description: 'Grants full admin access to the Supabase database, bypassing all RLS policies',
  },
  {
    id: 'supabase_url',
    severity: 'high',
    regex: /https:\/\/[a-z0-9-]+\.supabase\.co/gi,
    label: 'Supabase Project URL',
    description: 'Identifies the Supabase project — combined with keys, enables direct DB access',
  },
  {
    id: 'supabase_anon_key',
    severity: 'medium',
    regex: /(?:SUPABASE_PUBLISHABLE_KEY|SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY)\s*[:=]\s*['"]?eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/gi,
    label: 'Supabase Anon Key',
    description: 'Public key — safe if RLS is configured, dangerous if RLS is missing',
  },
  {
    id: 'openai_key',
    severity: 'critical',
    regex: /sk-[A-Za-z0-9]{20,}/g,
    label: 'OpenAI API Key',
    description: 'Could be used to generate charges on the account holder',
  },
  {
    id: 'stripe_live_key',
    severity: 'critical',
    regex: /sk_live_[A-Za-z0-9]{16,}/g,
    label: 'Stripe Live Secret Key',
    description: 'Full access to production payment processing',
  },
  {
    id: 'stripe_publishable',
    severity: 'medium',
    regex: /pk_live_[A-Za-z0-9]{16,}/g,
    label: 'Stripe Publishable Live Key',
    description: 'Publishable but still identifies the Stripe account',
  },
  {
    id: 'jwt_secret',
    severity: 'high',
    regex: /(?:JWT_SECRET|AUTH_SECRET|SESSION_SECRET)\s*[:=]\s*['"]?[A-Za-z0-9_\-\.]{12,}/gi,
    label: 'JWT / Auth Secret',
    description: 'Allows forging authentication tokens',
  },
  {
    id: 'db_connection_string',
    severity: 'critical',
    regex: /(?:postgres|mysql|mongodb)(?::\/\/)[^\s"']+/gi,
    label: 'Database Connection String',
    description: 'Direct database access with credentials',
  },
  {
    id: 'aws_access_key',
    severity: 'critical',
    regex: /AKIA[0-9A-Z]{16}/g,
    label: 'AWS Access Key ID',
    description: 'AWS credential — may grant cloud infrastructure access',
  },
  {
    id: 'aws_secret_key',
    severity: 'critical',
    regex: /(?:aws_secret_access_key|AWS_SECRET)\s*[:=]\s*['"]?[A-Za-z0-9\/+=]{40}/gi,
    label: 'AWS Secret Access Key',
    description: 'AWS secret — full access to associated services',
  },
  {
    id: 'sendgrid_key',
    severity: 'high',
    regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    label: 'SendGrid API Key',
    description: 'Email sending service — can be used for phishing',
  },
  {
    id: 'twilio_key',
    severity: 'high',
    regex: /SK[a-f0-9]{32}/g,
    label: 'Twilio API Key',
    description: 'SMS/voice service — can incur charges',
  },
  {
    id: 'firebase_key',
    severity: 'high',
    regex: /AIza[0-9A-Za-z_-]{35}/g,
    label: 'Firebase / Google API Key',
    description: 'Google Cloud API key — scope depends on restrictions',
  },
  {
    id: 'github_token',
    severity: 'critical',
    regex: /gh[ps]_[A-Za-z0-9_]{36,}/g,
    label: 'GitHub Personal Access Token',
    description: 'Repository access — may include write permissions',
  },
  {
    id: 'generic_password',
    severity: 'medium',
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    label: 'Hardcoded Password',
    description: 'Password found in source code',
  },
  {
    id: 'private_key_block',
    severity: 'critical',
    regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
    label: 'Private Key',
    description: 'Cryptographic private key found in source code',
  },
  {
    id: 'resend_key',
    severity: 'high',
    regex: /re_[A-Za-z0-9]{20,}/g,
    label: 'Resend API Key',
    description: 'Email service key — can be used for sending emails',
  },
  {
    id: 'anthropic_key',
    severity: 'critical',
    regex: /sk-ant-[A-Za-z0-9_-]{20,}/g,
    label: 'Anthropic API Key',
    description: 'Anthropic Claude API Key',
  },
  {
    id: 'slack_token',
    severity: 'critical',
    regex: /xox[baprs]-[0-9A-Za-z-]{10,}/g,
    label: 'Slack Token',
    description: 'Slack API Token',
  },
  {
    id: 'huggingface_token',
    severity: 'high',
    regex: /hf_[A-Za-z0-9]{30,}/g,
    label: 'HuggingFace Token',
    description: 'HuggingFace Access Token',
  },
  {
    id: 'mistral_key',
    severity: 'high',
    regex: /(?:mistral[_-]?(?:api[_-]?)?key|MISTRAL_API_KEY)\s*[=:]\s*['"][A-Za-z0-9_-]{32,}['"]/g,
    label: 'Mistral API Key',
    description: 'Mistral AI API Key',
  },
  {
    id: 'pinecone_key',
    severity: 'high',
    regex: /(?:pinecone[_-]?(?:api[_-]?)?key|PINECONE_API_KEY)\s*[=:]\s*['"][a-z0-9-]{36,}['"]/g,
    label: 'Pinecone API Key',
    description: 'Pinecone Vector DB Key',
  },
  {
    id: 'cohere_key',
    severity: 'high',
    regex: /(?:cohere[_-]?(?:api[_-]?)?key|COHERE_API_KEY)\s*[=:]\s*['"][A-Za-z0-9]{40,}['"]/g,
    label: 'Cohere API Key',
    description: 'Cohere AI API Key',
  },
  {
    id: 'google_oauth_secret',
    severity: 'critical',
    regex: /GOCSPX-[A-Za-z0-9_-]{28}/g,
    label: 'Google OAuth Client Secret',
    description: 'Google OAuth 2.0 Client Secret',
  },
];

// ---- PII Patterns ----
const PII_PATTERNS: PIIPattern[] = [
  {
    id: 'email_address',
    severity: 'medium',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    label: 'Email Address',
  },
  {
    id: 'linkedin_url',
    severity: 'medium',
    regex: /https?:\/\/(?:www\.)?linkedin\.com\/in\/[A-Za-z0-9_\-\/%?=.&]+/gi,
    label: 'LinkedIn Profile URL',
  },
  {
    id: 'dob_field',
    severity: 'high',
    regex: /(?:date_of_birth|birth_date|dob|birthdate)\b/gi,
    label: 'Date of Birth Field',
  },
  {
    id: 'cpf_field',
    severity: 'critical',
    regex: /(?:cpf|cnpj|social_security|ssn)\b/gi,
    label: 'Tax/ID Number Field (CPF/CNPJ/SSN)',
  },
  {
    id: 'phone_number',
    severity: 'medium',
    regex: /(?:phone|telefone|celular|mobile)\s*[:=]\s*['"]?\+?\d[\d\s\-()]{8,}/gi,
    label: 'Phone Number',
  },
  {
    id: 'stripe_customer',
    severity: 'high',
    regex: /cus_[A-Za-z0-9]{14,}/g,
    label: 'Stripe Customer ID',
  },
  {
    id: 'credit_card_pattern',
    severity: 'critical',
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g,
    label: 'Credit Card Number Pattern',
  },
];

// ---- Sensitive File Paths ----
const SENSITIVE_FILE_PATHS: SensitiveFilePath[] = [
  { path: '.env', severity: 'critical', reason: 'Environment variables often contain secrets' },
  { path: '.env.local', severity: 'critical', reason: 'Local env overrides with secrets' },
  { path: '.env.production', severity: 'critical', reason: 'Production credentials' },
  { path: '.env.development', severity: 'high', reason: 'Development credentials' },
  { path: 'supabase/functions', severity: 'high', reason: 'Edge functions may contain server-side secrets' },
  { path: 'prisma/schema.prisma', severity: 'medium', reason: 'Database schema reveals data model' },
  { path: 'src/integrations/supabase/client.ts', severity: 'high', reason: 'Lovable-generated Supabase client often has hardcoded keys' },
  { path: '.lovable/plan.md', severity: 'medium', reason: 'Build plan reveals architecture and business logic' },
  { path: 'supabase/config.toml', severity: 'medium', reason: 'Supabase project configuration' },
  { path: '.git/config', severity: 'high', reason: 'Git config may contain auth tokens' },
  { path: 'docker-compose.yml', severity: 'medium', reason: 'May contain service credentials' },
  { path: 'firebase.json', severity: 'medium', reason: 'Firebase project configuration' },
  { path: '.firebaserc', severity: 'medium', reason: 'Firebase project references' },
];

// ---- Risk Weights ----
const RISK_WEIGHTS: RiskWeights = {
  unauthorized_file_access_200: 60,
  unauthorized_chat_access_200: 60,
  critical_secret_match: 30,
  high_secret_match: 20,
  pii_match: 20,
  active_project_30d: 10,
};

// ---- Severity Thresholds ----
const SEVERITY_THRESHOLDS: SeverityThresholds = {
  critical_min: 80,
  high_min: 50,
  medium_min: 20,
};

// ---- Exported Rules ----
export const SECURITY_RULES: SecurityRules = {
  secretPatterns: SECRET_PATTERNS,
  piiPatterns: PII_PATTERNS,
  sensitiveFilePaths: SENSITIVE_FILE_PATHS,
  riskWeights: RISK_WEIGHTS,
  severityThresholds: SEVERITY_THRESHOLDS,
};

// ---- Content Analysis Functions ----

export interface PatternMatch {
  patternId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  label: string;
  description: string;
  match: string;
  masked: string;
  line?: number;
}

/**
 * Mask sensitive data for display — show first 4 and last 4 chars
 */
function maskSecret(value: string): string {
  if (value.length <= 12) return value.slice(0, 3) + '•'.repeat(value.length - 3);
  return value.slice(0, 4) + '•'.repeat(value.length - 8) + value.slice(-4);
}

/**
 * Scan content for secret patterns
 */
export function scanForSecrets(content: string, filePath?: string): PatternMatch[] {
  const matches: PatternMatch[] = [];
  const seen = new Set<string>();

  for (const pattern of SECRET_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      const key = `${pattern.id}:${match[0]}`;
      if (seen.has(key)) continue;
      seen.add(key);

      // Find line number
      let line: number | undefined;
      if (filePath) {
        const before = content.slice(0, match.index);
        line = (before.match(/\n/g) || []).length + 1;
      }

      matches.push({
        patternId: pattern.id,
        severity: pattern.severity,
        label: pattern.label,
        description: pattern.description,
        match: match[0],
        masked: maskSecret(match[0]),
        line,
      });
    }
  }

  return matches;
}

/**
 * Scan content for PII patterns
 */
export function scanForPII(content: string): PatternMatch[] {
  const matches: PatternMatch[] = [];
  const seen = new Set<string>();

  for (const pattern of PII_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      const key = `${pattern.id}:${match[0]}`;
      if (seen.has(key)) continue;
      seen.add(key);

      matches.push({
        patternId: pattern.id,
        severity: pattern.severity,
        label: pattern.label,
        description: '',
        match: match[0],
        masked: maskSecret(match[0]),
      });
    }
  }

  return matches;
}

/**
 * Check if a file path is in the sensitive list
 */
export function isSensitiveFile(filePath: string): SensitiveFilePath | null {
  const normalized = filePath.replace(/\\/g, '/').replace(/^\/+/, '');
  for (const sf of SENSITIVE_FILE_PATHS) {
    if (normalized === sf.path || normalized.endsWith('/' + sf.path) || normalized.startsWith(sf.path + '/')) {
      return sf;
    }
  }
  return null;
}
