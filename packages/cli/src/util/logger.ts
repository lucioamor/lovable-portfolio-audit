// ============================================================
// @nxlv-ai/lovable-audit — Structured Logger (H2 parity with extension)
// ============================================================
// Drop-in replacement for raw console.* that strips secrets before
// anything reaches stdout/stderr — even under --verbose.
//
// Mirrors extension/lib/skills/structured-logger.js:
//   - field-name blacklist (token/cookie/body/secret/key/password/auth)
//   - value regex redaction (JWT/CPF/email + provider key shapes)
//
// Invariant: no raw token, cookie, secret, JWT, CPF or email ever
// appears in emitted output.
// ============================================================

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };

let globalLevel: LogLevel = 'info';
export function setGlobalLevel(level: LogLevel): void {
  globalLevel = level;
}

// ---- Value-level redaction (regex) ----
// Order matters: most-specific provider shapes before the generic ones.
const SENSITIVE_PATTERNS: Array<{ kind: string; regex: RegExp }> = [
  { kind: 'JWT',         regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { kind: 'Anthropic',   regex: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { kind: 'OpenAI',      regex: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g },
  { kind: 'Stripe-live', regex: /sk_live_[A-Za-z0-9]{24,}/g },
  { kind: 'Stripe-test', regex: /sk_test_[A-Za-z0-9]{24,}/g },
  { kind: 'AWS',         regex: /AKIA[0-9A-Z]{16}/g },
  { kind: 'GitHub-PAT',  regex: /gh[pousr]_[A-Za-z0-9]{36,}/g },
  { kind: 'Bearer',      regex: /Bearer\s+[A-Za-z0-9._-]{20,}/gi },
  { kind: 'CPF',         regex: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g },
  { kind: 'Email',       regex: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
];

// ---- Field-name redaction (blacklist) ----
// A key whose name matches is dropped wholesale regardless of its value.
const BLACKLIST_FIELDS = /^(authorization|cookie|body|password|token|secret|apikey|api_key|bearer|auth|key)$/i;

const MAX_STRING = 500;

/**
 * Recursively redact a value: scrub sensitive substrings from strings,
 * drop blacklisted object keys, cap string/array sizes.
 */
export function redact(value: unknown, seen: WeakSet<object> = new WeakSet()): unknown {
  if (value === null || value === undefined) return value;

  if (typeof value === 'string') {
    let out = value;
    for (const { kind, regex } of SENSITIVE_PATTERNS) {
      out = out.replace(new RegExp(regex.source, regex.flags), `[REDACTED:${kind}]`);
    }
    return out.length > MAX_STRING ? out.slice(0, MAX_STRING - 3) + '...' : out;
  }

  if (typeof value !== 'object') return value;

  if (seen.has(value as object)) return '[Circular]';
  seen.add(value as object);

  if (Array.isArray(value)) {
    return value.slice(0, 50).map(v => redact(v, seen));
  }

  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = BLACKLIST_FIELDS.test(k) ? '[REDACTED:FieldName]' : redact(v, seen);
  }
  return out;
}

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  context: Record<string, unknown>;
  stack?: string;
}

export interface Logger {
  debug(msg: string, ctx?: Record<string, unknown>): void;
  info(msg: string, ctx?: Record<string, unknown>): void;
  warn(msg: string, ctx?: Record<string, unknown>): void;
  error(msg: string, err?: unknown, ctx?: Record<string, unknown>): void;
  child(scope: Record<string, unknown>): Logger;
  flush(): LogEntry[];
}

class LoggerImpl implements Logger {
  private buffer: LogEntry[] = [];
  private ctx: Record<string, unknown>;

  constructor(ctx: Record<string, unknown> = {}) {
    this.ctx = ctx;
  }

  private emit(level: LogLevel, message: string, context: Record<string, unknown> = {}, error?: unknown): void {
    if (LEVEL_ORDER[level] < LEVEL_ORDER[globalLevel]) return;

    const merged = { ...this.ctx, ...context };
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message: redact(message) as string,
      context: redact(merged) as Record<string, unknown>,
      // Stacks can embed tokens (e.g. URLs with credentials) — redact too.
      stack: error instanceof Error ? (redact(error.stack) as string) : undefined,
    };
    this.buffer.push(entry);

    const fn = level === 'error' ? console.error
             : level === 'warn'  ? console.warn
             : level === 'debug' ? console.debug
             : console.log;
    const tag = `[${level.toUpperCase()}]`;
    if (Object.keys(entry.context).length > 0) {
      fn(`${tag} ${entry.message}`, entry.context);
    } else {
      fn(`${tag} ${entry.message}`);
    }
  }

  debug(msg: string, ctx: Record<string, unknown> = {}): void { this.emit('debug', msg, ctx); }
  info(msg: string, ctx: Record<string, unknown> = {}): void { this.emit('info', msg, ctx); }
  warn(msg: string, ctx: Record<string, unknown> = {}): void { this.emit('warn', msg, ctx); }
  error(msg: string, err?: unknown, ctx: Record<string, unknown> = {}): void { this.emit('error', msg, ctx, err); }

  child(scope: Record<string, unknown>): Logger {
    return new LoggerImpl({ ...this.ctx, ...scope });
  }

  flush(): LogEntry[] {
    return this.buffer.slice();
  }
}

export function createLogger(defaultContext: Record<string, unknown> = {}): Logger {
  return new LoggerImpl(defaultContext);
}
