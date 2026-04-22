// SKILL-07: structured-logger
// Substitui console.log por logger que redaciona secrets antes de emitir.

const LEVEL_ORDER = { debug: 0, info: 1, warn: 2, error: 3 };
let globalLevel = 'info';
export const setGlobalLevel = (level) => { globalLevel = level; };

const SENSITIVE_PATTERNS = [
  { kind: 'JWT',         regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { kind: 'OpenAI',      regex: /sk-[A-Za-z0-9]{20,}/g },
  { kind: 'Anthropic',   regex: /sk-ant-[A-Za-z0-9]{20,}/g },
  { kind: 'Stripe-live', regex: /sk_live_[A-Za-z0-9]{24,}/g },
  { kind: 'Stripe-test', regex: /sk_test_[A-Za-z0-9]{24,}/g },
  { kind: 'AWS',         regex: /AKIA[0-9A-Z]{16}/g },
  { kind: 'GitHub-PAT',  regex: /ghp_[A-Za-z0-9]{36}/g },
  { kind: 'Bearer',      regex: /Bearer\s+[A-Za-z0-9._-]{20,}/gi },
  { kind: 'Email',       regex: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
];

const BLACKLIST_FIELDS = /^(authorization|cookie|password|token|secret|apikey|api_key|bearer)$/i;

function redact(value, seen = new WeakSet()) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    let r = value;
    for (const { kind, regex } of SENSITIVE_PATTERNS) {
      r = r.replace(new RegExp(regex.source, regex.flags), `[REDACTED:${kind}]`);
    }
    return r.length > 500 ? r.slice(0, 497) + '...' : r;
  }
  if (typeof value !== 'object') return value;
  if (seen.has(value)) return '[Circular]';
  seen.add(value);
  if (Array.isArray(value)) {
    return value.slice(0, 50).map(v => redact(v, seen));
  }
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = BLACKLIST_FIELDS.test(k) ? '[REDACTED:FieldName]' : redact(v, seen);
  }
  return out;
}

class LoggerImpl {
  #buffer = [];
  #ctx;
  constructor(ctx = {}) { this.#ctx = ctx; }

  #emit(level, message, context = {}, error) {
    if (LEVEL_ORDER[level] < LEVEL_ORDER[globalLevel]) return;
    const merged = { ...this.#ctx, ...context };
    const entry = Object.freeze({
      timestamp: new Date().toISOString(),
      level,
      message: redact(message),
      context: redact(merged),
      stack: error instanceof Error ? error.stack : undefined,
    });
    this.#buffer.push(entry);
    const fn = level === 'error' ? console.error
             : level === 'warn'  ? console.warn
             : level === 'debug' ? console.debug
             : console.log;
    fn(`[${level.toUpperCase()}] ${entry.message}`, entry.context);
  }

  debug(msg, ctx = {}) { this.#emit('debug', msg, ctx); }
  info(msg, ctx = {})  { this.#emit('info', msg, ctx); }
  warn(msg, ctx = {})  { this.#emit('warn', msg, ctx); }
  error(msg, err, ctx = {}) { this.#emit('error', msg, ctx, err); }
  child(scope) { return new LoggerImpl({ ...this.#ctx, ...scope }); }
  flush() { return this.#buffer.slice(); }
}

export function createLogger(defaultContext = {}) {
  return new LoggerImpl(defaultContext);
}
