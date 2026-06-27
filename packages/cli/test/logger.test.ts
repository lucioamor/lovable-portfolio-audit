// ============================================================
// A2 — CLI structured logger redaction (H2 parity)
// ============================================================
// Asserts that no raw token, secret, JWT, CPF or email survives the
// logger's redaction — the invariant behind "no leak even with --verbose".
// ============================================================

import { describe, it, expect } from 'vitest';
import { redact, createLogger, setGlobalLevel } from '../src/util/logger';

describe('redact — value-level', () => {
  it('scrubs a JWT', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.AbCdEfGhIjKlMnOpQrStUvWxYz123456';
    const out = redact(jwt) as string;
    expect(out).not.toContain('eyJ');
    expect(out).toContain('[REDACTED:JWT]');
  });

  it('scrubs an OpenAI key', () => {
    expect(redact('key sk-proj-abcdefghijklmnopqrstuvwx here') as string).toContain('[REDACTED:OpenAI]');
  });

  it('scrubs a Bearer header value', () => {
    const out = redact('Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123') as string;
    expect(out).toContain('[REDACTED:Bearer]');
    expect(out).not.toContain('abcdefghijklmnopqrstuvwxyz0123');
  });

  it('scrubs CPF and email', () => {
    const out = redact('user joao@example.com cpf 123.456.789-09') as string;
    expect(out).toContain('[REDACTED:Email]');
    expect(out).toContain('[REDACTED:CPF]');
    expect(out).not.toContain('joao@example.com');
  });
});

describe('redact — field-name blacklist', () => {
  it('drops blacklisted keys wholesale', () => {
    const out = redact({ token: 'raw-token-value', cookie: 'sb=abc', nested: { password: 'hunter2', ok: 'visible' } }) as Record<string, any>;
    expect(out.token).toBe('[REDACTED:FieldName]');
    expect(out.cookie).toBe('[REDACTED:FieldName]');
    expect(out.nested.password).toBe('[REDACTED:FieldName]');
    expect(out.nested.ok).toBe('visible');
  });

  it('handles circular references', () => {
    const a: any = { name: 'a' };
    a.self = a;
    const out = redact(a) as Record<string, any>;
    expect(out.self).toBe('[Circular]');
  });
});

describe('logger emit', () => {
  it('redacts message and context, and nothing raw reaches the buffer', () => {
    setGlobalLevel('debug');
    const log = createLogger({ module: 'test' });
    log.info('saw token eyJaaaaaaaaaaa.bbbbbbbbbbb.ccccccccccc', { token: 'secret', path: '/projects/x' });
    const entries = log.flush();
    expect(entries).toHaveLength(1);
    expect(entries[0].message).toContain('[REDACTED:JWT]');
    expect(entries[0].context.token).toBe('[REDACTED:FieldName]');
    expect(entries[0].context.path).toBe('/projects/x');
    setGlobalLevel('info');
  });

  it('respects level filtering', () => {
    setGlobalLevel('warn');
    const log = createLogger();
    log.info('quiet');
    log.warn('loud');
    expect(log.flush().map(e => e.message)).toEqual(['loud']);
    setGlobalLevel('info');
  });
});
