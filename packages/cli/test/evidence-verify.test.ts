// ============================================================
// P20 — Evidence-pack verifier (HMAC-SHA256, matches the extension recipe)
// ============================================================
import { describe, it, expect } from 'vitest';
import { webcrypto } from 'crypto';
import { extractPack, verifyPack, signPayload } from '../src/engines/evidence-verify';

const PASSPHRASE = 'correct horse battery staple';

// A representative signed object (the pack/payload that gets HMAC'd).
const SIGNED_OBJECT = {
  version: 'nxlv-evidence-pack/v1',
  generated_at: '2026-06-26T00:00:00.000Z',
  tool: 'lovable-portfolio-audit',
  summary: { total_projects: 1, critical: 1 },
  findings: [
    { project_id: 'p1', project_name: 'Alpha', severity: 'critical', risk_score: 90 },
  ],
};

// Independent reference signer using the README/extension recipe byte-for-byte,
// to prove our verifier agrees with an outside implementation.
async function referenceSign(obj: unknown, passphrase: string): Promise<string> {
  const enc = new TextEncoder();
  const payloadStr = JSON.stringify(obj, null, 2);
  const base = await webcrypto.subtle.importKey(
    'raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey'],
  );
  const key = await webcrypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode('lpa-evidence-v1'), iterations: 100000, hash: 'SHA-256' },
    base, { name: 'HMAC', hash: 'SHA-256' }, true, ['sign'],
  );
  const sig = await webcrypto.subtle.sign('HMAC', key, enc.encode(payloadStr));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

describe('signPayload matches the reference (extension) recipe', () => {
  it('produces the same lowercase-hex HMAC as an independent signer', async () => {
    const a = await signPayload(SIGNED_OBJECT, PASSPHRASE);
    const b = await referenceSign(SIGNED_OBJECT, PASSPHRASE);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('extractPack — supported export shapes', () => {
  it('side-panel shape: { _signature, pack }', () => {
    const p = extractPack({ _format: 'x', _signature: 'AB', pack: { a: 1 } });
    expect(p.signatureHex).toBe('ab'); // lowercased
    expect(p.signedObject).toEqual({ a: 1 });
  });

  it('README portable shape: { hmac_sha256, payload }', () => {
    const p = extractPack({ hmac_sha256: 'CD', payload: { b: 2 } });
    expect(p.signatureHex).toBe('cd');
    expect(p.signedObject).toEqual({ b: 2 });
  });

  it('throws on an unrecognized shape', () => {
    expect(() => extractPack({ nope: true })).toThrow(/Unrecognized/);
  });
});

describe('verifyPack', () => {
  it('returns VALID for a correctly signed side-panel pack', async () => {
    const signature = await signPayload(SIGNED_OBJECT, PASSPHRASE);
    const file = { _format: 'nxlv-evidence-pack/v1', _signature: signature, pack: SIGNED_OBJECT };
    expect(await verifyPack(extractPack(file), PASSPHRASE)).toBe(true);
  });

  it('returns VALID for a correctly signed README-shape pack', async () => {
    const signature = await referenceSign(SIGNED_OBJECT, PASSPHRASE);
    const file = { hmac_sha256: signature, payload: SIGNED_OBJECT };
    expect(await verifyPack(extractPack(file), PASSPHRASE)).toBe(true);
  });

  it('returns INVALID when the payload is tampered', async () => {
    const signature = await signPayload(SIGNED_OBJECT, PASSPHRASE);
    const tampered = { ...SIGNED_OBJECT, summary: { total_projects: 1, critical: 0 } };
    const file = { _signature: signature, pack: tampered };
    expect(await verifyPack(extractPack(file), PASSPHRASE)).toBe(false);
  });

  it('returns INVALID with the wrong passphrase', async () => {
    const signature = await signPayload(SIGNED_OBJECT, PASSPHRASE);
    const file = { _signature: signature, pack: SIGNED_OBJECT };
    expect(await verifyPack(extractPack(file), 'wrong passphrase')).toBe(false);
  });

  it('throws on a non-hex signature', async () => {
    await expect(verifyPack({ signedObject: {}, signatureHex: 'zz' }, PASSPHRASE))
      .rejects.toThrow(/hex/);
  });
});
