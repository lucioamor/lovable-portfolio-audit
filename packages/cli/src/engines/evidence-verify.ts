// ============================================================
// @nxlv/audit — Evidence-pack verifier (P20)
// ============================================================
// Verifies the HMAC-SHA256 signature of an exported evidence pack, matching
// extension/lib/evidence-pack.js byte-for-byte:
//   key  = PBKDF2(passphrase, salt='lpa-evidence-v1', 100000 iters, SHA-256)
//          → HMAC-SHA256 key
//   sig  = HMAC-SHA256 over JSON.stringify(<signed-object>, null, 2)
//   hex  = lowercase
//
// The signed object is the pack's `payload`/`pack` object re-serialized with
// 2-space indent. Two export shapes are supported:
//   1. extension side-panel export: { _format, _signature, pack: {...} }
//   2. README portable recipe:      { hmac_sha256, payload: {...} }
// ============================================================

import { webcrypto } from 'crypto';

const PBKDF2_SALT = 'lpa-evidence-v1';
const PBKDF2_ITERATIONS = 100000;

export interface ParsedPack {
  /** The object that was signed (re-serialized to compute the HMAC). */
  signedObject: unknown;
  /** The stored signature, lowercase hex. */
  signatureHex: string;
}

/**
 * Extract the signed object and stored signature from a parsed pack file,
 * supporting both known export shapes. Throws a clean Error if neither matches.
 */
export function extractPack(file: unknown): ParsedPack {
  if (typeof file !== 'object' || file === null) {
    throw new Error('Evidence pack is not a JSON object.');
  }
  const obj = file as Record<string, unknown>;

  // Shape 1: side-panel export ({ _signature, pack })
  if (typeof obj._signature === 'string' && obj.pack !== undefined) {
    return { signedObject: obj.pack, signatureHex: obj._signature.toLowerCase() };
  }
  // Shape 2: README portable recipe ({ hmac_sha256, payload })
  if (typeof obj.hmac_sha256 === 'string' && obj.payload !== undefined) {
    return { signedObject: obj.payload, signatureHex: obj.hmac_sha256.toLowerCase() };
  }
  // Tolerant fallback: { signature, payload|pack }
  if (typeof obj.signature === 'string' && (obj.payload !== undefined || obj.pack !== undefined)) {
    return {
      signedObject: obj.payload !== undefined ? obj.payload : obj.pack,
      signatureHex: obj.signature.toLowerCase(),
    };
  }

  throw new Error(
    'Unrecognized evidence-pack shape. Expected a signature field ' +
    '(_signature / hmac_sha256 / signature) plus the signed object (pack / payload).',
  );
}

/** Derive the HMAC-SHA256 signing key from a passphrase (matches the extension). */
async function deriveKey(passphrase: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const base = await webcrypto.subtle.importKey(
    'raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey'],
  );
  return webcrypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(PBKDF2_SALT), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(hex)) {
    throw new Error('Signature is not valid hex.');
  }
  const matches = hex.match(/.{2}/g) as string[];
  return new Uint8Array(matches.map(h => parseInt(h, 16)));
}

/**
 * Verify a pack. Re-serializes the signed object with JSON.stringify(_, null, 2)
 * and checks the HMAC against the stored signature. Returns true/false; never
 * throws for a mismatch (only for malformed input).
 */
export async function verifyPack(parsed: ParsedPack, passphrase: string): Promise<boolean> {
  const payloadStr = JSON.stringify(parsed.signedObject, null, 2);
  const key = await deriveKey(passphrase);
  const sigBytes = hexToBytes(parsed.signatureHex);
  return webcrypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(payloadStr));
}

/** Convenience for tests / tooling: sign a payload object with a passphrase. */
export async function signPayload(signedObject: unknown, passphrase: string): Promise<string> {
  const payloadStr = JSON.stringify(signedObject, null, 2);
  const key = await deriveKey(passphrase);
  const sig = await webcrypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadStr));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}
