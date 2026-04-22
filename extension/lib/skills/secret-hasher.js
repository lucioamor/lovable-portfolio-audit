// SKILL-01: secret-hasher
// Única porta de saída para valores brutos.
// Invariante: nenhum outro módulo pode exportar hashSecret.

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += HEX[bytes[i]];
  return out;
}

export async function hashSecret(raw) {
  if (typeof raw !== 'string' || raw.length === 0) {
    throw new TypeError('hashSecret requires a non-empty string');
  }
  const encoded = new TextEncoder().encode(raw);
  const digest = await crypto.subtle.digest('SHA-256', encoded);
  return Object.freeze({
    masked: maskSecret(raw),
    hash: bufferToHex(digest),
    length: raw.length,
    prefix: raw.slice(0, 4),
  });
}

export function maskSecret(raw, visibleStart = 4, visibleEnd = 3) {
  if (!raw || raw.length === 0) return '••••••••';
  if (raw.length <= visibleStart + visibleEnd + 2) {
    return '•'.repeat(Math.min(raw.length, 12));
  }
  const start = raw.slice(0, visibleStart);
  const end = raw.slice(-visibleEnd);
  const hiddenLen = Math.min(raw.length - visibleStart - visibleEnd, 12);
  return `${start}${'•'.repeat(hiddenLen)}${end}`;
}
