// SKILL-04: token-vault
// AES-GCM + PBKDF2 para tokens em chrome.storage.local.
// Chave derivada vive APENAS em memória — nunca persistida.

import { createLogger } from './structured-logger.js';

const logger = createLogger({ module: 'token-vault' });
const VAULT_KEY = 'lpa:vault';
const VERIFY_MARKER = 'lpa:vault:verify:2026';
const PBKDF2_ITERATIONS = 600_000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

let derivedKey = null;

function toB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function fromB64(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function deriveKey(passphrase, salt) {
  const material = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function readStorage() {
  const result = await chrome.storage.local.get(VAULT_KEY);
  return result[VAULT_KEY] ?? null;
}

async function writeStorage(data) {
  await chrome.storage.local.set({ [VAULT_KEY]: data });
}

async function encryptRaw(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext),
  );
  return { cipher: toB64(cipher), iv: toB64(iv.buffer), createdAt: new Date().toISOString() };
}

async function decryptRaw(key, entry) {
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(entry.iv) },
    key,
    fromB64(entry.cipher),
  );
  return new TextDecoder().decode(plaintext);
}

export async function isInitialized() {
  return (await readStorage()) !== null;
}

export async function initVault(passphrase) {
  if (await isInitialized()) throw new Error('Vault already initialized. Use reset() to recreate.');
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const key = await deriveKey(passphrase, salt);
  const verifyEntry = await encryptRaw(key, VERIFY_MARKER);
  derivedKey = key;
  await writeStorage({ salt: toB64(salt.buffer), entries: { __verify__: verifyEntry } });
  logger.info('vault initialized');
}

export async function unlock(passphrase) {
  const storage = await readStorage();
  if (!storage) return false;
  try {
    const key = await deriveKey(passphrase, fromB64(storage.salt));
    const verifyEntry = storage.entries.__verify__;
    if (!verifyEntry) return false;
    const decrypted = await decryptRaw(key, verifyEntry);
    if (decrypted !== VERIFY_MARKER) return false;
    derivedKey = key;
    logger.info('vault unlocked');
    return true;
  } catch {
    return false;
  }
}

export async function lock() {
  derivedKey = null;
  logger.info('vault locked');
}

export async function isUnlocked() {
  return derivedKey !== null;
}

export async function putToken(name, value) {
  if (!derivedKey) throw new Error('Vault is locked');
  if (name === '__verify__') throw new Error('Reserved name');
  const storage = (await readStorage());
  if (!storage) throw new Error('Vault not initialized');
  storage.entries[name] = await encryptRaw(derivedKey, value);
  await writeStorage(storage);
}

export async function getToken(name) {
  if (!derivedKey) throw new Error('Vault is locked');
  const storage = await readStorage();
  const entry = storage?.entries[name];
  if (!entry) return null;
  try {
    return await decryptRaw(derivedKey, entry);
  } catch {
    return null;
  }
}

export async function deleteToken(name) {
  const storage = await readStorage();
  if (!storage) return;
  delete storage.entries[name];
  await writeStorage(storage);
}

export async function listTokenNames() {
  const storage = await readStorage();
  if (!storage) return [];
  return Object.keys(storage.entries).filter(k => k !== '__verify__');
}

export async function reset() {
  derivedKey = null;
  await chrome.storage.local.remove(VAULT_KEY);
  logger.info('vault reset');
}

// Migration: move legacy plaintext token to vault
export async function migrateLegacyToken() {
  const result = await chrome.storage.local.get(['lpa:token', 'lpa:ownerToken']);
  const legacy = result['lpa:token'] || result['lpa:ownerToken'];
  if (legacy && (await isUnlocked())) {
    await putToken('lovable:owner', legacy);
    await chrome.storage.local.remove(['lpa:token', 'lpa:ownerToken']);
    logger.info('legacy token migrated to vault');
  }
}
