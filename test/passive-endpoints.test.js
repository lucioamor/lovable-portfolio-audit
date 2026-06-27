// ============================================================
// C2 — Passive endpoint registry / 5th-endpoint detection (P7)
// ============================================================
import { describe, it, expect } from 'vitest';
import {
  normalizeLovablePath,
  isKnownEndpoint,
  KNOWN_ENDPOINTS,
} from '../extension/lib/passive-endpoints.js';

const UUID = '1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d';

describe('normalizeLovablePath', () => {
  it('collapses the project id', () => {
    expect(normalizeLovablePath(`https://api.lovable.dev/projects/${UUID}`)).toBe('/projects/:id');
  });
  it('normalizes the messages endpoint', () => {
    expect(normalizeLovablePath(`https://api.lovable.dev/projects/${UUID}/messages`)).toBe('/projects/:id/messages');
  });
  it('normalizes git files listing and individual file', () => {
    expect(normalizeLovablePath(`https://api.lovable.dev/projects/${UUID}/git/files`)).toBe('/projects/:id/git/files');
    expect(normalizeLovablePath(`https://api.lovable.dev/projects/${UUID}/git/files/src%2Fmain.ts`)).toBe('/projects/:id/git/files/:file');
  });
  it('handles a relative path string', () => {
    expect(normalizeLovablePath(`/user/projects`)).toBe('/user/projects');
  });
  it('strips query strings', () => {
    expect(normalizeLovablePath(`https://api.lovable.dev/projects/${UUID}?foo=bar`)).toBe('/projects/:id');
  });
});

describe('isKnownEndpoint / 5th-endpoint detection', () => {
  it('recognizes all 4 documented endpoints + project list', () => {
    for (const ep of KNOWN_ENDPOINTS) expect(isKnownEndpoint(ep)).toBe(true);
  });
  it('flags an unseen endpoint as a candidate', () => {
    const norm = normalizeLovablePath(`https://api.lovable.dev/projects/${UUID}/deployments`);
    expect(norm).toBe('/projects/:id/deployments');
    expect(isKnownEndpoint(norm)).toBe(false); // → P7 candidate
  });
  it('flags a billing endpoint as unknown', () => {
    expect(isKnownEndpoint(normalizeLovablePath('https://api.lovable.dev/user/billing'))).toBe(false);
  });
});
