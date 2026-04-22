// SKILL-02: dual-probe
// Substitui booleano isVulnerable pela response_signature baseada em matriz owner×audit.
// Sem segundo token, não há prova de BOLA — só de acesso do dono.

import { createLogger } from './structured-logger.js';

const logger = createLogger({ module: 'dual-probe' });

const SIGNATURE_MATRIX = {
  '200:200': 'vulnerable',
  '200:403': 'patched',
  '200:404': 'patched',
  '200:401': 'auth_required',
  '200:429': 'rate_limited',
};

function classify(ownerStatus, auditStatus) {
  if (ownerStatus >= 500 || auditStatus >= 500) return 'error';
  if ([401, 403, 0].includes(ownerStatus)) return 'inaccessible';
  return SIGNATURE_MATRIX[`${ownerStatus}:${auditStatus}`] ?? 'error';
}

async function doFetch(url, token) {
  const started = performance.now();
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      credentials: 'omit',
    });
    // PRIVACY INVARIANT: não lemos body, apenas metadata
    const contentLength = Number(response.headers.get('content-length')) || undefined;
    return {
      status: response.status,
      contentLength,
      latencyMs: Math.round(performance.now() - started),
    };
  } catch (err) {
    return {
      status: 0,
      errorCode: err.name || 'network_error',
      latencyMs: Math.round(performance.now() - started),
    };
  }
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

export async function probeDual(endpoint, projectId, config) {
  const { ownerToken, auditToken, throttleMs = 500 } = config;

  const owner = await doFetch(endpoint, ownerToken);
  await sleep(throttleMs);
  const audit = await doFetch(endpoint, auditToken);
  const signature = classify(owner.status, audit.status);

  logger.debug('probe classified', { projectId, signature });

  return Object.freeze({
    endpoint, projectId,
    owner: { status: owner.status, contentLength: owner.contentLength, errorCode: owner.errorCode },
    audit: { status: audit.status, contentLength: audit.contentLength, errorCode: audit.errorCode },
    signature,
    probedAt: new Date().toISOString(),
    latencyMs: { owner: owner.latencyMs, audit: audit.latencyMs },
  });
}

// Single-token fallback when no audit token is available
export async function probeSingle(endpoint, projectId, ownerToken) {
  const started = performance.now();
  try {
    const response = await fetch(endpoint, {
      method: 'GET',
      headers: { Authorization: `Bearer ${ownerToken}`, Accept: 'application/json' },
      credentials: 'omit',
    });
    const contentLength = Number(response.headers.get('content-length')) || undefined;
    const status = response.status;
    const signature = status === 200 ? 'owner_only'
                    : status === 403 ? 'inaccessible'
                    : status === 401 ? 'inaccessible'
                    : 'error';
    return Object.freeze({
      endpoint, projectId,
      owner: { status, contentLength },
      audit: null,
      signature,
      probedAt: new Date().toISOString(),
      latencyMs: { owner: Math.round(performance.now() - started), audit: 0 },
      singleToken: true,
    });
  } catch (err) {
    return Object.freeze({
      endpoint, projectId,
      owner: { status: 0, errorCode: err.name },
      audit: null,
      signature: 'error',
      probedAt: new Date().toISOString(),
      latencyMs: { owner: Math.round(performance.now() - started), audit: 0 },
      singleToken: true,
    });
  }
}

export async function probeDualBatch(items, config) {
  const results = [];
  for (const item of items) {
    results.push(await probeDual(item.endpoint, item.projectId, config));
    await sleep(config.throttleMs ?? 500);
  }
  return results;
}
