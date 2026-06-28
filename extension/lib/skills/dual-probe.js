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

// A failure is only worth retrying when it is *transient* — i.e. the same call
// might succeed moments later. Network failures (status 0), request timeouts,
// rate limiting and 5xx qualify. A deterministic 4xx (405 method drift, 422
// bad-shape, 404 path drift) will NEVER change on retry, so retrying it just
// triples API load and floods the diagnostic log ring with noise that buries
// the real signal. See audit-engine probeWithRetry.
export function isRetryableStatus(status) {
  return status === 0 || status === 408 || status === 429 || status >= 500;
}

// Distinguish *why* a probe didn't yield a clean owner×audit signature so the
// self-diagnosis can tell endpoint drift (fixable in our code) apart from an
// upstream outage (wait and retry). Both used to collapse into 'error'.
function classifyDeterministic(ownerStatus) {
  if (ownerStatus === 404) return 'not_found';   // path likely drifted
  if (ownerStatus >= 400 && ownerStatus < 500) return 'drift'; // 405/422/etc — method/shape drifted
  return 'error';                                  // 0/5xx — transient/outage
}

function classify(ownerStatus, auditStatus) {
  if ([401, 403, 0].includes(ownerStatus)) {
    return ownerStatus === 0 ? 'error' : 'inaccessible';
  }
  const sig = SIGNATURE_MATRIX[`${ownerStatus}:${auditStatus}`];
  if (sig) return sig;
  // Unmatched: classify by the owner status (the call we actually control).
  return classifyDeterministic(ownerStatus >= 500 || auditStatus >= 500 ? 0 : ownerStatus);
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
  // Retry when either side hit a transient status (network/timeout/429/5xx).
  // A clean owner/security verdict requires owner=200 + a non-retryable audit
  // status, so this never re-runs a settled probe — only genuinely flaky ones.
  const retryable = isRetryableStatus(owner.status) || isRetryableStatus(audit.status);

  logger.debug('probe classified', { projectId, signature });

  return Object.freeze({
    endpoint, projectId,
    owner: { status: owner.status, contentLength: owner.contentLength, errorCode: owner.errorCode },
    audit: { status: audit.status, contentLength: audit.contentLength, errorCode: audit.errorCode },
    httpStatus: owner.status,
    errorCode: owner.errorCode,
    signature,
    retryable,
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
                    : (status === 403 || status === 401) ? 'inaccessible'
                    : classifyDeterministic(status); // 404→not_found, other 4xx→drift, 0/5xx→error
    return Object.freeze({
      endpoint, projectId,
      owner: { status, contentLength },
      audit: null,
      httpStatus: status,
      signature,
      retryable: isRetryableStatus(status), // 429/5xx/network only; 200 & 4xx-drift are final
      probedAt: new Date().toISOString(),
      latencyMs: { owner: Math.round(performance.now() - started), audit: 0 },
      singleToken: true,
    });
  } catch (err) {
    return Object.freeze({
      endpoint, projectId,
      owner: { status: 0, errorCode: err.name },
      audit: null,
      httpStatus: 0,
      errorCode: err.name,
      signature: 'error',
      retryable: true, // network throw — transient by definition
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
