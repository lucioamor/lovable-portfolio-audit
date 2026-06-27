// ============================================================
// @nxlv/shield — Diff-alert webhook (P11, self-contained, no backend)
// ============================================================
// After a --baseline scan computes a DeltaSummary, POST a compact JSON
// summary of what changed to a user-supplied URL. The payload carries only
// non-sensitive finding identifiers (ruleId, title, severity, project) and
// counts — never tokens, raw bodies, masked evidence, or response bodies.
//
// Delivery is best-effort: a non-2xx response or a network error is reported
// to the caller and never throws, so the scan itself is unaffected.
// ============================================================

import type { DeltaSummary, DeltaItem } from './baseline.js';

export const WEBHOOK_SCHEMA = 'nxlv-shield-drift/v1';

/** A single changed finding, reduced to non-sensitive identifiers only. */
export interface WebhookFinding {
  ruleId: string;
  title: string;
  severity: string;
  projectId: string;
}

export interface WebhookPayload {
  schema: typeof WEBHOOK_SCHEMA;
  generatedAt: string;
  counts: {
    new: number;
    resolved: number;
    unchanged: number;
  };
  new: WebhookFinding[];
  resolved: WebhookFinding[];
}

/** Reduce a delta item to the whitelisted, non-sensitive identifier fields.
 *  Note: `evidence`/`hash`/`secret` are intentionally NOT carried. */
function toWebhookFinding(item: DeltaItem): WebhookFinding {
  return {
    ruleId: item.ruleId,
    title: item.title,
    severity: item.severity,
    projectId: item.projectId,
  };
}

/**
 * Pure: build the webhook body from a delta. Includes counts and the new /
 * resolved finding identifiers; excludes every secret-bearing field.
 */
export function buildWebhookPayload(delta: DeltaSummary, generatedAt: string): WebhookPayload {
  return {
    schema: WEBHOOK_SCHEMA,
    generatedAt,
    counts: {
      new: delta.newCount,
      resolved: delta.resolvedCount,
      unchanged: delta.unchangedCount,
    },
    new: delta.items.filter(i => i.drift_state === 'new').map(toWebhookFinding),
    resolved: delta.items.filter(i => i.drift_state === 'resolved').map(toWebhookFinding),
  };
}

export interface WebhookResult {
  ok: boolean;
  status: number;
  error?: string;
}

/**
 * Best-effort POST of the payload as JSON. Never throws: a non-2xx status or a
 * network/abort error is returned as `{ ok:false }`. The response body is never
 * read or surfaced. A short timeout keeps a hung endpoint from blocking the CLI.
 */
export async function postWebhook(
  url: string,
  payload: WebhookPayload,
  timeoutMs = 10000,
): Promise<WebhookResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    return { ok: res.ok, status: res.status };
  } catch (err) {
    return { ok: false, status: 0, error: (err as Error).message };
  } finally {
    clearTimeout(timer);
  }
}
