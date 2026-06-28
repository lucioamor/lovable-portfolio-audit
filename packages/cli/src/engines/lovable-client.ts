// ============================================================
// @nxlv-ai/lovable-audit — Lovable API Client (CLI version, Node.js)
// ============================================================
// Invariants:
//   - GET only. No POST/PUT/DELETE.
//   - 500ms throttle between requests (configurable).
//   - Token never logged or transmitted externally.
//   - Body content never persisted — only status + hash metadata.
// ============================================================

import { createHash } from 'crypto';
import { createLogger, type Logger } from '../util/logger.js';
import type {
  LovableProject,
  LovableFilesResponse,
  LovableMessagesResponse,
  ProbeResult,
  ResponseSignature,
} from '../types.js';

const LOVABLE_API_BASE = 'https://api.lovable.dev';
const NOV_2025_CUTOFF = new Date('2025-11-01T00:00:00Z');

export class LovableAPIClient {
  private token: string;
  private requestDelay: number;
  private lastRequestTime = 0;
  private verbose: boolean;
  private log: Logger;

  constructor(token: string, requestDelayMs = 500, verbose = false) {
    this.token = token;
    this.requestDelay = requestDelayMs;
    this.verbose = verbose;
    this.log = createLogger({ module: 'lovable-client' });
  }

  // ---- Rate limiting ----

  private async throttle(): Promise<void> {
    const now = Date.now();
    const elapsed = now - this.lastRequestTime;
    if (elapsed < this.requestDelay) {
      await new Promise(r => setTimeout(r, this.requestDelay - elapsed));
    }
    this.lastRequestTime = Date.now();
  }

  // ---- Core HTTP (read-only) ----

  private async get<T>(path: string): Promise<{
    data: T | null;
    status: number;
    contentLength: number;
    sha256: string;
    error?: string;
  }> {
    await this.throttle();

    try {
      const response = await fetch(`${LOVABLE_API_BASE}${path}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Accept': 'application/json',
          'User-Agent': 'nxlv-shield/0.1.0 (security-audit; read-only)',
        },
      });

      const text = await response.text();
      const sha256 = createHash('sha256').update(text).digest('hex');
      const contentLength = Buffer.byteLength(text, 'utf-8');

      // Debug-only, redacted: never the body, only metadata.
      if (this.verbose) {
        this.log.debug('GET', { path, status: response.status, bytes: contentLength, sha256: sha256.slice(0, 16) });
      }

      if (!response.ok) {
        return { data: null, status: response.status, contentLength, sha256, error: `HTTP ${response.status}` };
      }

      let data: T | null = null;
      try {
        data = JSON.parse(text) as T;
      } catch {
        data = null;
      }

      return { data, status: response.status, contentLength, sha256 };
    } catch (err) {
      return {
        data: null,
        status: 0,
        contentLength: 0,
        sha256: '',
        error: `Network error: ${(err as Error).message}`,
      };
    }
  }

  // ---- Response Signatures ----

  // Single-token: 200 means owner has access, but cross-account is unconfirmed.
  private classifySignature(status: number, error?: string): ResponseSignature {
    if (status === 200) return 'owner_only';
    if (status === 403) return 'patched';
    if (status === 401) return 'patched';
    if (status === 0 || error?.includes('Network')) return 'error';
    return 'unknown';
  }

  // Dual-token matrix: owner × audit → confirmed signature.
  private classifyDualSignature(ownerStatus: number, auditStatus: number): ResponseSignature {
    if (ownerStatus === 200 && auditStatus === 200) return 'vulnerable';   // confirmed BOLA
    if (ownerStatus === 200 && auditStatus === 403) return 'patched';      // fixed
    if (ownerStatus === 200 && auditStatus === 401) return 'patched';
    if (ownerStatus === 200 && auditStatus === 429) return 'owner_only';   // rate-limited audit
    if (ownerStatus === 200) return 'owner_only';                          // audit inconclusive
    if (ownerStatus === 403 || ownerStatus === 401) return 'patched';
    return 'unknown';
  }

  // Raw GET with a given token (for audit probe — never logs token).
  private async getWithToken(path: string, token: string): Promise<{ status: number; error?: string }> {
    await this.throttle();
    try {
      const response = await fetch(`${LOVABLE_API_BASE}${path}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
          'User-Agent': 'nxlv-shield/0.1.0 (security-audit; read-only)',
        },
      });
      // Body intentionally discarded — we only care about status code.
      await response.body?.cancel();
      return { status: response.status };
    } catch (err) {
      return { status: 0, error: `Network error: ${(err as Error).message}` };
    }
  }

  // ---- Public API ----

  // Decode JWT payload without signature verification (safe: read-only metadata).
  static decodeTokenPayload(token: string): Record<string, unknown> | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      const payload = Buffer.from(parts[1], 'base64url').toString('utf-8');
      return JSON.parse(payload) as Record<string, unknown>;
    } catch {
      return null;
    }
  }

  // Try GET /projects/{id} to fetch real project metadata (project-scoped tokens).
  private async getProjectById(projectId: string): Promise<LovableProject | null> {
    const result = await this.get<LovableProject>(`/projects/${projectId}`);
    return result.status === 200 && result.data ? result.data : null;
  }

  async validateToken(): Promise<{ valid: boolean; userId?: string; projectScoped?: boolean }> {
    // Try user-level endpoints (API surface may shift over time).
    for (const path of ['/user/projects', '/user/projects/shared']) {
      const result = await this.get<{ id?: string; user_id?: string }>(path);
      if (result.status === 200) return { valid: true, userId: result.data?.id };
    }

    // Fall back: project-scoped token (e.g. lovable-auth cookie).
    const payload = LovableAPIClient.decodeTokenPayload(this.token);
    if (payload?.access_type === 'project' && typeof payload.project_id === 'string') {
      const probe = await this.get<unknown>(`/projects/${payload.project_id}/git/files`);
      if (probe.status === 200) {
        return {
          valid: true,
          projectScoped: true,
          userId: typeof payload.user_id === 'string' ? payload.user_id : undefined,
        };
      }
    }

    return { valid: false };
  }

  async listProjects(): Promise<LovableProject[]> {
    // User-scoped token: try standard endpoints (order = most-likely-current first).
    const endpoints = ['/user/projects', '/user/projects/shared', '/projects'];
    for (const endpoint of endpoints) {
      const result = await this.get<LovableProject[] | { projects: LovableProject[] }>(endpoint);
      if (result.data) {
        if (Array.isArray(result.data)) return result.data;
        if ('projects' in result.data) return result.data.projects;
      }
    }

    // Project-scoped token fallback: extract project_id from JWT.
    const payload = LovableAPIClient.decodeTokenPayload(this.token);
    if (payload?.access_type === 'project' && typeof payload.project_id === 'string') {
      const projectId = payload.project_id;
      // Try to get real project metadata.
      const detail = await this.getProjectById(projectId);
      if (detail) return [detail];
      // Synthetic fallback using JWT claims.
      const iat = typeof payload.iat === 'number' ? payload.iat : Math.floor(Date.now() / 1000);
      const issuedAt = new Date(iat * 1000).toISOString();
      return [{
        id: projectId,
        name: projectId,
        created_at: issuedAt,
        updated_at: issuedAt,
      }];
    }

    return [];
  }

  /**
   * Single-token probe — returns owner_only (200) or patched/error.
   * Cannot confirm BOLA cross-account without an audit token.
   */
  async probeFilesEndpoint(projectId: string): Promise<ProbeResult> {
    const endpoint = `/projects/${projectId}/git/files`;
    const result = await this.get<LovableFilesResponse>(endpoint);
    return {
      endpoint,
      status: result.status,
      signature: this.classifySignature(result.status, result.error),
      contentLengthBytes: result.contentLength,
      sha256: result.sha256,
    };
  }

  /**
   * Single-token probe for chat endpoint.
   */
  async probeChatEndpoint(projectId: string): Promise<ProbeResult> {
    const endpoint = `/projects/${projectId}/messages`;
    const result = await this.get<LovableMessagesResponse>(endpoint);
    return {
      endpoint,
      status: result.status,
      signature: this.classifySignature(result.status, result.error),
      contentLengthBytes: result.contentLength,
      sha256: result.sha256,
    };
  }

  /**
   * Dual-token probe for files endpoint.
   * Returns vulnerable (confirmed BOLA) only when audit token also gets HTTP 200.
   */
  async probeFilesEndpointDual(projectId: string, auditToken: string): Promise<ProbeResult> {
    const endpoint = `/projects/${projectId}/git/files`;
    const [owner, audit] = await Promise.all([
      this.get<LovableFilesResponse>(endpoint),
      this.getWithToken(endpoint, auditToken),
    ]);
    return {
      endpoint,
      status: owner.status,
      signature: this.classifyDualSignature(owner.status, audit.status),
      contentLengthBytes: owner.contentLength,
      sha256: owner.sha256,
    };
  }

  /**
   * Dual-token probe for chat endpoint.
   */
  async probeChatEndpointDual(projectId: string, auditToken: string): Promise<ProbeResult> {
    const endpoint = `/projects/${projectId}/messages`;
    const [owner, audit] = await Promise.all([
      this.get<LovableMessagesResponse>(endpoint),
      this.getWithToken(endpoint, auditToken),
    ]);
    return {
      endpoint,
      status: owner.status,
      signature: this.classifyDualSignature(owner.status, audit.status),
      contentLengthBytes: owner.contentLength,
      sha256: owner.sha256,
    };
  }

  /**
   * Get file tree (only if probe returned vulnerable).
   * Returns file list — content is NOT fetched here (deep-inspect requires consent).
   */
  async getProjectFiles(projectId: string): Promise<{
    files: LovableFilesResponse | null;
    status: number;
  }> {
    const result = await this.get<LovableFilesResponse>(`/projects/${projectId}/git/files`);
    return { files: result.data, status: result.status };
  }

  /**
   * Download file content — requires deepInspect consent toggle.
   * Content is returned for scanning but NEVER persisted.
   */
  async getFileContent(projectId: string, filePath: string): Promise<{
    content: string | null;
    status: number;
    sha256: string;
  }> {
    await this.throttle();

    try {
      const encodedPath = encodeURIComponent(filePath);
      const response = await fetch(`${LOVABLE_API_BASE}/projects/${projectId}/git/files/${encodedPath}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'User-Agent': 'nxlv-shield/0.1.0 (security-audit; read-only)',
        },
      });

      const text = await response.text();
      const sha256 = createHash('sha256').update(text).digest('hex');

      return {
        content: response.ok ? text : null,
        status: response.status,
        sha256,
      };
    } catch (err) {
      return { content: null, status: 0, sha256: '' };
    }
  }

  /**
   * Get chat messages (only if probe returned vulnerable).
   * Content returned for scanning, NOT persisted.
   */
  async getProjectMessages(projectId: string): Promise<{
    messages: LovableMessagesResponse | null;
    status: number;
  }> {
    const result = await this.get<LovableMessagesResponse>(`/projects/${projectId}/messages`);
    return { messages: result.data, status: result.status };
  }

  // ---- LOV-006: Age check ----

  static isPreNov2025(project: LovableProject): boolean {
    return new Date(project.created_at) < NOV_2025_CUTOFF;
  }

  static isActiveProject(project: LovableProject): boolean {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const lastActivity = project.last_edited_at || project.updated_at;
    return new Date(lastActivity) > thirtyDaysAgo;
  }
}
