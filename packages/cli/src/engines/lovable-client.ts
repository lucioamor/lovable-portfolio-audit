// ============================================================
// @nxlv/shield — Lovable API Client (CLI version, Node.js)
// ============================================================
// Invariants:
//   - GET only. No POST/PUT/DELETE.
//   - 500ms throttle between requests (configurable).
//   - Token never logged or transmitted externally.
//   - Body content never persisted — only status + hash metadata.
// ============================================================

import { createHash } from 'crypto';
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

  constructor(token: string, requestDelayMs = 500, verbose = false) {
    this.token = token;
    this.requestDelay = requestDelayMs;
    this.verbose = verbose;
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

  async validateToken(): Promise<{ valid: boolean; userId?: string }> {
    const result = await this.get<{ id?: string; user_id?: string }>('/user/projects');
    return { valid: result.status === 200, userId: result.data?.id };
  }

  async listProjects(): Promise<LovableProject[]> {
    const endpoints = ['/user/projects', '/projects'];
    for (const endpoint of endpoints) {
      const result = await this.get<LovableProject[] | { projects: LovableProject[] }>(endpoint);
      if (result.data) {
        if (Array.isArray(result.data)) return result.data;
        if ('projects' in result.data) return result.data.projects;
      }
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
