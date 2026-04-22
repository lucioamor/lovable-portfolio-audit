// ============================================================
// Lovable Security Scanner — Lovable API Client
// ============================================================
// 
// WARNING: This client is designed to access YOUR OWN projects
// using your authenticated session token. It is NOT intended
// for accessing third-party projects.
//
// The endpoints below are based on observed API behavior from
// browser DevTools and the disclosed vulnerability research.
// ============================================================

import type {
  LovableProject,
  LovableFilesResponse,
  LovableMessagesResponse,
} from './types';

const BASE_URL = 'https://api.lovable.dev';

export class LovableAPIClient {
  private token: string;
  private requestDelay: number;
  private lastRequestTime = 0;

  constructor(token: string, requestDelayMs = 500) {
    this.token = token;
    this.requestDelay = requestDelayMs;
  }

  /**
   * Apply rate limiting between requests
   */
  private async throttle(): Promise<void> {
    const now = Date.now();
    const elapsed = now - this.lastRequestTime;
    if (elapsed < this.requestDelay) {
      await new Promise(r => setTimeout(r, this.requestDelay - elapsed));
    }
    this.lastRequestTime = Date.now();
  }

  /**
   * Make an authenticated GET request
   */
  private async get<T>(path: string): Promise<{ data: T | null; status: number; error?: string }> {
    await this.throttle();

    try {
      const response = await fetch(`${BASE_URL}${path}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Accept': 'application/json',
        },
      });

      if (!response.ok) {
        if (response.status === 401) {
          return { data: null, status: 401, error: 'Token inválido ou expirado' };
        }
        if (response.status === 403) {
          // 403 = project is PROTECTED (good!)
          return { data: null, status: 403, error: 'Acesso negado (protegido)' };
        }
        return { data: null, status: response.status, error: `HTTP ${response.status}` };
      }

      const data = await response.json() as T;
      return { data, status: response.status };
    } catch (err) {
      return { data: null, status: 0, error: `Network error: ${(err as Error).message}` };
    }
  }

  /**
   * Fetch raw file content from a project
   */
  private async getRaw(path: string): Promise<{ data: string | null; status: number; error?: string }> {
    await this.throttle();

    try {
      const response = await fetch(`${BASE_URL}${path}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.token}`,
        },
      });

      if (!response.ok) {
        return { data: null, status: response.status, error: `HTTP ${response.status}` };
      }

      const text = await response.text();
      return { data: text, status: response.status };
    } catch (err) {
      return { data: null, status: 0, error: `Network error: ${(err as Error).message}` };
    }
  }

  /**
   * Validate the token by making a simple API call
   */
  async validateToken(): Promise<boolean> {
    const result = await this.get('/user/projects');
    return result.status === 200;
  }

  /**
   * List all projects belonging to the authenticated user
   */
  async listProjects(): Promise<LovableProject[]> {
    // Try the most likely endpoint patterns
    const endpoints = [
      '/user/projects',
      '/projects',
    ];

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
   * Get the file tree of a project
   * Returns 200 if accessible, 403 if protected
   */
  async getProjectFiles(projectId: string): Promise<{
    files: LovableFilesResponse | null;
    status: number;
    isVulnerable: boolean;
  }> {
    const result = await this.get<LovableFilesResponse>(`/projects/${projectId}/git/files`);
    return {
      files: result.data,
      status: result.status,
      isVulnerable: result.status === 200, // 200 means accessible
    };
  }

  /**
   * Download a specific file's content from a project
   */
  async getFileContent(projectId: string, filePath: string): Promise<{
    content: string | null;
    status: number;
  }> {
    const encodedPath = encodeURIComponent(filePath);
    const result = await this.getRaw(`/projects/${projectId}/git/files/${encodedPath}`);
    return {
      content: result.data,
      status: result.status,
    };
  }

  /**
   * Get the chat/message history of a project
   */
  async getProjectMessages(projectId: string): Promise<{
    messages: LovableMessagesResponse | null;
    status: number;
    isVulnerable: boolean;
  }> {
    const result = await this.get<LovableMessagesResponse>(`/projects/${projectId}/messages`);
    return {
      messages: result.data,
      status: result.status,
      isVulnerable: result.status === 200,
    };
  }

  /**
   * Test BOLA vulnerability on a specific project
   * This checks if the files and messages endpoints return 200
   */
  async testBOLA(projectId: string): Promise<{
    filesAccessible: boolean;
    chatAccessible: boolean;
    filesStatus: number;
    chatStatus: number;
  }> {
    const filesResult = await this.get(`/projects/${projectId}/git/files`);
    const chatResult = await this.get(`/projects/${projectId}/messages`);

    return {
      filesAccessible: filesResult.status === 200,
      chatAccessible: chatResult.status === 200,
      filesStatus: filesResult.status,
      chatStatus: chatResult.status,
    };
  }
}
