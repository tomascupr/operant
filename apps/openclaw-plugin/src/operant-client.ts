export type PolicyEffect = "allow" | "deny" | "approval_required";

export interface PolicyDecision {
  effect: PolicyEffect;
  reasons: string[];
}

export interface PluginUserContext {
  sessionKey: string;
  workspaceId: string;
  slackUserId: string | null;
  roles: string[];
}

export interface PolicyCheckInput {
  principalId: string | null;
  tool: string;
  action: string;
}

export interface PipedreamAppSummary {
  id: string | null;
  name: string;
  slug: string;
  description: string | null;
  category: string | null;
}

export interface PipedreamAccountSummary {
  id: string;
  app: string | null;
  appName: string | null;
  externalUserId: string | null;
  name: string | null;
  healthy: boolean | null;
  createdAt: string | null;
  updatedAt: string | null;
}

export interface PipedreamConnectTokenResult {
  app: string | null;
  expiresAt: string | null;
  connectLinkUrl: string;
}

export interface MemoryEntry {
  id: string;
  content: string;
  visibility: "private" | "team";
  scope_key: string | null;
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface SkillEntry {
  id: string;
  name: string;
  trigger_hint: string;
  body: string;
  tags: string[];
}

export interface MemoryWriteInput {
  principalId: string;
  content: string;
  visibility?: "private" | "team";
  scopeKey?: string;
  tags?: string[];
}

export interface MemorySearchInput {
  principalId: string;
  q?: string;
  tags?: string[];
  limit?: number;
}

export interface OperantClient {
  getUserContext(sessionKey: string): Promise<PluginUserContext>;
  checkPolicy(input: PolicyCheckInput): Promise<PolicyDecision>;
  searchPipedreamApps(input: { q?: string; limit?: number }): Promise<{ apps: PipedreamAppSummary[]; pageInfo?: Record<string, unknown> | null }>;
  createPipedreamConnectToken(input: { principalId: string; appSlug?: string }): Promise<PipedreamConnectTokenResult>;
  listPipedreamAccounts(input: { principalId: string; app?: string }): Promise<{ accounts: PipedreamAccountSummary[] }>;
  writeMemory(input: MemoryWriteInput): Promise<{ id: string; createdAt: string }>;
  searchMemory(input: MemorySearchInput): Promise<{ entries: MemoryEntry[] }>;
  searchSkills(input: MemorySearchInput): Promise<{ skills: SkillEntry[] }>;
}

export interface OperantClientOptions {
  baseUrl: string;
  token: string;
  fetchImpl?: typeof fetch;
}

export class OperantClientError extends Error {
  constructor(public readonly endpoint: string, public readonly status: number, message: string) {
    super(`${endpoint} responded ${status}: ${message}`);
    this.name = "OperantClientError";
  }
}

const DEFAULT_TIMEOUT_MS = 10_000;

export function createOperantClient({ baseUrl, token, fetchImpl = fetch }: OperantClientOptions): OperantClient {
  const root = baseUrl.replace(/\/$/, "");
  async function post<T>(endpoint: string, body: unknown): Promise<T> {
    const response = await fetchImpl(`${root}${endpoint}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new OperantClientError(endpoint, response.status, text.slice(0, 500));
    }
    return (await response.json()) as T;
  }
  return {
    getUserContext(sessionKey) {
      return post<PluginUserContext>("/internal/plugin/user-context", { sessionKey });
    },
    checkPolicy(input) {
      return post<PolicyDecision>("/internal/plugin/policy-check", input);
    },
    searchPipedreamApps(input) {
      return post<{ apps: PipedreamAppSummary[]; pageInfo?: Record<string, unknown> | null }>("/internal/plugin/pipedream/apps", input);
    },
    createPipedreamConnectToken(input) {
      return post<PipedreamConnectTokenResult>("/internal/plugin/pipedream/connect-token", input);
    },
    listPipedreamAccounts(input) {
      return post<{ accounts: PipedreamAccountSummary[] }>("/internal/plugin/pipedream/accounts", input);
    },
    writeMemory(input) {
      return post<{ id: string; createdAt: string }>("/internal/plugin/memory/write", input);
    },
    searchMemory(input) {
      return post<{ entries: MemoryEntry[] }>("/internal/plugin/memory/search", input);
    },
    searchSkills(input) {
      return post<{ skills: SkillEntry[] }>("/internal/plugin/skills/search", input);
    },
  };
}
