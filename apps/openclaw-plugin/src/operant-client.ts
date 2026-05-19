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
  slackUserId: string | null;
  tool: string;
  action: string;
}

export interface OperantClient {
  getUserContext(sessionKey: string): Promise<PluginUserContext>;
  checkPolicy(input: PolicyCheckInput): Promise<PolicyDecision>;
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
  };
}
