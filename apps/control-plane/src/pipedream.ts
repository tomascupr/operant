export type PipedreamEnvironment = "development" | "production";

export type PipedreamApp = {
  id: string | null;
  name: string;
  slug: string;
  description: string | null;
  category: string | null;
};

export type PipedreamAccount = {
  id: string;
  app: string | null;
  appName: string | null;
  externalUserId: string | null;
  name: string | null;
  healthy: boolean | null;
  createdAt: string | null;
  updatedAt: string | null;
};

export type PipedreamToolListing = {
  name: string;
  description?: string;
  inputSchema?: unknown;
};

export type PipedreamConnectToken = {
  token: string;
  expiresAt: string | null;
  connectLinkUrl: string;
};

export type PipedreamConnectClient = {
  listApps(input?: { q?: string; limit?: number; after?: string }): Promise<{ apps: PipedreamApp[]; pageInfo: Record<string, unknown> | null }>;
  listAccounts(input: { externalUserId: string; app?: string }): Promise<PipedreamAccount[]>;
  createConnectToken(input: { externalUserId: string; appSlug?: string; allowedOrigins?: string[] }): Promise<PipedreamConnectToken>;
  deleteAccount(accountId: string): Promise<void>;
  listTools(input: { externalUserId: string; appSlug: string }): Promise<PipedreamToolListing[]>;
};

export interface PipedreamConnectClientOptions {
  clientId: string;
  clientSecret: string;
  projectId: string;
  environment: PipedreamEnvironment;
  apiBaseUrl?: string;
  tokenUrl?: string;
  mcpUrl?: string;
  connectBaseUrl?: string;
  fetchImpl?: typeof fetch;
  now?: () => number;
  tokenRefreshBufferMs?: number;
}

type JsonRpcResponse<T> = {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: T;
  error?: { code: number; message: string; data?: unknown };
};

type CachedToken = {
  token: string;
  expiresAtMs: number;
};

export class PipedreamConnectClientError extends Error {
  constructor(
    public readonly endpoint: string,
    public readonly status: number,
    message: string,
  ) {
    super(`${endpoint} responded ${status}: ${message}`);
    this.name = "PipedreamConnectClientError";
  }
}

const DEFAULT_API_BASE_URL = "https://api.pipedream.com/v1";
const DEFAULT_TOKEN_URL = "https://api.pipedream.com/v1/oauth/token";
const DEFAULT_MCP_URL = "https://remote.mcp.pipedream.net/v3";
const DEFAULT_CONNECT_BASE_URL = "https://pipedream.com/_static/connect.html";
const DEFAULT_REFRESH_BUFFER_MS = 60_000;
const FALLBACK_TOKEN_TTL_SECONDS = 300;
const MAX_ERROR_BODY_CHARS = 500;

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

function booleanValue(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function firstString(...values: unknown[]): string | null {
  for (const value of values) {
    const resolved = stringValue(value);
    if (resolved) return resolved;
  }
  return null;
}

function pageItems(body: unknown): unknown[] {
  if (Array.isArray(body)) return body;
  const root = asRecord(body);
  if (!root) return [];
  for (const key of ["data", "apps", "accounts", "items", "results"]) {
    const value = root[key];
    if (Array.isArray(value)) return value;
  }
  return [];
}

function pageInfo(body: unknown): Record<string, unknown> | null {
  const root = asRecord(body);
  return asRecord(root?.page_info) ?? asRecord(root?.pageInfo) ?? null;
}

function normalizeApp(item: unknown): PipedreamApp | null {
  const row = asRecord(item);
  if (!row) return null;
  const slug = firstString(row.name_slug, row.nameSlug, row.slug, row.key);
  const name = firstString(row.name, row.label, slug);
  if (!slug || !name) return null;
  return {
    id: firstString(row.id),
    name,
    slug,
    description: firstString(row.description, row.short_description, row.shortDescription),
    category: firstString(row.category, row.app_category, row.appCategory),
  };
}

function normalizeAccount(item: unknown): PipedreamAccount | null {
  const row = asRecord(item);
  if (!row) return null;
  const app = asRecord(row.app);
  const id = firstString(row.id, row.account_id, row.accountId);
  if (!id) return null;
  return {
    id,
    app: firstString(row.app, row.app_slug, row.appSlug, app?.name_slug, app?.slug),
    appName: firstString(row.app_name, row.appName, app?.name),
    externalUserId: firstString(row.external_user_id, row.externalUserId, row.user_id, row.userId),
    name: firstString(row.name, row.account_name, row.accountName, row.email),
    healthy: booleanValue(row.healthy) ?? booleanValue(row.connected) ?? booleanValue(row.active),
    createdAt: firstString(row.created_at, row.createdAt),
    updatedAt: firstString(row.updated_at, row.updatedAt),
  };
}

export function sanitizePipedreamConnectMessage(text: string): string {
  return text
    .replace(/ctok_[A-Za-z0-9_-]+/g, "ctok_[redacted]")
    .replace(/tok_[A-Za-z0-9_-]+/g, "tok_[redacted]")
    .replace(/https?:\/\/pipedream\.com\/_static\/connect\.html\?[^\s"']+/g, "<connect-link redacted>");
}

export function parseSseJsonRpc<T = unknown>(text: string): T {
  for (const block of text.split(/\r?\n\r?\n/)) {
    const data: string[] = [];
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith("data:")) data.push(line.slice(line.startsWith("data: ") ? 6 : 5));
    }
    if (data.length > 0) return JSON.parse(data.join("\n")) as T;
  }
  throw new Error("no data: event in SSE response");
}

export function createPipedreamConnectClient(options: PipedreamConnectClientOptions): PipedreamConnectClient {
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? (() => Date.now());
  const apiBaseUrl = (options.apiBaseUrl ?? DEFAULT_API_BASE_URL).replace(/\/$/, "");
  const tokenUrl = options.tokenUrl ?? DEFAULT_TOKEN_URL;
  const mcpUrl = (options.mcpUrl ?? DEFAULT_MCP_URL).replace(/\/$/, "");
  const connectBaseUrl = options.connectBaseUrl ?? DEFAULT_CONNECT_BASE_URL;
  const tokenRefreshBufferMs = options.tokenRefreshBufferMs ?? DEFAULT_REFRESH_BUFFER_MS;
  let cached: CachedToken | null = null;
  let inFlight: Promise<string> | null = null;
  let nextRpcId = 1;

  async function fetchAccessToken(): Promise<string> {
    const response = await fetchImpl(tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "client_credentials",
        client_id: options.clientId,
        client_secret: options.clientSecret,
      }),
    });
    if (!response.ok) {
      throw new PipedreamConnectClientError(tokenUrl, response.status, "oauth token mint failed");
    }
    const body = (await response.json()) as { access_token?: string; expires_in?: number };
    if (typeof body.access_token !== "string") {
      throw new PipedreamConnectClientError(tokenUrl, response.status, "missing access_token in response");
    }
    const ttlMs = (typeof body.expires_in === "number" ? body.expires_in : FALLBACK_TOKEN_TTL_SECONDS) * 1000;
    cached = { token: body.access_token, expiresAtMs: now() + ttlMs };
    return body.access_token;
  }

  async function accessToken(): Promise<string> {
    if (cached && cached.expiresAtMs - now() > tokenRefreshBufferMs) return cached.token;
    if (!inFlight) {
      inFlight = fetchAccessToken().finally(() => {
        inFlight = null;
      });
    }
    return inFlight;
  }

  async function requestJson<T>(endpoint: string, init: RequestInit = {}): Promise<T> {
    const token = await accessToken();
    const url = endpoint.startsWith("http") ? endpoint : `${apiBaseUrl}${endpoint}`;
    const response = await fetchImpl(url, {
      ...init,
      headers: {
        accept: "application/json",
        authorization: `Bearer ${token}`,
        "x-pd-project-id": options.projectId,
        "x-pd-environment": options.environment,
        ...(init.body ? { "content-type": "application/json" } : {}),
        ...(init.headers || {}),
      },
    });
    if (response.status === 204) return undefined as T;
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new PipedreamConnectClientError(url, response.status, sanitizePipedreamConnectMessage(text.slice(0, MAX_ERROR_BODY_CHARS)));
    }
    return (await response.json()) as T;
  }

  async function rpc<T>(externalUserId: string, method: string, params: unknown, appSlug?: string): Promise<T> {
    const token = await accessToken();
    const id = nextRpcId++;
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "accept": "application/json, text/event-stream",
      "authorization": `Bearer ${token}`,
      "x-pd-project-id": options.projectId,
      "x-pd-environment": options.environment,
      "x-pd-external-user-id": externalUserId,
    };
    if (appSlug) headers["x-pd-app-slug"] = appSlug;
    const response = await fetchImpl(mcpUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new PipedreamConnectClientError(mcpUrl, response.status, sanitizePipedreamConnectMessage(text.slice(0, MAX_ERROR_BODY_CHARS)));
    }
    const contentType = response.headers.get("content-type") ?? "";
    const body = contentType.includes("text/event-stream")
      ? parseSseJsonRpc<JsonRpcResponse<T>>(await response.text())
      : ((await response.json()) as JsonRpcResponse<T>);
    if (body.error) throw new PipedreamConnectClientError(mcpUrl, 200, sanitizePipedreamConnectMessage(body.error.message));
    if (body.result === undefined) throw new PipedreamConnectClientError(mcpUrl, 200, "missing result");
    return body.result;
  }

  return {
    async listApps(input = {}) {
      const url = new URL(`${apiBaseUrl}/apps`);
      if (input.q) url.searchParams.set("q", input.q);
      if (input.limit) url.searchParams.set("limit", String(input.limit));
      if (input.after) url.searchParams.set("after", input.after);
      const body = await requestJson<unknown>(url.toString());
      return {
        apps: pageItems(body).map(normalizeApp).filter((app): app is PipedreamApp => Boolean(app)),
        pageInfo: pageInfo(body),
      };
    },
    async listAccounts(input) {
      const url = new URL(`${apiBaseUrl}/connect/${encodeURIComponent(options.projectId)}/accounts`);
      url.searchParams.set("external_user_id", input.externalUserId);
      url.searchParams.set("include_credentials", "false");
      if (input.app) url.searchParams.set("app", input.app);
      const body = await requestJson<unknown>(url.toString());
      return pageItems(body).map(normalizeAccount).filter((account): account is PipedreamAccount => Boolean(account));
    },
    async createConnectToken(input) {
      const tokensPath = `/connect/${encodeURIComponent(options.projectId)}/tokens`;
      const body = await requestJson<unknown>(tokensPath, {
        method: "POST",
        body: JSON.stringify({
          user_id: input.externalUserId,
          external_user_id: input.externalUserId,
          ...(input.allowedOrigins?.length ? { allowed_origins: input.allowedOrigins } : {}),
        }),
      });
      const root = asRecord(body);
      const token = firstString(root?.token, root?.connect_token, root?.connectToken);
      if (!token) throw new PipedreamConnectClientError(`${apiBaseUrl}${tokensPath}`, 200, "missing token in response");
      const providedUrl = firstString(root?.connect_link_url, root?.connectLinkUrl);
      const connectUrl = new URL(providedUrl ?? connectBaseUrl);
      connectUrl.searchParams.set("token", token);
      if (input.appSlug) connectUrl.searchParams.set("app", input.appSlug);
      return {
        token,
        expiresAt: firstString(root?.expires_at, root?.expiresAt),
        connectLinkUrl: connectUrl.toString(),
      };
    },
    async deleteAccount(accountId) {
      await requestJson<void>(`/connect/${encodeURIComponent(options.projectId)}/accounts/${encodeURIComponent(accountId)}`, {
        method: "DELETE",
      });
    },
    async listTools(input) {
      const result = await rpc<{ tools?: PipedreamToolListing[] }>(input.externalUserId, "tools/list", {}, input.appSlug);
      return result.tools ?? [];
    },
  };
}

export function createPipedreamConnectClientFromEnv(env: NodeJS.ProcessEnv = process.env, fetchImpl: typeof fetch = fetch): PipedreamConnectClient | null {
  const clientId = env.PIPEDREAM_PROJECT_CLIENT_ID?.trim();
  const clientSecret = env.PIPEDREAM_PROJECT_CLIENT_SECRET?.trim();
  const projectId = env.PIPEDREAM_PROJECT_ID?.trim();
  const mcpUrl = env.OPERANT_MCP_SOURCE_PIPEDREAM_URL?.trim();
  const environment = env.PIPEDREAM_ENVIRONMENT?.trim() === "production" ? "production" : env.PIPEDREAM_ENVIRONMENT?.trim() === "development" ? "development" : null;
  if (!clientId || !clientSecret || !projectId || !environment || !mcpUrl) return null;
  return createPipedreamConnectClient({
    clientId,
    clientSecret,
    projectId,
    environment,
    apiBaseUrl: env.PIPEDREAM_API_BASE_URL,
    tokenUrl: env.PIPEDREAM_OAUTH_TOKEN_URL,
    mcpUrl,
    connectBaseUrl: env.PIPEDREAM_CONNECT_BASE_URL,
    fetchImpl,
  });
}
