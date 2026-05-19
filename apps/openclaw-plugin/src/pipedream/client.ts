export interface PipedreamToolListing {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

export interface PipedreamContentBlock {
  type: string;
  text?: string;
}

export interface PipedreamToolCallResult {
  content: PipedreamContentBlock[];
  isError?: boolean;
}

export interface PipedreamClient {
  listTools(slackUserId: string, appSlug: string): Promise<PipedreamToolListing[]>;
  callTool(slackUserId: string, toolName: string, args?: Record<string, unknown>, appSlug?: string): Promise<PipedreamToolCallResult>;
}

export interface PipedreamClientOptions {
  mcpUrl: string;
  clientId: string;
  clientSecret: string;
  projectId: string;
  environment: "development" | "production";
  tokenUrl?: string;
  tokenRefreshBufferMs?: number;
  fetchImpl?: typeof fetch;
  now?: () => number;
}

export class PipedreamClientError extends Error {
  constructor(
    public readonly endpoint: string,
    public readonly status: number,
    message: string,
  ) {
    super(`${endpoint} responded ${status}: ${message}`);
    this.name = "PipedreamClientError";
  }
}

export class PipedreamRpcError extends Error {
  constructor(
    public readonly method: string,
    public readonly code: number,
    message: string,
  ) {
    super(`${method} returned JSON-RPC error ${code}: ${message}`);
    this.name = "PipedreamRpcError";
  }
}

interface CachedToken {
  token: string;
  expiresAtMs: number;
}

interface JsonRpcResponse<T> {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: T;
  error?: { code: number; message: string; data?: unknown };
}

const DEFAULT_TOKEN_URL = "https://api.pipedream.com/v1/oauth/token";
const DEFAULT_REFRESH_BUFFER_MS = 60_000;
const FALLBACK_TOKEN_TTL_SECONDS = 300;
const MAX_ERROR_BODY_CHARS = 500;

export function sanitizePipedreamMessage(text: string): string {
  return text
    .replace(/ctok_[A-Za-z0-9_-]+/g, "ctok_[redacted]")
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

export function createPipedreamClient(options: PipedreamClientOptions): PipedreamClient {
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? (() => Date.now());
  const tokenUrl = options.tokenUrl ?? DEFAULT_TOKEN_URL;
  const refreshBufferMs = options.tokenRefreshBufferMs ?? DEFAULT_REFRESH_BUFFER_MS;
  const mcpUrl = options.mcpUrl.replace(/\/$/, "");
  // This OAuth token is project-scoped client-credentials auth. Per-user isolation
  // comes from the x-pd-external-user-id header set on every RPC below.
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
      throw new PipedreamClientError(tokenUrl, response.status, "oauth token mint failed");
    }
    const body = (await response.json()) as { access_token?: string; expires_in?: number };
    if (typeof body.access_token !== "string") {
      throw new PipedreamClientError(tokenUrl, response.status, "missing access_token in response");
    }
    const ttlMs = (typeof body.expires_in === "number" ? body.expires_in : FALLBACK_TOKEN_TTL_SECONDS) * 1000;
    cached = { token: body.access_token, expiresAtMs: now() + ttlMs };
    return body.access_token;
  }

  async function accessToken(): Promise<string> {
    if (cached && cached.expiresAtMs - now() > refreshBufferMs) return cached.token;
    if (!inFlight) {
      inFlight = fetchAccessToken().finally(() => {
        inFlight = null;
      });
    }
    return inFlight;
  }

  async function rpc<T>(slackUserId: string, method: string, params: unknown, appSlug?: string): Promise<T> {
    const token = await accessToken();
    const id = nextRpcId++;
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "accept": "application/json, text/event-stream",
      "authorization": `Bearer ${token}`,
      "x-pd-project-id": options.projectId,
      "x-pd-environment": options.environment,
      "x-pd-external-user-id": slackUserId,
    };
    if (appSlug) headers["x-pd-app-slug"] = appSlug;
    const response = await fetchImpl(mcpUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new PipedreamClientError(mcpUrl, response.status, sanitizePipedreamMessage(text.slice(0, MAX_ERROR_BODY_CHARS)));
    }
    const contentType = response.headers.get("content-type") ?? "";
    const body = contentType.includes("text/event-stream")
      ? parseSseJsonRpc<JsonRpcResponse<T>>(await response.text())
      : ((await response.json()) as JsonRpcResponse<T>);
    if (body.error) throw new PipedreamRpcError(method, body.error.code, sanitizePipedreamMessage(body.error.message));
    if (body.result === undefined) throw new PipedreamRpcError(method, -32000, "missing result");
    return body.result;
  }

  return {
    async listTools(slackUserId, appSlug) {
      const result = await rpc<{ tools?: PipedreamToolListing[] }>(slackUserId, "tools/list", {}, appSlug);
      return result.tools ?? [];
    },
    async callTool(slackUserId, toolName, args, appSlug) {
      return rpc<PipedreamToolCallResult>(slackUserId, "tools/call", {
        name: toolName,
        arguments: args ?? {},
      }, appSlug);
    },
  };
}
