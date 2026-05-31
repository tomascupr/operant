import { jsonResult } from "openclaw/plugin-sdk/core";
import { Type } from "typebox";
import type { OperantClient, PolicyDecision } from "../operant-client.js";
import type { PipedreamClient, PipedreamToolCallResult, PipedreamToolListing } from "./client.js";

export interface PipedreamToolDependencies {
  pipedreamClient: PipedreamClient;
  operantClient: OperantClient;
  principalId: string | null;
}

export function deriveAppAction(toolName: string): { app: string; action: string } {
  const dashIdx = toolName.indexOf("-");
  if (dashIdx < 0) return { app: toolName, action: "*" };
  return { app: toolName.slice(0, dashIdx), action: toolName.slice(dashIdx + 1) };
}

const ListActionsParameters = Type.Object(
  {
    app: Type.String({
      description: "Pipedream app slug to list actions for (e.g. \"gmail\", \"slack\", \"notion\", \"github\"). Pipedream requires per-app discovery; there is no list-all mode.",
    }),
  },
  { additionalProperties: false },
);

const SearchAppsParameters = Type.Object(
  {
    q: Type.Optional(Type.String({ description: "Search query for Pipedream apps, e.g. gmail, notion, github." })),
    limit: Type.Optional(Type.Number({ description: "Maximum number of apps to return, up to 50." })),
  },
  { additionalProperties: false },
);

const ConnectAppParameters = Type.Object(
  {
    app: Type.String({ description: "Pipedream app slug to connect, e.g. gmail, notion, github." }),
  },
  { additionalProperties: false },
);

const ListConnectionsParameters = Type.Object(
  {
    app: Type.Optional(Type.String({ description: "Optional Pipedream app slug to filter connections." })),
  },
  { additionalProperties: false },
);

const RunActionParameters = Type.Object(
  {
    toolName: Type.String({ description: "The Pipedream tool to invoke, e.g. \"gmail-send-email\"." }),
    args: Type.Optional(Type.Record(Type.String(), Type.Unknown(), {
      description: "JSON-object arguments forwarded as the MCP tools/call arguments payload.",
    })),
  },
  { additionalProperties: false },
);

async function evaluatePipedreamPolicy(
  deps: PipedreamToolDependencies,
  app: string,
  action: string,
): Promise<PolicyDecision> {
  return deps.operantClient.checkPolicy({
    principalId: deps.principalId,
    tool: `pipedream:${app}`,
    action,
  });
}

export function createPipedreamListActionsTool(deps: PipedreamToolDependencies) {
  return {
    name: "pipedream_list_actions",
    label: "List Pipedream Actions",
    description: "List Pipedream Connect tools available for a given app slug, filtered by Operant policy. Pipedream requires an explicit app (e.g. gmail, slack, notion). Use this before pipedream_run_action to discover toolName + arguments.",
    parameters: ListActionsParameters,
    execute: async (_toolCallId: string, rawParams: unknown) => {
      if (!deps.principalId) return jsonResult({ error: "missing_principal_context" });
      const params = rawParams as { app?: unknown };
      const app = typeof params.app === "string" ? params.app.trim() : "";
      if (!app) return jsonResult({ error: "missing_app" });
      const entries = await deps.pipedreamClient.listTools(deps.principalId, app);
      const settled = await Promise.allSettled(
        entries.map(async (entry: PipedreamToolListing) => {
          const { action } = deriveAppAction(entry.name);
          const decision = await evaluatePipedreamPolicy(deps, app, action);
          return decision.effect === "deny" ? null : entry;
        }),
      );
      const tools = settled.flatMap((result) =>
        result.status === "fulfilled" && result.value
          ? [{
              toolName: result.value.name,
              description: result.value.description,
              inputSchema: result.value.inputSchema,
            }]
          : [],
      );
      return jsonResult({ app, tools });
    },
  };
}

export function createPipedreamSearchAppsTool(deps: PipedreamToolDependencies) {
  return {
    name: "pipedream_search_apps",
    label: "Search Pipedream Apps",
    description: "Search the Pipedream Connect app catalog. Use this before asking a Slack user to connect an app or before discovering app actions.",
    parameters: SearchAppsParameters,
    execute: async (_toolCallId: string, rawParams: unknown) => {
      const params = rawParams as { q?: unknown; limit?: unknown };
      const q = typeof params.q === "string" && params.q.trim() ? params.q.trim() : undefined;
      const limit = typeof params.limit === "number" && Number.isFinite(params.limit)
        ? Math.min(Math.max(Math.trunc(params.limit), 1), 50)
        : 20;
      const result = await deps.operantClient.searchPipedreamApps({ q, limit });
      return jsonResult(result);
    },
  };
}

export function createPipedreamConnectAppTool(deps: PipedreamToolDependencies) {
  return {
    name: "pipedream_connect_app",
    label: "Connect Pipedream App",
    description: "Create a short-lived Pipedream Connect link for the requesting Slack user to OAuth a SaaS account.",
    parameters: ConnectAppParameters,
    execute: async (_toolCallId: string, rawParams: unknown) => {
      if (!deps.principalId) return jsonResult({ error: "missing_principal_context" });
      const params = rawParams as { app?: unknown };
      const app = typeof params.app === "string" ? params.app.trim() : "";
      if (!app) return jsonResult({ error: "missing_app" });
      const result = await deps.operantClient.createPipedreamConnectToken({ principalId: deps.principalId, appSlug: app })
        .catch((error) => ({ error: "connect_token_failed", message: error instanceof Error ? error.message : "unknown error" }));
      return jsonResult(result);
    },
  };
}

export function createPipedreamListConnectionsTool(deps: PipedreamToolDependencies) {
  return {
    name: "pipedream_list_connections",
    label: "List Pipedream Connections",
    description: "List the requesting Slack user's connected Pipedream accounts, optionally filtered by app slug.",
    parameters: ListConnectionsParameters,
    execute: async (_toolCallId: string, rawParams: unknown) => {
      if (!deps.principalId) return jsonResult({ error: "missing_principal_context" });
      const params = rawParams as { app?: unknown };
      const app = typeof params.app === "string" && params.app.trim() ? params.app.trim() : undefined;
      const result = await deps.operantClient.listPipedreamAccounts({ principalId: deps.principalId, app })
        .catch((error) => ({ error: "connections_lookup_failed", message: error instanceof Error ? error.message : "unknown error" }));
      return jsonResult(result);
    },
  };
}

function wrapPipedreamResult(result: PipedreamToolCallResult) {
  const blocks = Array.isArray(result.content) ? result.content : [];
  const content = blocks.map((block) => ({
    type: "text" as const,
    text: block.text ?? JSON.stringify(block),
  }));
  return { content, details: result };
}

export function createPipedreamRunActionTool(deps: PipedreamToolDependencies) {
  return {
    name: "pipedream_run_action",
    label: "Run Pipedream Action",
    description: "Run a Pipedream Connect tool on behalf of the requesting Slack user. The tool call is gated by Operant policy and per-user OAuth; if the user has not yet connected the underlying SaaS account, the response includes a connect URL to share in Slack.",
    parameters: RunActionParameters,
    execute: async (_toolCallId: string, rawParams: unknown) => {
      const params = rawParams as { toolName?: unknown; args?: unknown };
      const toolName = typeof params.toolName === "string" ? params.toolName : "";
      if (!toolName) return jsonResult({ error: "missing_toolName" });
      if (!deps.principalId) return jsonResult({ error: "missing_principal_context", toolName });
      const { app, action } = deriveAppAction(toolName);
      const decision = await evaluatePipedreamPolicy(deps, app, action).catch(() => null);
      if (!decision) return jsonResult({ error: "policy_check_failed", toolName });
      if (decision.effect === "deny") {
        return jsonResult({ error: "policy_denied", toolName, reasons: decision.reasons });
      }
      if (decision.effect === "approval_required") {
        return jsonResult({ status: "approval_required", toolName, reasons: decision.reasons });
      }
      const args = params.args && typeof params.args === "object" && !Array.isArray(params.args)
        ? (params.args as Record<string, unknown>)
        : undefined;
      const result = await deps.pipedreamClient.callTool(deps.principalId, toolName, args, app);
      return wrapPipedreamResult(result);
    },
  };
}
