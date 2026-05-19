import { jsonResult } from "openclaw/plugin-sdk/core";
import { Type } from "typebox";
import type { OperantClient, PolicyDecision } from "../operant-client.js";
import type { PipedreamClient, PipedreamToolCallResult, PipedreamToolListing } from "./client.js";

export interface PipedreamToolDependencies {
  pipedreamClient: PipedreamClient;
  operantClient: OperantClient;
  slackUserId: string | null;
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
    slackUserId: deps.slackUserId,
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
      if (!deps.slackUserId) return jsonResult({ error: "missing_slack_user_context" });
      const params = rawParams as { app?: unknown };
      const app = typeof params.app === "string" ? params.app.trim() : "";
      if (!app) return jsonResult({ error: "missing_app" });
      const entries = await deps.pipedreamClient.listTools(deps.slackUserId, app);
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

function wrapPipedreamResult(result: PipedreamToolCallResult) {
  const content = result.content.map((block) => ({
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
      if (!deps.slackUserId) return jsonResult({ error: "missing_slack_user_context", toolName });
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
      const result = await deps.pipedreamClient.callTool(deps.slackUserId, toolName, args, app);
      return wrapPipedreamResult(result);
    },
  };
}
