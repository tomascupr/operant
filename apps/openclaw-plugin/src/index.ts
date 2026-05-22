import { definePluginEntry, jsonResult } from "openclaw/plugin-sdk/core";
import { Type } from "typebox";
import { createOperantClient, type OperantClient } from "./operant-client.js";
import { createPipedreamClient, type PipedreamClient } from "./pipedream/client.js";
import {
  createPipedreamConnectAppTool,
  createPipedreamListActionsTool,
  createPipedreamListConnectionsTool,
  createPipedreamRunActionTool,
  createPipedreamSearchAppsTool,
} from "./pipedream/tools.js";

export const PingToolParameters = Type.Object({}, { additionalProperties: false });

export const pingTool = {
  name: "operant_ping",
  label: "Operant Ping",
  description: "Health check exposed by the Operant plugin. Returns ok and a server timestamp.",
  parameters: PingToolParameters,
  execute: async (_toolCallId: string, _rawParams: unknown) =>
    jsonResult({ ok: true, timestamp: new Date().toISOString() }),
};

interface ResolvedEnv {
  operantBaseUrl: string;
  operantInternalToken: string;
  pipedreamMcpUrl: string | null;
  pipedreamClientId: string | null;
  pipedreamClientSecret: string | null;
  pipedreamProjectId: string | null;
  pipedreamEnvironment: "development" | "production";
}

export function readPluginEnv(env: NodeJS.ProcessEnv): ResolvedEnv | null {
  const operantBaseUrl = env.OPERANT_CONTROL_PLANE_URL?.trim();
  const operantInternalToken = env.OPERANT_INTERNAL_TOKEN?.trim();
  if (!operantBaseUrl || !operantInternalToken) return null;
  const pipedreamEnvironment = env.PIPEDREAM_ENVIRONMENT?.trim() === "production" ? "production" : "development";
  return {
    operantBaseUrl,
    operantInternalToken,
    pipedreamMcpUrl: env.OPERANT_MCP_SOURCE_PIPEDREAM_URL?.trim() || null,
    pipedreamClientId: env.PIPEDREAM_PROJECT_CLIENT_ID?.trim() || null,
    pipedreamClientSecret: env.PIPEDREAM_PROJECT_CLIENT_SECRET?.trim() || null,
    pipedreamProjectId: env.PIPEDREAM_PROJECT_ID?.trim() || null,
    pipedreamEnvironment,
  };
}

export interface PipedreamWiring {
  pipedreamClient: PipedreamClient;
}

export function buildPipedreamWiring(env: ResolvedEnv): PipedreamWiring | null {
  if (!env.pipedreamMcpUrl || !env.pipedreamClientId || !env.pipedreamClientSecret || !env.pipedreamProjectId) return null;
  const pipedreamClient = createPipedreamClient({
    mcpUrl: env.pipedreamMcpUrl,
    clientId: env.pipedreamClientId,
    clientSecret: env.pipedreamClientSecret,
    projectId: env.pipedreamProjectId,
    environment: env.pipedreamEnvironment,
  });
  return { pipedreamClient };
}

export default definePluginEntry({
  id: "operant",
  name: "Operant",
  description: "Operant control-plane bridge: per-user policy, RBAC, and integration credentials for OpenClaw tools.",
  register(api) {
    api.registerTool(pingTool);
    const env = readPluginEnv(process.env);
    if (!env) {
      console.warn(
        "[operant-plugin] OPERANT_CONTROL_PLANE_URL / OPERANT_INTERNAL_TOKEN not set; only operant_ping is registered.",
      );
      return;
    }
    const operantClient = createOperantClient({ baseUrl: env.operantBaseUrl, token: env.operantInternalToken });
    const pipedream = buildPipedreamWiring(env);
    if (!pipedream) {
      console.warn(
        "[operant-plugin] Pipedream env (OPERANT_MCP_SOURCE_PIPEDREAM_URL, PIPEDREAM_PROJECT_CLIENT_ID, PIPEDREAM_PROJECT_CLIENT_SECRET, PIPEDREAM_PROJECT_ID) incomplete; Pipedream tools will not be registered.",
      );
      return;
    }
    const factoryDeps = (ctx: { requesterSenderId?: string }) => ({
      pipedreamClient: pipedream.pipedreamClient,
      operantClient,
      slackUserId: ctx.requesterSenderId ?? null,
    });
    api.registerTool((ctx) => createPipedreamSearchAppsTool(factoryDeps(ctx)));
    api.registerTool((ctx) => createPipedreamConnectAppTool(factoryDeps(ctx)));
    api.registerTool((ctx) => createPipedreamListConnectionsTool(factoryDeps(ctx)));
    api.registerTool((ctx) => createPipedreamListActionsTool(factoryDeps(ctx)));
    api.registerTool((ctx) => createPipedreamRunActionTool(factoryDeps(ctx)));
  },
});
