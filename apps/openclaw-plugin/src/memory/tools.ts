import { jsonResult } from "openclaw/plugin-sdk/core";
import { Type } from "typebox";
import type { OperantClient } from "../operant-client.js";

export interface MemoryToolDependencies {
  operantClient: OperantClient;
  // The active chat user's raw principal id (Slack member id or Teams AAD id). The
  // control plane resolves the platform by shape and scopes private memory to it.
  principalId: string | null;
}

const VisibilityParam = Type.Union([Type.Literal("private"), Type.Literal("team")]);

function clampLimit(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value)
    ? Math.min(Math.max(Math.trunc(value), 1), 50)
    : fallback;
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const items = value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
  return items.length > 0 ? items : undefined;
}

const WriteParameters = Type.Object(
  {
    content: Type.String({ description: "The fact, preference, or decision to remember.", maxLength: 32768 }),
    visibility: Type.Optional(VisibilityParam),
    scopeKey: Type.Optional(Type.String({ description: "Optional topic grouping key, e.g. \"project-alpha\"." })),
    tags: Type.Optional(Type.Array(Type.String(), { maxItems: 20 })),
  },
  { additionalProperties: false },
);

const SearchParameters = Type.Object(
  {
    q: Type.Optional(Type.String({ description: "Keyword search across stored memory." })),
    tags: Type.Optional(Type.Array(Type.String(), { description: "Filter to entries carrying all of these tags." })),
    limit: Type.Optional(Type.Number({ description: "Maximum entries to return, up to 50." })),
  },
  { additionalProperties: false },
);

const SkillSearchParameters = Type.Object(
  {
    q: Type.Optional(Type.String({ description: "Keyword search across skill name, trigger, and body." })),
    tags: Type.Optional(Type.Array(Type.String(), { description: "Filter to skills carrying all of these tags." })),
    limit: Type.Optional(Type.Number({ description: "Maximum skills to return, up to 50." })),
  },
  { additionalProperties: false },
);

export function createMemoryWriteTool(deps: MemoryToolDependencies) {
  return {
    name: "operant_memory_write",
    label: "Store Memory",
    description: "Remember a fact, preference, or decision for later. Use visibility 'team' to share with the whole workspace or 'private' (default) to keep it to the current user. Secret-shaped values are stripped before storage.",
    parameters: WriteParameters,
    execute: async (_toolCallId: string, rawParams: unknown) => {
      if (!deps.principalId) return jsonResult({ error: "missing_principal_context" });
      const params = (rawParams ?? {}) as { content?: unknown; visibility?: unknown; scopeKey?: unknown; tags?: unknown };
      const content = typeof params.content === "string" ? params.content.trim() : "";
      if (!content) return jsonResult({ error: "missing_content" });
      const visibility = params.visibility === "team" ? "team" : params.visibility === "private" ? "private" : undefined;
      const scopeKey = typeof params.scopeKey === "string" && params.scopeKey.trim() ? params.scopeKey.trim() : undefined;
      const result = await deps.operantClient.writeMemory({
        principalId: deps.principalId,
        content,
        visibility,
        scopeKey,
        tags: stringArray(params.tags),
      });
      return jsonResult(result);
    },
  };
}

export function createMemorySearchTool(deps: MemoryToolDependencies) {
  return {
    name: "operant_memory_search",
    label: "Search Memory",
    description: "Search remembered context by keyword. Returns workspace team entries plus the current user's own private entries.",
    parameters: SearchParameters,
    execute: async (_toolCallId: string, rawParams: unknown) => {
      if (!deps.principalId) return jsonResult({ error: "missing_principal_context" });
      const params = (rawParams ?? {}) as { q?: unknown; tags?: unknown; limit?: unknown };
      const q = typeof params.q === "string" && params.q.trim() ? params.q.trim() : undefined;
      const result = await deps.operantClient.searchMemory({
        principalId: deps.principalId,
        q,
        tags: stringArray(params.tags),
        limit: clampLimit(params.limit, 10),
      });
      return jsonResult(result);
    },
  };
}

export function createSkillsSearchTool(deps: MemoryToolDependencies) {
  return {
    name: "operant_skills_search",
    label: "Search Skills",
    description: "Retrieve approved, reusable procedure definitions (skills) curated for the workspace. Search by keyword or tag, then follow the returned steps.",
    parameters: SkillSearchParameters,
    execute: async (_toolCallId: string, rawParams: unknown) => {
      if (!deps.principalId) return jsonResult({ error: "missing_principal_context" });
      const params = (rawParams ?? {}) as { q?: unknown; tags?: unknown; limit?: unknown };
      const q = typeof params.q === "string" && params.q.trim() ? params.q.trim() : undefined;
      const result = await deps.operantClient.searchSkills({
        principalId: deps.principalId,
        q,
        tags: stringArray(params.tags),
        limit: clampLimit(params.limit, 10),
      });
      return jsonResult(result);
    },
  };
}
