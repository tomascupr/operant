import assert from "node:assert/strict";
import test from "node:test";
import type { MemorySearchInput, MemoryWriteInput, OperantClient } from "../src/operant-client.js";
import { createMemorySearchTool, createMemoryWriteTool, createSkillsSearchTool, type MemoryToolDependencies } from "../src/memory/tools.js";

interface Captures {
  write?: MemoryWriteInput;
  search?: MemorySearchInput;
  skills?: MemorySearchInput;
}

function stubClient(captures: Captures): OperantClient {
  return {
    getUserContext: async () => ({ sessionKey: "k", workspaceId: "w", slackUserId: null, roles: [] }),
    checkPolicy: async () => ({ effect: "allow", reasons: [] }),
    searchPipedreamApps: async () => ({ apps: [] }),
    createPipedreamConnectToken: async () => ({ app: null, expiresAt: null, connectLinkUrl: "" }),
    listPipedreamAccounts: async () => ({ accounts: [] }),
    writeMemory: async (input) => {
      captures.write = input;
      return { id: "mem_1", createdAt: "2026-05-31T00:00:00Z" };
    },
    searchMemory: async (input) => {
      captures.search = input;
      return { entries: [{ id: "mem_1", content: "team note", visibility: "team", scope_key: null, tags: [], created_at: "t", updated_at: "t" }] };
    },
    searchSkills: async (input) => {
      captures.skills = input;
      return { skills: [{ id: "skill_1", name: "draft-email", trigger_hint: "when emailing", body: "step 1", tags: [] }] };
    },
  };
}

function deps(principalId: string | null, captures: Captures): MemoryToolDependencies {
  return { operantClient: stubClient(captures), principalId };
}

function parseFirstTextBlock(result: { content: ReadonlyArray<{ type: string; text?: string }> }): unknown {
  const block = result.content[0];
  assert.ok(block && block.type === "text" && typeof block.text === "string");
  return JSON.parse(block.text);
}

test("memory_write refuses without a principal in session context", async () => {
  const captures: Captures = {};
  const tool = createMemoryWriteTool(deps(null, captures));
  const body = parseFirstTextBlock(await tool.execute("call-1", { content: "remember this" })) as { error: string };
  assert.equal(body.error, "missing_principal_context");
  assert.equal(captures.write, undefined);
});

test("memory_write requires non-empty content", async () => {
  const captures: Captures = {};
  const tool = createMemoryWriteTool(deps("U_alice", captures));
  const body = parseFirstTextBlock(await tool.execute("call-1", { content: "   " })) as { error: string };
  assert.equal(body.error, "missing_content");
  assert.equal(captures.write, undefined);
});

test("memory_write forwards principal, content, visibility, and tags", async () => {
  const captures: Captures = {};
  const tool = createMemoryWriteTool(deps("U_alice", captures));
  const body = parseFirstTextBlock(await tool.execute("call-1", {
    content: "  Acme uses gpt-5  ",
    visibility: "team",
    scopeKey: "models",
    tags: ["config", "  ", 7],
  })) as { id: string };
  assert.equal(body.id, "mem_1");
  assert.deepEqual(captures.write, {
    principalId: "U_alice",
    content: "Acme uses gpt-5",
    visibility: "team",
    scopeKey: "models",
    tags: ["config"],
  });
});

test("memory_write defaults visibility/tags to undefined when omitted", async () => {
  const captures: Captures = {};
  const tool = createMemoryWriteTool(deps("U_alice", captures));
  await tool.execute("call-1", { content: "note" });
  assert.deepEqual(captures.write, { principalId: "U_alice", content: "note", visibility: undefined, scopeKey: undefined, tags: undefined });
});

test("memory_search propagates q and clamps limit to 50", async () => {
  const captures: Captures = {};
  const tool = createMemorySearchTool(deps("U_alice", captures));
  const body = parseFirstTextBlock(await tool.execute("call-1", { q: "  note ", limit: 999 })) as { entries: unknown[] };
  assert.equal(body.entries.length, 1);
  assert.deepEqual(captures.search, { principalId: "U_alice", q: "note", tags: undefined, limit: 50 });
});

test("memory_search refuses without a principal", async () => {
  const captures: Captures = {};
  const tool = createMemorySearchTool(deps(null, captures));
  const body = parseFirstTextBlock(await tool.execute("call-1", {})) as { error: string };
  assert.equal(body.error, "missing_principal_context");
});

test("skills_search forwards the query and returns workspace skills", async () => {
  const captures: Captures = {};
  const tool = createSkillsSearchTool(deps("U_alice", captures));
  const body = parseFirstTextBlock(await tool.execute("call-1", { q: "email" })) as { skills: Array<{ name: string }> };
  assert.equal(body.skills[0]?.name, "draft-email");
  assert.deepEqual(captures.skills, { principalId: "U_alice", q: "email", tags: undefined, limit: 10 });
});

test("skills_search refuses without a principal", async () => {
  const captures: Captures = {};
  const tool = createSkillsSearchTool(deps(null, captures));
  const body = parseFirstTextBlock(await tool.execute("call-1", {})) as { error: string };
  assert.equal(body.error, "missing_principal_context");
});
