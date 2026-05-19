import assert from "node:assert/strict";
import test from "node:test";
import { pingTool } from "../src/index.js";

test("ping tool advertises the operant_ping name and an executable handler", () => {
  assert.equal(pingTool.name, "operant_ping");
  assert.equal(typeof pingTool.execute, "function");
});

test("ping tool returns ok plus an ISO timestamp", async () => {
  const result = await pingTool.execute("call-1", {});
  const [block] = result.content;
  assert.equal(block?.type, "text");
  const body = JSON.parse((block as { text: string }).text);
  assert.equal(body.ok, true);
  assert.match(body.timestamp, /^\d{4}-\d{2}-\d{2}T/);
});
