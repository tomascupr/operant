import assert from "node:assert/strict";
import test from "node:test";
import { revokePipedreamAccountsForWorkspace } from "../src/server.js";

const ws = { id: "w1", company_id: "c1" };
// audit() writes via pool.query; a no-op stub is enough for this unit test.
const pool = { query: async () => ({ rows: [], rowCount: 0 }) } as any;

function mockClient(
  accountsByUser: Record<string, Array<{ id: string; app: string }>>,
  deleteImpl?: (id: string) => void,
) {
  const deleted: string[] = [];
  const client = {
    listAccounts: async ({ externalUserId }: { externalUserId: string }) => accountsByUser[externalUserId] ?? [],
    deleteAccount: async (id: string) => {
      if (deleteImpl) deleteImpl(id);
      deleted.push(id);
    },
  } as any;
  return { client, deleted };
}

test("revokes every connected account for each wiped user", async () => {
  const { client, deleted } = mockClient({
    U_alice: [{ id: "apn_1", app: "github" }, { id: "apn_2", app: "gmail" }],
    U_bob: [{ id: "apn_3", app: "linear" }],
  });
  const r = await revokePipedreamAccountsForWorkspace(pool, ws, ["U_alice", "U_bob"], client);
  assert.equal(r.configured, true);
  assert.equal(r.revoked, 3);
  assert.equal(r.failures.length, 0);
  assert.deepEqual(deleted.sort(), ["apn_1", "apn_2", "apn_3"]);
});

test("records per-account failures without throwing the wipe", async () => {
  const { client } = mockClient(
    { U_alice: [{ id: "apn_1", app: "github" }, { id: "apn_2", app: "gmail" }] },
    (id) => { if (id === "apn_2") throw new Error("boom"); },
  );
  const r = await revokePipedreamAccountsForWorkspace(pool, ws, ["U_alice"], client);
  assert.equal(r.revoked, 1);
  assert.equal(r.failures.length, 1);
  assert.equal(r.failures[0].accountId, "apn_2");
});

test("no-op when Pipedream is unconfigured (null client)", async () => {
  const r = await revokePipedreamAccountsForWorkspace(pool, ws, ["U_alice"], null);
  assert.equal(r.configured, false);
  assert.equal(r.revoked, 0);
});

test("no-op for an empty user list", async () => {
  const { client } = mockClient({});
  const r = await revokePipedreamAccountsForWorkspace(pool, ws, [], client);
  assert.equal(r.configured, true);
  assert.equal(r.revoked, 0);
});
