import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { decryptSecret, encryptSecret, parseMasterKey } from "../src/secrets.js";

test("encrypts and decrypts a secret envelope", () => {
  const key = randomBytes(32);
  const envelope = encryptSecret("xoxb-test-token", key);
  assert.notEqual(envelope, "xoxb-test-token");
  assert.equal(decryptSecret(envelope, key), "xoxb-test-token");
});

test("parses base64 master keys", () => {
  const key = randomBytes(32);
  assert.equal(parseMasterKey(key.toString("base64")).length, 32);
});

test("rejects invalid master key sizes", () => {
  assert.throws(() => parseMasterKey("short"), /32 bytes/);
});
