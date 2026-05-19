import assert from "node:assert/strict";
import test from "node:test";
import { createSessionToken, hashSessionToken, readBearerToken } from "../src/auth.js";

test("creates random session tokens and sha256 hashes", () => {
  const first = createSessionToken();
  const second = createSessionToken();
  assert.notEqual(first.token, second.token);
  assert.equal(first.tokenHash, hashSessionToken(first.token));
  assert.equal(first.tokenHash.length, 64);
});

test("reads bearer tokens case-insensitively", () => {
  assert.equal(readBearerToken("Bearer abc123"), "abc123");
  assert.equal(readBearerToken("bearer abc123"), "abc123");
  assert.equal(readBearerToken("Token abc123"), null);
});
