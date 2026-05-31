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

test("uses the v1 envelope and authenticates on decrypt (wrong key, tamper, bad version all throw)", () => {
  const key = randomBytes(32);
  const envelope = encryptSecret("super-secret", key);
  const parts = envelope.split(":");
  assert.equal(parts.length, 4);
  assert.equal(parts[0], "v1");
  // A different key fails the GCM auth tag.
  assert.throws(() => decryptSecret(envelope, randomBytes(32)));
  // Tampered ciphertext fails the auth tag.
  const flipped = parts[3][0] === "A" ? "B" : "A";
  const tampered = [parts[0], parts[1], parts[2], flipped + parts[3].slice(1)].join(":");
  assert.throws(() => decryptSecret(tampered, key));
  // An unsupported envelope version is rejected.
  assert.throws(() => decryptSecret("v2:a:b:c", key), /Unsupported encrypted secret envelope/);
});
