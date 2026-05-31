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

test("parses 64-hex and 32-byte utf8 master keys", () => {
  const hex = randomBytes(32).toString("hex");
  assert.equal(parseMasterKey(hex).length, 32);
  const utf8 = "abcdefghijklmnopqrstuvwxyz012345"; // 32 ASCII bytes
  assert.equal(Buffer.byteLength(utf8), 32);
  assert.deepEqual(parseMasterKey(utf8), Buffer.from(utf8, "utf8"));
});

test("fails loud on a malformed base64 key instead of silently leniently decoding it", () => {
  const b64 = randomBytes(32).toString("base64"); // valid, decodes to 32 bytes
  const footgun = b64[0] + "!" + b64.slice(1); // an invalid char Node would silently drop
  // Precondition: the old lenient path still yields 32 bytes, and it is not a utf8-32 key.
  assert.equal(Buffer.from(footgun, "base64").length, 32);
  assert.notEqual(Buffer.byteLength(footgun, "utf8"), 32);
  assert.throws(() => parseMasterKey(footgun), /invalid characters/);
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
