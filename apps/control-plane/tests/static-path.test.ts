import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { isPathInsideDirectory } from "../src/server.js";

test("static path guard rejects sibling directories with matching prefixes", () => {
  const publicDir = path.resolve("/tmp/operant/public");

  assert.equal(isPathInsideDirectory(path.join(publicDir, "index.html"), publicDir), true);
  assert.equal(isPathInsideDirectory(publicDir, publicDir), true);
  assert.equal(isPathInsideDirectory(path.resolve("/tmp/operant/public2/index.html"), publicDir), false);
  assert.equal(isPathInsideDirectory(path.resolve("/tmp/operant/public/../secret.txt"), publicDir), false);
});
