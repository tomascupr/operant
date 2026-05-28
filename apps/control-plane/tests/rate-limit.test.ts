import assert from "node:assert/strict";
import test from "node:test";
import { createRateLimiter } from "../src/rate-limit.js";

function clock(start = 1_000_000) {
  let t = start;
  return { now: () => t, advance: (ms: number) => { t += ms; } };
}

test("not limited until maxFailures is reached", () => {
  const c = clock();
  const rl = createRateLimiter({ maxFailures: 3, windowMs: 60_000, now: c.now });
  assert.equal(rl.isLimited("ip").limited, false);
  rl.recordFailure("ip");
  rl.recordFailure("ip");
  assert.equal(rl.isLimited("ip").limited, false, "2 < 3 is not limited");
  rl.recordFailure("ip");
  const verdict = rl.isLimited("ip");
  assert.equal(verdict.limited, true, "3 >= 3 is limited");
  assert.ok(verdict.retryAfterSeconds > 0);
});

test("window expiry clears the counter", () => {
  const c = clock();
  const rl = createRateLimiter({ maxFailures: 1, windowMs: 60_000, now: c.now });
  rl.recordFailure("ip");
  assert.equal(rl.isLimited("ip").limited, true);
  c.advance(60_001);
  assert.equal(rl.isLimited("ip").limited, false, "counter resets after the window elapses");
});

test("reset clears the counter immediately", () => {
  const c = clock();
  const rl = createRateLimiter({ maxFailures: 1, windowMs: 60_000, now: c.now });
  rl.recordFailure("ip");
  assert.equal(rl.isLimited("ip").limited, true);
  rl.reset("ip");
  assert.equal(rl.isLimited("ip").limited, false);
});

test("keys are throttled independently", () => {
  const c = clock();
  const rl = createRateLimiter({ maxFailures: 1, windowMs: 60_000, now: c.now });
  rl.recordFailure("a");
  assert.equal(rl.isLimited("a").limited, true);
  assert.equal(rl.isLimited("b").limited, false);
});

test("retryAfterSeconds reflects the remaining window", () => {
  const c = clock();
  const rl = createRateLimiter({ maxFailures: 1, windowMs: 60_000, now: c.now });
  rl.recordFailure("ip");
  c.advance(30_000);
  assert.equal(rl.isLimited("ip").retryAfterSeconds, 30);
});
