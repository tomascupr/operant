// Fixed-window, in-memory failed-attempt limiter used to throttle admin-login
// brute-force. One Compose project is one single-process control plane, so
// module-local state is sufficient; a multi-replica deployment would move this
// to Redis (the optional queue profile already provisions it).

type Window = { count: number; resetAt: number };

export type RateLimitVerdict = { limited: boolean; retryAfterSeconds: number };

export type RateLimiter = {
  isLimited(key: string): RateLimitVerdict;
  recordFailure(key: string): void;
  reset(key: string): void;
};

export function createRateLimiter(options: {
  maxFailures: number;
  windowMs: number;
  now?: () => number;
}): RateLimiter {
  const { maxFailures, windowMs } = options;
  const now = options.now ?? (() => Date.now());
  const windows = new Map<string, Window>();

  // Returns the live window for a key, dropping it if its window has elapsed.
  function current(key: string): Window | undefined {
    const window = windows.get(key);
    if (window && window.resetAt <= now()) {
      windows.delete(key);
      return undefined;
    }
    return window;
  }

  return {
    isLimited(key) {
      const window = current(key);
      if (window && window.count >= maxFailures) {
        return {
          limited: true,
          retryAfterSeconds: Math.max(1, Math.ceil((window.resetAt - now()) / 1000)),
        };
      }
      return { limited: false, retryAfterSeconds: 0 };
    },
    recordFailure(key) {
      const window = current(key);
      if (!window) {
        windows.set(key, { count: 1, resetAt: now() + windowMs });
        return;
      }
      window.count += 1;
    },
    reset(key) {
      windows.delete(key);
    },
  };
}
