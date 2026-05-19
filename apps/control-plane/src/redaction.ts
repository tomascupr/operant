const REDACTED = "[REDACTED]";

const secretLikePattern = /\b(?:xox[a-z]-[A-Za-z0-9-]+|xapp-[A-Za-z0-9-]+|sk-[A-Za-z0-9_-]+|ghp_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]{16})\b/g;

function isSensitiveKey(key: string): boolean {
  const normalized = key.replace(/[-_]/g, "").toLowerCase();
  if (normalized.includes("secretref")) return false;
  return normalized.includes("token")
    || normalized.includes("apikey")
    || normalized.includes("password")
    || normalized.includes("secret")
    || normalized === "authorization"
    || normalized === "cookie"
    || normalized === "credential";
}

export function redactForPersistence(value: unknown): unknown {
  if (typeof value === "string") return value.replace(secretLikePattern, REDACTED);
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((item) => redactForPersistence(item));

  const output: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    output[key] = isSensitiveKey(key) ? REDACTED : redactForPersistence(child);
  }
  return output;
}

export function redactRecordForPersistence(value: Record<string, unknown>): Record<string, unknown> {
  return redactForPersistence(value) as Record<string, unknown>;
}
