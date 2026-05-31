#!/usr/bin/env node

const chunks = [];
for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));

let request;
try {
  request = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
} catch {
  request = {};
}
const baseUrl = process.env.OPERANT_CONTROL_PLANE_URL;
const token = process.env.OPERANT_INTERNAL_TOKEN;

if (!baseUrl || !token) {
  process.stdout.write(JSON.stringify({
    protocolVersion: 1,
    values: {},
    errors: Object.fromEntries((request.ids || []).map((id) => [id, { message: "Operant resolver environment is not configured" }])),
  }));
  process.exit(0);
}

const values = {};
const errors = {};

for (const id of request.ids || []) {
  try {
    const response = await fetch(`${baseUrl.replace(/\/$/, "")}/internal/openclaw/secrets/${encodeURIComponent(id)}`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(Number(process.env.OPERANT_RESOLVER_TIMEOUT_MS || 10000)),
    });
    if (!response.ok) {
      errors[id] = { message: `Secret lookup failed with ${response.status}` };
      continue;
    }
    const body = await response.json();
    if (typeof body.value !== "string") {
      errors[id] = { message: "Secret lookup returned no value" };
      continue;
    }
    values[id] = body.value;
  } catch (error) {
    errors[id] = { message: error instanceof Error ? error.message : String(error) };
  }
}

process.stdout.write(JSON.stringify({
  protocolVersion: 1,
  values,
  ...(Object.keys(errors).length > 0 ? { errors } : {}),
}));
