const $ = (id) => document.getElementById(id);

const PIPEDREAM_APPS = [
  { slug: "gmail", name: "Gmail", icon: "/icons/gmail.svg" },
  { slug: "slack", name: "Slack", icon: "/icons/slack.svg" },
  { slug: "notion", name: "Notion", icon: "/icons/notion.svg" },
  { slug: "github", name: "GitHub", icon: "/icons/github.svg" },
  { slug: "linear", name: "Linear", icon: "/icons/linear.svg" },
  { slug: "hubspot", name: "HubSpot", icon: "/icons/hubspot.svg" },
  { slug: "google_sheets", name: "Google Sheets", icon: "/icons/google_sheets.svg" },
  { slug: "google_calendar", name: "Google Calendar", icon: "/icons/google_calendar.svg" },
];

const appState = {
  summary: null,
  settings: null,
  policy: null,
  roles: [],
  credentials: [],
  users: [],
  approvals: [],
  sessions: [],
  jobs: [],
  usageSummary: null,
  usageEvents: [],
  audit: [],
  pipedreamApps: [],
  pipedreamAccounts: [],
  selectedPipedreamApp: null,
  pipedreamActions: [],
};

let activePolicyFilterTool = null;
let confirmResolve = null;

function splitIds(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parsePermissionPairs(value) {
  return String(value || "")
    .split(/\n|,/)
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => {
      const [action, resource] = item.split(/\s+/);
      if (!action || !resource) throw new Error("Each permission needs an action and resource");
      return { action, resource };
    });
}

function selectedValues(select) {
  return Array.from(select.selectedOptions, (option) => option.value).filter(Boolean);
}

function text(value, fallback = "—") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function number(value) {
  return Number(value || 0).toLocaleString();
}

function usd(value) {
  return Number(value || 0).toLocaleString(undefined, { style: "currency", currency: "USD", maximumFractionDigits: 6 });
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "—";
}

function shortId(value, keep = 8) {
  const raw = String(value || "");
  if (raw.length <= keep * 2 + 3) return raw || "—";
  return `${raw.slice(0, keep)}...${raw.slice(-keep)}`;
}

function maskSecretRef(value) {
  const raw = String(value || "");
  const parts = raw.split("/").filter(Boolean);
  if (parts.length <= 3) return raw || "—";
  return `${parts[0]}/.../${parts.slice(-2).join("/")}`;
}

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "className") node.className = value;
    else if (key === "textContent") node.textContent = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key === "ariaLabel") node.setAttribute("aria-label", value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of Array.isArray(children) ? children : [children]) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function toast(message) {
  const node = $("toast");
  node.textContent = message;
  node.classList.add("show");
  setTimeout(() => node.classList.remove("show"), 3600);
}

function setStatusPill(node, textValue, tone = "") {
  node.className = `status-pill ${tone}`.trim();
  node.textContent = textValue;
}

function statusPill(textValue, tone = "") {
  return el("span", { className: `status-pill ${tone}`.trim(), textContent: textValue });
}

function jsonBlock(value) {
  return el("pre", { className: "json-block", textContent: JSON.stringify(value, null, 2) });
}

function emptyState(title, detail) {
  return el("div", { className: "empty-state" }, [
    el("strong", { textContent: title }),
    detail ? el("small", { textContent: detail }) : null,
  ]);
}

function renderTable(target, columns, rows, emptyTitle, emptyDetail = "") {
  target.replaceChildren();
  if (!rows.length) {
    target.append(emptyState(emptyTitle, emptyDetail));
    return;
  }
  const table = el("table", { className: "data-table" });
  const thead = el("thead", {}, [
    el("tr", {}, columns.map((column) => el("th", { textContent: column.label }))),
  ]);
  const tbody = el("tbody");
  for (const row of rows) {
    tbody.append(el("tr", {}, columns.map((column) => {
      const rendered = column.render ? column.render(row) : text(row[column.key]);
      return el("td", {}, rendered instanceof Node ? rendered : String(rendered));
    })));
  }
  table.append(thead, tbody);
  target.append(el("div", { className: "data-table-wrap" }, table));
}

function renderKeyValueRows(target, rows) {
  target.replaceChildren(...rows.map((row) => el("div", { className: "summary-row" }, [
    el("span", { textContent: row.label }),
    row.node ?? statusPill(row.value, row.tone),
  ])));
}

async function request(path, options = {}) {
  const sessionToken = localStorage.getItem("operant.sessionToken");
  const response = await fetch(path, {
    ...options,
    headers: {
      "content-type": "application/json",
      ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
      ...(options.headers || {}),
    },
  });
  const textBody = await response.text();
  const body = textBody ? JSON.parse(textBody) : {};
  if (!response.ok) {
    const error = new Error(body.error || `Request failed: ${response.status}`);
    error.status = response.status;
    if (body.code) error.code = body.code;
    if (body.issues) error.issues = body.issues;
    throw error;
  }
  return body;
}

async function login(slackUserId, adminLoginToken) {
  const result = await request("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ slackUserId, adminLoginToken }),
    headers: {},
  });
  localStorage.setItem("operant.sessionToken", result.token);
  localStorage.setItem("operant.adminSlackUserId", slackUserId);
  $("session-state").textContent = `${slackUserId} signed in`;
  $("login-result").replaceChildren(
    statusPill("Signed in", "ok"),
    el("span", { textContent: ` Session expires ${formatDate(result.expiresAt)}` }),
  );
  return result;
}

function renderSignedOut() {
  const savedSlackUserId = localStorage.getItem("operant.adminSlackUserId");
  const sessionToken = localStorage.getItem("operant.sessionToken");
  $("session-state").textContent = sessionToken && savedSlackUserId ? `${savedSlackUserId} signed in` : "Not signed in";
  for (const id of ["credentials", "channels", "sessions", "usage", "approvals", "audit"]) $(id).textContent = "-";
  $("settings-result").textContent = "Sign in to view settings.";
  $("usage-summary").replaceChildren(emptyState("Sign in required", "Usage totals are available to authorized users."));
  $("usage-events").replaceChildren(emptyState("Sign in required", "Usage events are hidden until sign-in."));
  $("activity-result").replaceChildren(emptyState("Sign in required", "Sessions and jobs are hidden until sign-in."));
  $("audit-log").replaceChildren(emptyState("Sign in required", "Audit rows are hidden until sign-in."));
  $("approvals-result").replaceChildren(emptyState("Sign in required", "Approvals are hidden until sign-in."));
  $("users-result").replaceChildren(emptyState("Sign in required", "Users are hidden until sign-in."));
  $("roles-result").replaceChildren(emptyState("Sign in required", "Roles are hidden until sign-in."));
  $("integration-credentials-result").replaceChildren(emptyState("Sign in required", "Credential metadata is hidden until sign-in."));
  $("pipedream-diagnostics").textContent = "Sign in to view Pipedream diagnostics.";
  $("pipedream-apps-grid").textContent = "Sign in to manage Pipedream policies.";
  $("pipedream-marketplace-grid").replaceChildren(emptyState("Sign in required", "Pipedream apps are hidden until sign-in."));
  $("pipedream-accounts").replaceChildren(emptyState("Sign in required", "Connected accounts are hidden until sign-in."));
  $("pipedream-actions").replaceChildren(emptyState("Select an app", "Sign in, then select an app to preview available actions."));
  setStatusPill($("pipedream-marketplace-state"), "Waiting", "pending");
}

function credentialFacts() {
  const refIds = (appState.credentials ?? []).map((credential) => credential.secret_ref_id ?? "");
  return {
    slackBot: refIds.some((id) => id.endsWith("/slack/botToken")),
    slackApp: refIds.some((id) => id.endsWith("/slack/appToken")),
    modelKey: refIds.some((id) => id.includes("/models/") && id.endsWith("/apiKey")),
    integrationCount: Math.max(0, refIds.length - 3),
  };
}

function readinessFacts() {
  const credentials = credentialFacts();
  const policy = appState.policy ?? {};
  const hasApprover = (policy.approvalPolicies ?? []).some((rule) =>
    rule.enabled !== false && (rule.approverSlackUserIds ?? []).length > 0,
  );
  return [
    {
      key: "session",
      label: "Admin session",
      detail: localStorage.getItem("operant.sessionToken") ? "Operator session is active." : "Sign in or complete first setup.",
      done: Boolean(localStorage.getItem("operant.sessionToken")),
    },
    {
      key: "slack",
      label: "Slack Socket Mode secrets",
      detail: credentials.slackBot && credentials.slackApp ? "Bot and app tokens are saved as SecretRefs." : "Save xoxb and xapp tokens.",
      done: credentials.slackBot && credentials.slackApp,
    },
    {
      key: "model",
      label: "Model key",
      detail: credentials.modelKey ? "Model provider key is saved as a SecretRef." : "Save a provider API key.",
      done: credentials.modelKey,
    },
    {
      key: "policy",
      label: "Users and channels",
      detail: (policy.allowedDmUserIds ?? []).length || (policy.channelPolicies ?? []).length
        ? `${(policy.allowedDmUserIds ?? []).length} DM users and ${(policy.channelPolicies ?? []).length} channels configured.`
        : "Add at least one Slack user or channel.",
      done: (policy.allowedDmUserIds ?? []).length > 0 || (policy.channelPolicies ?? []).length > 0,
    },
    {
      key: "approvals",
      label: "Risk approvals",
      detail: hasApprover ? "Risky exec work has configured approvers." : "Add an approver for risky actions.",
      done: hasApprover,
    },
    {
      key: "config",
      label: "OpenClaw config",
      detail: appState.summary?.latestConfig ? `Latest checksum ${shortId(appState.summary.latestConfig.checksum, 6)}.` : "Generate the OpenClaw config.",
      done: Boolean(appState.summary?.latestConfig),
    },
  ];
}

function renderSetupChecklist() {
  const facts = readinessFacts();
  const complete = facts.filter((item) => item.done).length;
  $("setup-progress").textContent = `${complete} of ${facts.length} complete`;
  const ready = complete === facts.length;
  setStatusPill(
    $("readiness-state"),
    ready ? "Ready to run Slack acceptance" : "Setup pending",
    ready ? "ok" : "pending",
  );
  $("setup-checklist").replaceChildren(...facts.map((item) => el("article", { className: `check-item ${item.done ? "done" : ""}` }, [
    el("div", { className: "check-dot", textContent: item.done ? "✓" : "•" }),
    el("div", { className: "check-copy" }, [
      el("strong", { textContent: item.label }),
      el("small", { textContent: item.detail }),
    ]),
  ])));
}

function renderConfigSummary(summary) {
  const target = $("config-summary");
  target.replaceChildren();
  if (!summary?.latestConfig) {
    target.append(emptyState("No config generated", "Save credentials or regenerate OpenClaw config after policy changes."));
    return;
  }
  renderKeyValueRows(target, [
    { label: "Checksum", value: shortId(summary.latestConfig.checksum, 12), tone: "ok" },
    { label: "Path", node: el("span", { className: "mono", textContent: summary.latestConfig.config_path }) },
    { label: "Generated", value: formatDate(summary.latestConfig.generated_at), tone: "ok" },
  ]);
}

function renderCredentials(credentials) {
  const target = $("integration-credentials-result");
  renderTable(target, [
    { label: "Kind", render: (row) => statusPill(row.kind, "ok") },
    { label: "Label", render: (row) => text(row.label) },
    { label: "Scope", render: (row) => row.slack_user_id ? `User ${row.slack_user_id}` : "Workspace shared" },
    { label: "SecretRef", render: (row) => el("span", { className: "code-chip", textContent: maskSecretRef(row.secret_ref_id) }) },
    { label: "Updated", render: (row) => formatDate(row.updated_at) },
  ], credentials, "No integration credentials saved", "Slack/model setup credentials and customer integration secrets will appear as masked metadata.");

  const savedRefIds = credentials.map((credential) => credential.secret_ref_id ?? "");
  for (const indicator of document.querySelectorAll(".saved-indicator")) {
    const suffix = indicator.dataset.savedFor;
    const prefix = indicator.dataset.savedForPrefix;
    const matched = savedRefIds.some((id) =>
      (suffix && id.endsWith(`/${suffix}`)) || (prefix && id.includes(`/${prefix}`)),
    );
    indicator.textContent = matched ? "Saved as SecretRef - leave blank to keep, or re-enter to rotate." : "Not saved yet.";
  }
}

function renderUsers(users) {
  renderTable($("users-result"), [
    { label: "Slack user", render: (row) => el("span", { className: "code-chip", textContent: row.slack_user_id }) },
    { label: "Name", render: (row) => text(row.name) },
    { label: "Email", render: (row) => text(row.email) },
    { label: "Roles", render: (row) => (row.roles ?? []).map((role) => statusPill(role, role === "owner" ? "ok" : "")).reduce((frag, node) => (frag.append(node, " "), frag), document.createDocumentFragment()) },
    { label: "Created", render: (row) => formatDate(row.created_at) },
  ], users, "No users yet", "First credential setup creates the owner.");
}

function renderRoles(roles) {
  renderTable($("roles-result"), [
    { label: "Role", render: (row) => statusPill(row.name, row.builtin ? "ok" : "pending") },
    { label: "Type", render: (row) => row.builtin ? "Built-in" : "Custom" },
    { label: "Permissions", render: (row) => `${(row.permissions ?? []).length} grants` },
    { label: "Examples", render: (row) => (row.permissions ?? []).slice(0, 4).map((permission) => `${permission.action} ${permission.resource}`).join(", ") || "—" },
  ], roles, "No roles loaded", "Sign in to view the role catalog.");

  const select = $("user-roles-select");
  const previouslySelected = new Set(Array.from(select.selectedOptions, (option) => option.value));
  const seedDefault = previouslySelected.size === 0;
  const options = roles.map((role) => {
    const option = document.createElement("option");
    option.value = role.name;
    option.textContent = role.name;
    if (previouslySelected.has(role.name) || (seedDefault && role.name === "member")) option.selected = true;
    return option;
  });
  select.replaceChildren(...options);
}

function renderUsageSummary(usage) {
  const target = $("usage-summary");
  target.replaceChildren();
  if (!usage?.totals?.events) {
    target.append(emptyState("No usage events yet", "Sync OpenClaw activity or ingest events to populate usage."));
    return;
  }
  const cards = el("div", { className: "usage-cards" }, [
    el("div", { className: "stat-tile" }, [el("span", { className: "stat-value", textContent: number(usage.totals.events) }), el("small", { textContent: "Events" })]),
    el("div", { className: "stat-tile" }, [el("span", { className: "stat-value", textContent: number(usage.totals.total_tokens) }), el("small", { textContent: "Total tokens" })]),
    el("div", { className: "stat-tile" }, [el("span", { className: "stat-value", textContent: number(usage.totals.input_tokens) }), el("small", { textContent: "Input tokens" })]),
    el("div", { className: "stat-tile" }, [el("span", { className: "stat-value", textContent: usd(usage.totals.estimated_cost_usd) }), el("small", { textContent: "Estimated cost" })]),
  ]);
  const modelTarget = el("div", { className: "table-surface" });
  const toolTarget = el("div", { className: "table-surface" });
  renderTable(modelTarget, [
    { label: "Provider", render: (row) => text(row.provider) },
    { label: "Model", render: (row) => text(row.model) },
    { label: "Events", render: (row) => number(row.events) },
    { label: "Tokens", render: (row) => number(row.total_tokens) },
    { label: "Cost", render: (row) => usd(row.estimated_cost_usd) },
  ], usage.byModel ?? [], "No model usage", "");
  renderTable(toolTarget, [
    { label: "Tool", render: (row) => text(row.tool_name) },
    { label: "Events", render: (row) => number(row.events) },
    { label: "Tokens", render: (row) => number(row.total_tokens) },
    { label: "Cost", render: (row) => usd(row.estimated_cost_usd) },
  ], usage.byTool ?? [], "No tool usage", "");
  target.append(cards, modelTarget, toolTarget);
}

function renderUsageEvents(items) {
  renderTable($("usage-events"), [
    { label: "When", render: (row) => formatDate(row.created_at) },
    { label: "Provider", render: (row) => text(row.provider) },
    { label: "Model", render: (row) => text(row.model) },
    { label: "Tool", render: (row) => text(row.tool_name, "model") },
    { label: "Tokens", render: (row) => number(Number(row.input_tokens || 0) + Number(row.output_tokens || 0)) },
    { label: "Cost", render: (row) => usd(row.estimated_cost_usd) },
  ], items.slice(0, 50), "No usage events yet", "Usage events appear after OpenClaw sync or internal event ingest.");
}

function renderAudit(items) {
  renderTable($("audit-log"), [
    { label: "When", render: (row) => formatDate(row.created_at) },
    { label: "Event", render: (row) => el("span", { className: "code-chip", textContent: row.event_type }) },
    { label: "Outcome", render: (row) => statusPill(text(row.outcome), row.outcome === "success" ? "ok" : row.outcome === "deny" || row.outcome === "failure" ? "bad" : "pending") },
    { label: "Resource", render: (row) => `${row.resource_type}${row.resource_id ? ` / ${shortId(row.resource_id, 6)}` : ""}` },
    { label: "Metadata", render: (row) => shortId(JSON.stringify(row.metadata ?? {}), 30) },
  ], items.slice(0, 80), "No audit events yet", "Actions taken through the control plane will appear here.");
}

function renderActivity(sessions, jobs) {
  const target = $("activity-result");
  target.replaceChildren();
  const rows = [
    ...sessions.slice(0, 10).map((item) => ({ ...item, kind: "Session" })),
    ...jobs.slice(0, 10).map((item) => ({ ...item, kind: "Job" })),
  ];
  if (!rows.length) {
    target.append(emptyState("No sessions or jobs yet", "Sync OpenClaw activity to import observed runtime work."));
    return;
  }
  for (const item of rows) {
    const isJob = item.kind === "Job";
    const title = isJob ? `Job ${item.openclaw_run_id || shortId(item.id)}` : `Session ${item.openclaw_session_key || shortId(item.id)}`;
    target.append(el("article", { className: "decision-item" }, [
      el("div", { className: "decision-header" }, [
        el("div", {}, [el("strong", { textContent: title }), el("small", { textContent: item.kind })]),
        statusPill(item.status || "observed", item.status === "failed" ? "bad" : "ok"),
      ]),
      el("small", { textContent: `${formatDate(item.last_event_at || item.started_at || item.created_at)}${item.slack_user_id ? ` · ${item.slack_user_id}` : ""}` }),
      jsonBlock({
        id: item.id,
        session: item.openclaw_session_key,
        run: item.openclaw_run_id,
        channel: item.slack_channel_id,
        metadata: item.metadata,
      }),
    ]));
  }
}

function renderApprovals(items) {
  const target = $("approvals-result");
  target.replaceChildren();
  if (!items.length) {
    target.append(emptyState("No approvals yet", "Approval-gated requests will be listed with decision controls."));
    return;
  }
  for (const item of items.slice(0, 30)) {
    const requirement = item.payload?.operantApproval ?? {};
    const row = el("article", { className: "decision-item" }, [
      el("div", { className: "decision-header" }, [
        el("div", {}, [
          el("strong", { textContent: `${item.action} on ${item.resource}` }),
          el("small", { textContent: `Requested ${formatDate(item.created_at)}` }),
        ]),
        statusPill(item.status, item.status === "approved" ? "ok" : item.status === "denied" ? "bad" : "pending"),
      ]),
      el("div", { className: "summary-row" }, [
        el("span", { textContent: "Approvers" }),
        el("span", { className: "mono", textContent: (requirement.approverSlackUserIds ?? []).join(", ") || "—" }),
      ]),
      el("div", { className: "summary-row" }, [
        el("span", { textContent: "Minimum approvals" }),
        statusPill(String(requirement.minApprovals ?? 1), "pending"),
      ]),
    ]);
    if (item.status === "pending") {
      const actions = el("div", { className: "actions" });
      for (const decision of ["approved", "denied"]) {
        actions.append(el("button", {
          type: "button",
          className: decision === "approved" ? "" : "danger-button",
          textContent: decision === "approved" ? "Approve" : "Deny",
          dataset: { approvalId: item.id, status: decision },
        }));
      }
      row.append(actions);
    }
    target.append(row);
  }
}

function normalizePolicy(policy) {
  return {
    allowedDmUserIds: policy?.allowedDmUserIds ?? [],
    channelPolicies: policy?.channelPolicies ?? [],
    toolPolicies: policy?.toolPolicies ?? [],
    approvalPolicies: policy?.approvalPolicies ?? [],
  };
}

function renderPolicyStructured(policy) {
  const normalized = normalizePolicy(policy);
  const target = $("policy-structured");
  target.replaceChildren();
  target.append(el("div", { className: "summary-row" }, [
    el("span", { textContent: "DM allowlist" }),
    el("span", { className: "mono", textContent: normalized.allowedDmUserIds.join(", ") || "Empty" }),
  ]));

  const channelTarget = el("div", { className: "table-surface" });
  renderTable(channelTarget, [
    { label: "Channel", render: (row) => el("span", { className: "code-chip", textContent: row.channelId }) },
    { label: "Enabled", render: (row) => statusPill(row.enabled ? "Enabled" : "Disabled", row.enabled ? "ok" : "bad") },
    { label: "Mention", render: (row) => row.requireMention ? "Required" : "Not required" },
    { label: "Allowed", render: (row) => (row.allowedUserIds ?? []).join(", ") || "—" },
    { label: "Denied", render: (row) => (row.deniedUserIds ?? []).join(", ") || "—" },
  ], normalized.channelPolicies, "No channel policies", "Credential setup can seed the first allowlist.");

  const toolTarget = el("div", { className: "table-surface" });
  renderTable(toolTarget, [
    { label: "Tool", render: (row) => el("span", { className: "code-chip", textContent: row.tool }) },
    { label: "Action", render: (row) => row.action },
    { label: "Effect", render: (row) => statusPill(row.effect, row.effect === "allow" ? "ok" : row.effect === "deny" ? "bad" : "pending") },
    { label: "Users", render: (row) => (row.slackUserIds ?? []).join(", ") || "All" },
    { label: "Roles", render: (row) => (row.roleNames ?? []).join(", ") || "All" },
  ], normalized.toolPolicies, "No tool policies", "Add allow, deny, or approval-required tool rules.");

  const approvalTarget = el("div", { className: "table-surface" });
  renderTable(approvalTarget, [
    { label: "Name", render: (row) => row.name },
    { label: "Pattern", render: (row) => `${row.actionPattern} / ${row.resourcePattern}` },
    { label: "Approvers", render: (row) => (row.approverSlackUserIds ?? []).join(", ") || "—" },
    { label: "Min", render: (row) => String(row.minApprovals) },
    { label: "State", render: (row) => statusPill(row.enabled ? "Enabled" : "Disabled", row.enabled ? "ok" : "bad") },
  ], normalized.approvalPolicies, "No approval policies", "Risky actions should have at least one enabled approval policy.");

  target.append(channelTarget, toolTarget, approvalTarget);
}

function pipedreamTool(slug) {
  return `pipedream:${slug}`;
}

function pipedreamRows(policy, slug) {
  const tool = pipedreamTool(slug);
  return (policy?.toolPolicies ?? []).filter((row) => row.tool === tool);
}

function appWidePipedreamRule(policy, slug) {
  const rows = pipedreamRows(policy, slug);
  return rows.find((row) => row.action === "*") ?? rows[0] ?? null;
}

function normalizedPipedreamRule(policy, slug) {
  const rule = appWidePipedreamRule(policy, slug);
  return {
    tool: pipedreamTool(slug),
    action: "*",
    effect: rule?.effect ?? "allow",
    slackUserIds: rule?.slackUserIds ?? [],
    roleNames: rule?.roleNames ?? [],
  };
}

function renderPipedreamDiagnostics(diagnostics) {
  const target = $("pipedream-diagnostics");
  target.replaceChildren();

  const env = el("div", { className: "diagnostic-grid" });
  for (const item of diagnostics.env ?? []) {
    env.append(el("div", {}, [
      el("span", { textContent: item.name }),
      statusPill(item.present ? "present" : "missing", item.present ? "ok" : "bad"),
    ]));
  }

  const checks = el("div", { className: "diagnostic-grid" });
  checks.append(
    el("div", {}, [el("span", { textContent: "Operant plugin" }), statusPill(diagnostics.plugin?.status ?? "unknown", diagnostics.plugin?.ok ? "ok" : "bad")]),
    el("div", {}, [el("span", { textContent: "OAuth handshake" }), statusPill(diagnostics.oauth?.status ?? "unknown", diagnostics.oauth?.ok ? "ok" : "bad")]),
    el("div", {}, [
      el("span", { textContent: "Last invocation" }),
      statusPill(diagnostics.lastInvocation ? `${diagnostics.lastInvocation.status} · ${formatDate(diagnostics.lastInvocation.timestamp)}` : "none", diagnostics.lastInvocation ? "ok" : "pending"),
    ]),
  );

  target.append(env, checks);
}

function renderPolicyFilteredRows(policy, tool = activePolicyFilterTool) {
  const target = $("policy-filtered-rows");
  if (!tool) {
    target.textContent = "No app policy filter selected.";
    return;
  }
  const rows = (policy?.toolPolicies ?? []).filter((row) => row.tool === tool);
  target.replaceChildren(rows.length ? jsonBlock(rows) : emptyState(`No policy rows for ${tool}`, "Use the structured tool editor or app cards to add one."));
}

function renderPipedreamApps(policy, roles) {
  const target = $("pipedream-apps-grid");
  target.replaceChildren();
  if (!policy) {
    target.textContent = "Sign in to manage Pipedream policies.";
    return;
  }
  for (const app of PIPEDREAM_APPS) {
    const rows = pipedreamRows(policy, app.slug);
    const rule = normalizedPipedreamRule(policy, app.slug);
    const card = el("article", { className: "pipedream-card", dataset: { app: app.slug } });

    const icon = el("img", { src: app.icon, alt: "", width: "32", height: "32" });
    const title = el("div", {}, [
      el("strong", { textContent: app.name }),
      el("small", { textContent: `${rows.length} policy ${rows.length === 1 ? "rule" : "rules"} for ${rule.tool}` }),
    ]);
    card.append(el("div", { className: "app-card-header" }, [
      el("div", { className: "app-card-title" }, [icon, title]),
      statusPill(rule.effect, rule.effect === "allow" ? "ok" : rule.effect === "deny" ? "bad" : "pending"),
    ]));

    const toggle = el("input", { type: "checkbox", className: "pipedream-toggle" });
    toggle.checked = rule.effect !== "deny";
    const mode = el("select", { className: "pipedream-mode" });
    for (const value of ["allow", "approval_required", "deny"]) {
      const option = el("option", { value, textContent: value });
      option.selected = rule.effect === value;
      mode.append(option);
    }
    const roleSelect = el("select", { className: "pipedream-roles", multiple: true, size: String(Math.min(Math.max(roles.length || 1, 3), 5)) });
    const selectedRoles = new Set(rule.roleNames ?? []);
    for (const role of roles) {
      const option = el("option", { value: role.name, textContent: role.name });
      option.selected = selectedRoles.has(role.name);
      roleSelect.append(option);
    }
    card.append(el("div", { className: "app-controls" }, [
      el("label", { className: "toggle-row" }, [toggle, el("span", { textContent: "Enabled" })]),
      el("label", {}, ["Mode", mode]),
      el("label", {}, ["Scoped to roles", roleSelect]),
      el("button", { type: "button", className: "link-button pipedream-raw", textContent: "View raw policy rows" }),
    ]));
    target.append(card);
  }
}

function curatedPipedreamApp(slug) {
  return PIPEDREAM_APPS.find((app) => app.slug === slug);
}

function pipedreamAppIcon(app) {
  const curated = curatedPipedreamApp(app.slug);
  if (curated) return el("img", { src: curated.icon, alt: "", width: "32", height: "32" });
  const initials = String(app.name || app.slug || "?")
    .split(/[\s_-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() || "")
    .join("") || "?";
  return el("span", { className: "app-letter-tile", textContent: initials });
}

function policyForPipedreamSlug(slug) {
  const rule = normalizedPipedreamRule(appState.policy, slug);
  return rule.effect;
}

function accountForApp(slug) {
  return (appState.pipedreamAccounts ?? []).find((account) => account.app === slug);
}

function renderPipedreamAccounts(accounts) {
  renderTable($("pipedream-accounts"), [
    { label: "App", render: (row) => text(row.appName || row.app) },
    { label: "Account", render: (row) => text(row.name, row.id) },
    { label: "State", render: (row) => statusPill(row.healthy === false ? "needs attention" : "connected", row.healthy === false ? "bad" : "ok") },
    { label: "Updated", render: (row) => formatDate(row.updatedAt || row.createdAt) },
    {
      label: "Action",
      render: (row) => el("button", {
        type: "button",
        className: "link-button pipedream-disconnect",
        dataset: { accountId: row.id },
        textContent: "Disconnect",
      }),
    },
  ], accounts, "No connected accounts", "Connect an app from the marketplace to let Operant act under your account.");
}

function renderPipedreamMarketplace() {
  const target = $("pipedream-marketplace-grid");
  target.replaceChildren();
  const apps = appState.pipedreamApps ?? [];
  if (!apps.length) {
    target.append(emptyState("No apps found", "Search by app name or check Pipedream configuration."));
    return;
  }
  for (const app of apps) {
    const account = accountForApp(app.slug);
    const policy = policyForPipedreamSlug(app.slug);
    const selected = appState.selectedPipedreamApp === app.slug;
    const card = el("article", { className: selected ? "marketplace-card selected" : "marketplace-card", dataset: { app: app.slug } });
    card.append(el("div", { className: "app-card-header" }, [
      el("div", { className: "app-card-title" }, [
        pipedreamAppIcon(app),
        el("div", {}, [
          el("strong", { textContent: app.name }),
          el("small", { textContent: app.slug }),
        ]),
      ]),
      statusPill(account ? "connected" : "not connected", account ? "ok" : "pending"),
    ]));
    card.append(el("p", { textContent: app.description || "Pipedream Connect app" }));
    card.append(el("div", { className: "card-meta" }, [
      statusPill(policy, policy === "allow" ? "ok" : policy === "deny" ? "bad" : "pending"),
      app.category ? statusPill(app.category, "") : null,
    ].filter(Boolean)));
    card.append(el("div", { className: "app-controls" }, [
      el("button", { type: "button", className: "secondary-button pipedream-preview", textContent: "Preview Actions" }),
      el("button", { type: "button", className: account ? "secondary-button pipedream-connect" : "pipedream-connect", textContent: account ? "Reconnect" : "Connect" }),
    ]));
    target.append(card);
  }
}

function renderPipedreamActions(appSlug, actions) {
  const target = $("pipedream-actions");
  if (!appSlug) {
    target.replaceChildren(emptyState("Select an app", "Choose an app to preview available actions."));
    return;
  }
  renderTable(target, [
    { label: "Tool", render: (row) => el("span", { className: "code-chip", textContent: row.toolName }) },
    { label: "Action", render: (row) => text(row.action) },
    { label: "Policy", render: (row) => statusPill(row.policy?.effect ?? "unknown", row.policy?.effect === "allow" ? "ok" : row.policy?.effect === "approval_required" ? "pending" : "bad") },
    { label: "Description", render: (row) => text(row.description) },
  ], actions, `No available actions for ${appSlug}`, "Policy may deny actions or Pipedream may not expose MCP tools for this app.");
}

async function loadPipedreamMarketplace(q = "") {
  setStatusPill($("pipedream-marketplace-state"), "Loading", "pending");
  const params = new URLSearchParams({ limit: "40" });
  if (q) params.set("q", q);
  try {
    const [apps, accounts] = await Promise.all([
      request(`/api/integrations/pipedream/apps?${params}`),
      request("/api/integrations/pipedream/accounts"),
    ]);
    appState.pipedreamApps = apps.apps ?? [];
    appState.pipedreamAccounts = accounts.accounts ?? [];
    renderPipedreamMarketplace();
    renderPipedreamAccounts(appState.pipedreamAccounts);
    setStatusPill($("pipedream-marketplace-state"), `${appState.pipedreamApps.length} apps`, "ok");
  } catch (error) {
    appState.pipedreamApps = [];
    appState.pipedreamAccounts = [];
    $("pipedream-marketplace-grid").replaceChildren(emptyState("Pipedream unavailable", error.message));
    $("pipedream-accounts").replaceChildren(emptyState("Pipedream unavailable", "Connected accounts could not be loaded."));
    setStatusPill($("pipedream-marketplace-state"), "Unavailable", "bad");
  }
}

async function loadPipedreamActions(appSlug) {
  appState.selectedPipedreamApp = appSlug;
  renderPipedreamMarketplace();
  $("pipedream-actions").replaceChildren(emptyState("Loading actions", appSlug));
  const result = await request(`/api/integrations/pipedream/apps/${encodeURIComponent(appSlug)}/actions`);
  appState.pipedreamActions = result.actions ?? [];
  renderPipedreamActions(appSlug, appState.pipedreamActions);
}

async function loadPolicyEditor() {
  const policy = await request("/api/policy");
  appState.policy = policy;
  $("policy-editor").value = JSON.stringify(policy, null, 2);
  renderPolicyStructured(policy);
  renderPolicyFilteredRows(policy);
  renderPipedreamApps(policy, appState.roles);
  renderSetupChecklist();
  return policy;
}

async function savePolicyDocument(policy) {
  const result = await request("/api/policies", {
    method: "POST",
    body: JSON.stringify(normalizePolicy(policy)),
  });
  appState.policy = result.policy;
  $("policy-editor").value = JSON.stringify(result.policy, null, 2);
  renderPolicyStructured(result.policy);
  renderPipedreamApps(result.policy, appState.roles);
  renderPolicyFilteredRows(result.policy);
  renderSetupChecklist();
  return result;
}

function policyWithPipedreamRule(policy, slug, updates) {
  const current = normalizedPipedreamRule(policy, slug);
  const nextRule = {
    ...current,
    ...updates,
    tool: pipedreamTool(slug),
    action: "*",
    slackUserIds: updates.slackUserIds ?? current.slackUserIds ?? [],
    roleNames: updates.roleNames ?? current.roleNames ?? [],
  };
  return {
    ...normalizePolicy(policy),
    toolPolicies: [
      ...(policy.toolPolicies ?? []).filter((row) => !(row.tool === nextRule.tool && row.action === "*")),
      nextRule,
    ],
  };
}

async function savePipedreamRule(slug, updates) {
  const policy = appState.policy ?? await request("/api/policy");
  return savePolicyDocument(policyWithPipedreamRule(policy, slug, updates));
}

async function showPipedreamRawRows(slug) {
  activePolicyFilterTool = pipedreamTool(slug);
  const policy = await loadPolicyEditor();
  renderPolicyFilteredRows(policy, activePolicyFilterTool);
  const form = $("policy-form");
  if (form) {
    form.elements.tool.value = activePolicyFilterTool;
    form.elements.action.value = "*";
    form.elements.resource.value = "tool";
  }
  $("policy-preview-section").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderOperationResult(targetId, title, result) {
  const target = $(targetId);
  const summary = [];
  if (result.ok !== undefined) summary.push(["Result", result.ok ? "ok" : "not ok", result.ok ? "ok" : "bad"]);
  if (result.id) summary.push(["Record ID", shortId(result.id, 10), "ok"]);
  if (result.status) summary.push(["Status", result.status, result.status === "complete" || result.status === "approved" ? "ok" : "pending"]);
  if (result.checksum) summary.push(["Checksum", shortId(result.checksum, 12), "ok"]);
  if (result.exitCode !== undefined) summary.push(["Exit code", String(result.exitCode), result.exitCode === 0 ? "ok" : "bad"]);
  if (result.timedOut !== undefined) summary.push(["Timed out", result.timedOut ? "yes" : "no", result.timedOut ? "bad" : "ok"]);

  const children = [el("strong", { textContent: title })];
  if (summary.length) {
    children.push(el("div", { className: "diagnostic-grid" }, summary.map(([label, value, tone]) => el("div", {}, [
      el("span", { textContent: label }),
      statusPill(value, tone),
    ]))));
  }
  children.push(jsonBlock(result));
  target.replaceChildren(...children);
}

function confirmAction({ title, detail, summary, acceptLabel = "Confirm", danger = true }) {
  const modal = $("confirm-modal");
  $("confirm-title").textContent = title;
  $("confirm-detail").textContent = detail;
  $("confirm-summary").textContent = summary || "";
  $("confirm-accept").textContent = acceptLabel;
  $("confirm-accept").className = danger ? "danger-button" : "";
  modal.showModal();
  return new Promise((resolve) => {
    confirmResolve = resolve;
  });
}

function closeConfirm(value) {
  const modal = $("confirm-modal");
  if (modal.open) modal.close();
  if (confirmResolve) confirmResolve(value);
  confirmResolve = null;
}

async function loadSummary() {
  const savedSlackUserId = localStorage.getItem("operant.adminSlackUserId");
  const sessionToken = localStorage.getItem("operant.sessionToken");
  $("session-state").textContent = sessionToken && savedSlackUserId ? `${savedSlackUserId} signed in` : "Not signed in";

  let summary;
  try {
    summary = await request("/api/summary");
  } catch (error) {
    if (error.status === 401) {
      $("workspace").textContent = "Sign in to view workspace.";
      renderSignedOut();
      renderSetupChecklist();
      return;
    }
    throw error;
  }

  appState.summary = summary;
  $("workspace").textContent = `${summary.companyName} / ${summary.workspaceName}`;
  $("credentials").textContent = number(summary.counts.credentials);
  $("channels").textContent = number(summary.counts.channels);
  $("sessions").textContent = number(summary.counts.sessions);
  $("usage").textContent = number(summary.counts.usage_events);
  $("approvals").textContent = number(summary.counts.pending_approvals);
  $("audit").textContent = number(summary.counts.audit_events);
  renderConfigSummary(summary);

  if (!sessionToken) {
    renderSignedOut();
    renderSetupChecklist();
    return;
  }

  try {
    appState.settings = await request("/api/settings");
    const settings = appState.settings;
    const form = $("settings-form");
    if (form) {
      form.elements.companyName.value = settings.companyName || "";
      form.elements.workspaceName.value = settings.workspaceName || "";
      form.elements.slackTeamId.value = settings.slackTeamId || "";
      form.elements.openclawGatewayUrl.value = settings.openclawGatewayUrl || "";
      form.elements.modelProvider.value = settings.modelProvider || "";
      form.elements.modelName.value = settings.modelName || "";
      form.elements.retentionDays.value = settings.retentionDays || "";
    }
    const credForm = $("credentials-form");
    if (credForm) {
      credForm.elements.companyName.value = settings.companyName || "";
      credForm.elements.workspaceName.value = settings.workspaceName || "";
      credForm.elements.modelProvider.value = settings.modelProvider || "openai";
      credForm.elements.modelName.value = settings.modelName || "";
      if (savedSlackUserId) credForm.elements.adminSlackUserId.value = savedSlackUserId;
    }
    renderOperationResult("settings-result", "Current settings", settings);
  } catch {
    $("settings-result").textContent = "Sign in to view settings.";
  }

  try {
    appState.policy = await request("/api/policy");
    $("policy-editor").value = JSON.stringify(appState.policy, null, 2);
    const credForm = $("credentials-form");
    if (credForm) {
      credForm.elements.allowedDmUserIds.value = (appState.policy.allowedDmUserIds ?? []).join(", ");
      credForm.elements.allowedChannelIds.value = (appState.policy.channelPolicies ?? []).map((c) => c.channelId).join(", ");
      credForm.elements.approvalSlackUserIds.value = Array.from(new Set((appState.policy.approvalPolicies ?? []).flatMap((p) => p.approverSlackUserIds ?? []))).join(", ");
    }
    renderPolicyStructured(appState.policy);
    renderPolicyFilteredRows(appState.policy);
  } catch {
    appState.policy = null;
  }

  try {
    const diagnostics = await request("/api/pipedream/diagnostics");
    renderPipedreamDiagnostics(diagnostics);
  } catch {
    $("pipedream-diagnostics").textContent = "Unable to load Pipedream diagnostics.";
  }

  try {
    appState.usageSummary = await request("/api/usage/summary");
    renderUsageSummary(appState.usageSummary);
  } catch {
    $("usage-summary").replaceChildren(emptyState("Sign in required", "Usage totals are available to authorized users."));
  }

  try {
    const usageEvents = await request("/api/usage");
    appState.usageEvents = usageEvents.items ?? [];
    renderUsageEvents(appState.usageEvents);
  } catch {
    $("usage-events").replaceChildren(emptyState("Sign in required", "Usage events are hidden until sign-in."));
  }

  try {
    const [sessions, jobs] = await Promise.all([
      request("/api/sessions"),
      request("/api/jobs"),
    ]);
    appState.sessions = sessions.items ?? [];
    appState.jobs = jobs.items ?? [];
    renderActivity(appState.sessions, appState.jobs);
  } catch {
    $("activity-result").replaceChildren(emptyState("Sign in required", "Sessions and jobs are hidden until sign-in."));
  }

  try {
    const audit = await request("/api/audit");
    appState.audit = audit.items ?? [];
    renderAudit(appState.audit);
  } catch {
    $("audit-log").replaceChildren(emptyState("Sign in required", "Audit rows are hidden until sign-in."));
  }

  try {
    const approvals = await request("/api/approvals");
    appState.approvals = approvals.items ?? [];
    renderApprovals(appState.approvals);
  } catch {
    $("approvals-result").replaceChildren(emptyState("Sign in required", "Approvals are hidden until sign-in."));
  }

  try {
    const users = await request("/api/users");
    appState.users = users.users ?? [];
    renderUsers(appState.users);
  } catch {
    $("users-result").replaceChildren(emptyState("Sign in required", "Users are hidden until sign-in."));
  }

  try {
    const roles = await request("/api/roles");
    appState.roles = roles.roles ?? [];
    renderRoles(appState.roles);
    renderPipedreamApps(appState.policy, appState.roles);
  } catch {
    appState.roles = [];
    $("roles-result").replaceChildren(emptyState("Sign in required", "Roles are hidden until sign-in."));
    renderPipedreamApps(appState.policy, appState.roles);
  }

  await loadPipedreamMarketplace().catch(() => {});

  try {
    const credentials = await request("/api/integrations/credentials");
    appState.credentials = credentials.credentials ?? [];
    renderCredentials(appState.credentials);
  } catch {
    appState.credentials = [];
    $("integration-credentials-result").replaceChildren(emptyState("Sign in required", "Credential metadata is hidden until sign-in."));
  }

  renderSetupChecklist();
  validateCredentialInputs();
}

function validateCredentialInputs() {
  const form = $("credentials-form");
  if (!form) return;
  const checks = [
    [form.elements.slackBotToken, (value) => !value || value.startsWith("xoxb-")],
    [form.elements.slackAppToken, (value) => !value || value.startsWith("xapp-")],
    [form.elements.modelApiKey, (value) => !value || value.length >= 8],
    [form.elements.adminSlackUserId, (value) => !value || /^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(value)],
  ];
  let invalid = 0;
  for (const [input, validator] of checks) {
    const ok = validator(input.value.trim());
    input.dataset.valid = String(ok);
    if (!ok) invalid += 1;
  }
  setStatusPill($("credential-validation-state"), invalid ? `${invalid} field issue${invalid === 1 ? "" : "s"}` : "Fields valid", invalid ? "bad" : "ok");
}

function switchView(targetId) {
  for (const view of document.querySelectorAll(".view")) view.classList.toggle("active", view.id === targetId);
  for (const tab of document.querySelectorAll(".nav-tab")) tab.classList.toggle("active", tab.dataset.viewTarget === targetId);
  window.scrollTo({ top: 0, behavior: "smooth" });
}

for (const tab of document.querySelectorAll(".nav-tab")) {
  tab.addEventListener("click", () => switchView(tab.dataset.viewTarget));
}

for (const input of $("credentials-form").querySelectorAll("input, select")) {
  input.addEventListener("input", validateCredentialInputs);
}

$("confirm-cancel").addEventListener("click", () => closeConfirm(false));
$("confirm-accept").addEventListener("click", () => closeConfirm(true));
$("confirm-modal").addEventListener("cancel", (event) => {
  event.preventDefault();
  closeConfirm(false);
});

$("refresh").addEventListener("click", () => loadSummary().catch((error) => toast(error.message)));
$("refresh-integrations").addEventListener("click", () => loadPipedreamMarketplace($("pipedream-search-form").elements.q.value.trim()).catch((error) => toast(error.message)));

$("pipedream-search-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  await loadPipedreamMarketplace(String(form.get("q") || "").trim());
});

$("pipedream-marketplace-grid").addEventListener("click", async (event) => {
  const card = event.target.closest(".marketplace-card");
  if (!card) return;
  const slug = card.dataset.app;
  try {
    if (event.target.closest(".pipedream-connect")) {
      const result = await request("/api/integrations/pipedream/connect-token", {
        method: "POST",
        body: JSON.stringify({ appSlug: slug }),
      });
      window.open(result.connectLinkUrl, "_blank", "noopener");
      renderOperationResult("pipedream-result", `${slug} connect link`, {
        ok: true,
        app: slug,
        expiresAt: result.expiresAt,
        connectLinkUrl: result.connectLinkUrl,
      });
      toast(`${slug} connect link opened`);
      return;
    }
    if (event.target.closest(".pipedream-preview") || card) {
      await loadPipedreamActions(slug);
    }
  } catch (error) {
    toast(error.message);
  }
});

$("pipedream-accounts").addEventListener("click", async (event) => {
  const button = event.target.closest(".pipedream-disconnect");
  if (!button) return;
  const accountId = button.dataset.accountId;
  const ok = await confirmAction({
    title: "Disconnect Pipedream account",
    detail: "The account will be revoked in Pipedream and can be reconnected later.",
    summary: accountId,
    acceptLabel: "Disconnect",
  });
  if (!ok) return;
  try {
    const result = await request(`/api/integrations/pipedream/accounts/${encodeURIComponent(accountId)}`, { method: "DELETE" });
    renderOperationResult("pipedream-result", "Pipedream account disconnected", result);
    await loadPipedreamMarketplace($("pipedream-search-form").elements.q.value.trim());
  } catch (error) {
    toast(error.message);
  }
});

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    await login(String(form.get("slackUserId") || ""), String(form.get("adminLoginToken") || ""));
    toast("Signed in");
    await loadSummary();
  } catch (error) {
    if (error.code === "bootstrap_required") {
      const hint = "First-time setup: complete Credential Setup with your Slack user ID and admin login token to create the workspace owner.";
      toast(hint);
      $("login-result").textContent = hint;
      $("credentials-form").scrollIntoView({ behavior: "smooth", block: "start" });
      $("credentials-form").elements.adminSlackUserId.focus();
      return;
    }
    toast(error.message);
  }
});

$("logout").addEventListener("click", async () => {
  try {
    await request("/api/auth/logout", { method: "POST", body: "{}" });
  } catch {
    // Continue with local logout even if the server session is already gone.
  }
  localStorage.removeItem("operant.sessionToken");
  $("session-state").textContent = "Not signed in";
  toast("Signed out");
  await loadSummary().catch(() => renderSignedOut());
});

$("credentials-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const credentialsForm = event.currentTarget;
  validateCredentialInputs();
  const form = new FormData(credentialsForm);
  const payload = Object.fromEntries(form.entries());
  if (payload.adminSlackUserId) localStorage.setItem("operant.adminSlackUserId", payload.adminSlackUserId);
  if (!payload.adminLoginToken) delete payload.adminLoginToken;
  payload.allowedDmUserIds = splitIds(payload.allowedDmUserIds);
  payload.allowedChannelIds = splitIds(payload.allowedChannelIds);
  payload.approvalSlackUserIds = splitIds(payload.approvalSlackUserIds);
  if (payload.adminSlackUserId) {
    payload.allowedDmUserIds = Array.from(new Set([payload.adminSlackUserId, ...payload.allowedDmUserIds]));
    payload.approvalSlackUserIds = Array.from(new Set([payload.adminSlackUserId, ...payload.approvalSlackUserIds]));
  }
  for (const key of ["slackBotToken", "slackAppToken", "modelApiKey", "adminLoginToken"]) {
    if (!payload[key]) delete payload[key];
  }
  try {
    const result = await request("/api/config/credentials", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (payload.adminSlackUserId && payload.adminLoginToken) await login(payload.adminSlackUserId, payload.adminLoginToken);
    credentialsForm.elements.slackBotToken.value = "";
    credentialsForm.elements.slackAppToken.value = "";
    credentialsForm.elements.modelApiKey.value = "";
    credentialsForm.elements.adminLoginToken.value = "";
    toast(`Config generated: ${result.checksum.slice(0, 12)}`);
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = Object.fromEntries(form.entries());
  payload.roles = form.getAll("roles").map((value) => String(value)).filter((value) => value.length > 0);
  if (!payload.email) delete payload.email;
  if (!payload.name) delete payload.name;
  try {
    const result = await request("/api/users", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    toast(`Saved ${result.user.slack_user_id}`);
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("role-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    const payload = {
      name: String(form.get("name") || ""),
      permissions: parsePermissionPairs(form.get("permissions")),
    };
    const result = await request("/api/roles", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    toast(`Role saved: ${result.role.name}`);
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("integration-credential-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const integrationForm = event.currentTarget;
  const form = new FormData(integrationForm);
  const payload = Object.fromEntries(form.entries());
  if (!payload.label) delete payload.label;
  if (!payload.slackUserId) delete payload.slackUserId;
  try {
    const result = await request("/api/integrations/credentials", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    integrationForm.reset();
    renderOperationResult("data-result", "Integration credential saved", { credential: result.credential, ok: true });
    toast("Integration secret saved as masked metadata");
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("generate-config").addEventListener("click", async () => {
  const ok = await confirmAction({
    title: "Regenerate OpenClaw config",
    detail: "This writes a new SecretRef-backed config file and records an audit event.",
    summary: "Plaintext credentials remain encrypted in Operant; the generated config should contain only SecretRefs.",
    acceptLabel: "Regenerate Config",
    danger: false,
  });
  if (!ok) return;
  try {
    const result = await request("/api/openclaw/config", { method: "POST", body: "{}" });
    renderOperationResult("openclaw-result", "OpenClaw config generated", result);
    toast(`OpenClaw config generated: ${result.checksum.slice(0, 12)}`);
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("sync-openclaw").addEventListener("click", async () => {
  const ok = await confirmAction({
    title: "Sync OpenClaw activity",
    detail: "This runs OpenClaw observation commands and imports sessions, jobs, tasks, and usage snapshots.",
    summary: "The sync writes audit evidence and skips oversized usage/cost values before persistence.",
    acceptLabel: "Sync Activity",
    danger: false,
  });
  if (!ok) return;
  try {
    const result = await request("/api/openclaw/observations/sync", { method: "POST", body: "{}" });
    renderOperationResult("openclaw-result", "OpenClaw activity synced", result);
    toast(`Synced ${result.synced.sessionsUpserted} sessions`);
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = Object.fromEntries(form.entries());
  if (payload.retentionDays) payload.retentionDays = Number(payload.retentionDays);
  for (const key of Object.keys(payload)) {
    if (payload[key] === "") delete payload[key];
  }
  try {
    const result = await request("/api/settings", {
      method: "PUT",
      body: JSON.stringify(payload),
    });
    renderOperationResult("settings-result", "Settings saved", result.settings);
    toast("Settings saved");
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("retention-purge").addEventListener("click", async () => {
  const ok = await confirmAction({
    title: "Apply retention",
    detail: "This permanently deletes operational records older than the configured retention window.",
    summary: `Current retention window: ${appState.settings?.retentionDays ?? "unknown"} days.`,
    acceptLabel: "Apply Retention",
  });
  if (!ok) return;
  try {
    const result = await request("/api/retention/purge", { method: "POST", body: "{}" });
    renderOperationResult("data-result", "Retention applied", result);
    toast(`Retention applied: ${Object.values(result.deleted).reduce((sum, value) => sum + value, 0)} rows`);
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("queue-export").addEventListener("click", async () => {
  const ok = await confirmAction({
    title: "Create export",
    detail: "This creates a completed export snapshot in the current test or customer database.",
    summary: "Credential exports include metadata only; plaintext and encrypted secret values are excluded.",
    acceptLabel: "Create Export",
    danger: false,
  });
  if (!ok) return;
  try {
    const result = await request("/api/export", { method: "POST", body: "{}" });
    renderOperationResult("data-result", "Export created", {
      id: result.id,
      status: result.status,
      counts: result.payload?.counts,
      ok: true,
    });
    toast("Export created");
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("queue-wipe").addEventListener("click", async () => {
  const scope = $("wipe-scope").value;
  const ok = await confirmAction({
    title: `Run ${scope} wipe`,
    detail: "This permanently removes data in the selected scope and writes a wipe audit event.",
    summary: scope === "workspace" ? "Workspace wipe also revokes dashboard admin sessions." : `Selected scope: ${scope}.`,
    acceptLabel: "Run Wipe",
  });
  if (!ok) return;
  try {
    const result = await request("/api/wipe", { method: "POST", body: JSON.stringify({ scope }) });
    renderOperationResult("data-result", `${scope} wipe completed`, result);
    toast(`${scope} wipe completed`);
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("load-policy").addEventListener("click", async () => {
  try {
    await loadPolicyEditor();
    toast("Policy loaded");
  } catch (error) {
    toast(error.message);
  }
});

$("save-policy").addEventListener("click", async () => {
  try {
    const result = await request("/api/policy", {
      method: "PUT",
      body: $("policy-editor").value,
    });
    appState.policy = result.policy;
    $("policy-editor").value = JSON.stringify(result.policy, null, 2);
    renderPolicyStructured(result.policy);
    renderPipedreamApps(result.policy, appState.roles);
    renderPolicyFilteredRows(result.policy);
    toast(`Policy saved: ${result.config.checksum.slice(0, 12)}`);
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("policy-channel-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const current = normalizePolicy(appState.policy ?? await request("/api/policy"));
  const channelId = String(form.get("channelId") || "");
  const rule = {
    channelId,
    name: String(form.get("name") || "") || null,
    enabled: Boolean(form.get("enabled")),
    requireMention: Boolean(form.get("requireMention")),
    allowedUserIds: splitIds(form.get("allowedUserIds")),
    deniedUserIds: splitIds(form.get("deniedUserIds")),
  };
  try {
    const result = await savePolicyDocument({
      ...current,
      channelPolicies: [...current.channelPolicies.filter((item) => item.channelId !== channelId), rule],
    });
    toast(`Channel policy saved: ${result.config.checksum.slice(0, 12)}`);
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("policy-tool-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const current = normalizePolicy(appState.policy ?? await request("/api/policy"));
  const rule = {
    tool: String(form.get("tool") || ""),
    action: String(form.get("action") || "*"),
    effect: String(form.get("effect") || "allow"),
    slackUserIds: splitIds(form.get("slackUserIds")),
    roleNames: splitIds(form.get("roleNames")),
  };
  try {
    const result = await savePolicyDocument({
      ...current,
      toolPolicies: [
        ...current.toolPolicies.filter((item) =>
          !(item.tool === rule.tool && item.action === rule.action && (item.slackUserIds ?? []).length === 0 && (item.roleNames ?? []).length === 0),
        ),
        rule,
      ],
    });
    toast(`Tool policy saved: ${result.config.checksum.slice(0, 12)}`);
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("policy-approval-rule-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const current = normalizePolicy(appState.policy ?? await request("/api/policy"));
  const name = String(form.get("name") || "");
  const rule = {
    name,
    actionPattern: String(form.get("actionPattern") || ""),
    resourcePattern: String(form.get("resourcePattern") || "*"),
    approverSlackUserIds: splitIds(form.get("approverSlackUserIds")),
    minApprovals: Number(form.get("minApprovals") || 1),
    enabled: Boolean(form.get("enabled")),
  };
  try {
    const result = await savePolicyDocument({
      ...current,
      approvalPolicies: [...current.approvalPolicies.filter((item) => item.name !== name), rule],
    });
    toast(`Approval policy saved: ${result.config.checksum.slice(0, 12)}`);
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("pipedream-apps-grid").addEventListener("change", async (event) => {
  const card = event.target.closest(".pipedream-card");
  if (!card) return;
  const slug = card.dataset.app;
  const mode = card.querySelector(".pipedream-mode");
  const roleSelect = card.querySelector(".pipedream-roles");
  const toggle = card.querySelector(".pipedream-toggle");
  const roles = selectedValues(roleSelect);
  let effect = mode.value;
  if (event.target.classList.contains("pipedream-toggle")) {
    effect = toggle.checked ? (mode.value === "deny" ? "allow" : mode.value) : "deny";
  }
  try {
    await savePipedreamRule(slug, { effect, roleNames: roles });
    toast(`${pipedreamTool(slug)} policy saved`);
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("pipedream-apps-grid").addEventListener("click", async (event) => {
  const button = event.target.closest(".pipedream-raw");
  if (!button) return;
  const card = button.closest(".pipedream-card");
  if (!card) return;
  try {
    await showPipedreamRawRows(card.dataset.app);
  } catch (error) {
    toast(error.message);
  }
});

$("policy-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = Object.fromEntries(form.entries());
  for (const key of ["slackChannelId", "tool", "action", "resource"]) {
    if (!payload[key]) delete payload[key];
  }
  try {
    const result = await request("/api/policy/evaluate", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    $("policy-result").replaceChildren(
      el("div", { className: "summary-row" }, [
        el("span", { textContent: "Decision" }),
        statusPill(result.effect, result.effect === "allow" ? "ok" : result.effect === "deny" ? "bad" : "pending"),
      ]),
      jsonBlock(result),
    );
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("approval-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = Object.fromEntries(form.entries());
  try {
    const result = await request("/api/approvals", {
      method: "POST",
      body: JSON.stringify({
        action: payload.action,
        resource: payload.resource,
        payload: { reason: payload.reason || "" },
      }),
    });
    renderOperationResult("approval-result", "Approval requested", result);
    toast("Approval requested");
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

$("approvals-result").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-approval-id]");
  if (!button) return;
  try {
    const result = await request(`/api/approvals/${button.dataset.approvalId}/decision`, {
      method: "POST",
      body: JSON.stringify({ status: button.dataset.status }),
    });
    renderOperationResult("approval-result", `Approval ${button.dataset.status}`, result);
    toast(`Approval ${button.dataset.status}`);
    await loadSummary();
  } catch (error) {
    toast(error.message);
  }
});

for (const button of document.querySelectorAll(".openclaw-check")) {
  button.addEventListener("click", async () => {
    const ok = await confirmAction({
      title: `Run OpenClaw ${button.dataset.check}`,
      detail: "This runs the configured OpenClaw check wrapper from the control plane and records an audit row.",
      summary: "Use these checks before live Slack acceptance, and inspect failures before rerunning.",
      acceptLabel: "Run Check",
      danger: false,
    });
    if (!ok) return;
    try {
      const result = await request(`/api/openclaw/checks/${button.dataset.check}`, {
        method: "POST",
        body: "{}",
      });
      renderOperationResult("openclaw-result", `OpenClaw ${button.dataset.check}`, result.json || result);
      await loadSummary();
    } catch (error) {
      toast(error.message);
    }
  });
}

loadSummary().catch((error) => toast(error.message));
