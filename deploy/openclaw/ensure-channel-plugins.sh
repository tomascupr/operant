#!/bin/sh
set -eu

state_dir=${OPENCLAW_STATE_DIR:-"$HOME/.openclaw"}

prune_channel_test_harnesses() {
  find "$state_dir" \( -path "*/slack/dist/*test-harness*.js" -o -path "*/msteams/dist/*test-harness*.js" \) -type f -delete 2>/dev/null || true
}

has_plugin() {
  plugin_id=$1
  required_channel=${2:-}
  openclaw plugins list --json | node -e '
const pluginId = process.argv[1];
const requiredChannel = process.argv[2] || "";
let source = "";
process.stdin.on("data", (chunk) => { source += chunk; });
process.stdin.on("end", () => {
  const payload = JSON.parse(source);
  const plugin = (payload.plugins || []).find((item) => item.id === pluginId);
  if (!plugin) process.exit(1);
  if (requiredChannel && !(plugin.channelIds || []).includes(requiredChannel)) process.exit(1);
  process.exit(0);
});
' "$plugin_id" "$required_channel"
}

ensure_plugin() {
  plugin_id=$1
  package_pattern=$2
  failure_message=$3
  required_channel=${4:-}
  fatal=${5:-yes}
  log_file="/tmp/openclaw-${plugin_id}-plugin-install.log"

  if has_plugin "$plugin_id" "$required_channel" >/dev/null 2>&1; then
    return 0
  fi

  if ! openclaw plugins install $package_pattern >"$log_file" 2>&1; then
    # OpenClaw installs the package before trying to update config. Operant mounts
    # generated config read-only, so the install can be usable even when that final
    # config-write step returns EROFS/EACCES.
    :
  fi

  if has_plugin "$plugin_id" "$required_channel" >/dev/null 2>&1; then
    return 0
  fi

  cat "$log_file" >&2
  echo "$failure_message" >&2
  if [ "$fatal" = "no" ]; then
    echo "Continuing without the ${plugin_id} plugin (non-fatal); the gateway will still serve other configured channels." >&2
    return 0
  fi
  exit 1
}

prune_channel_test_harnesses
ensure_plugin "slack" "/usr/local/share/operant/openclaw/plugins/openclaw-slack-*.tgz" "OpenClaw Slack plugin is not installed; the gateway cannot serve Slack channels." "slack"
ensure_plugin "msteams" "/usr/local/share/operant/openclaw/plugins/openclaw-msteams-*.tgz" "OpenClaw Microsoft Teams plugin is not installed; Teams channels will be unavailable (Slack-only stacks can ignore this)." "msteams" "no"
prune_channel_test_harnesses
ensure_plugin "operant" "/usr/local/share/operant/openclaw/plugins/operant-openclaw-plugin-*.tgz" "Operant plugin is not installed; per-user policy and Pipedream tools will not be available in this gateway."
