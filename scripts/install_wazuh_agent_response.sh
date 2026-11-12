#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
WAZUH_HOME="${WAZUH_AGENT_HOME:-/var/ossec}"
BIN_DIR="$WAZUH_HOME/active-response/bin"
SERVICE_FILE="/etc/systemd/system/satark-response-watchdog.service"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root on an authorized disposable Linux Wazuh agent." >&2
  exit 1
fi
if [ ! -d "$WAZUH_HOME" ] || [ ! -x "$WAZUH_HOME/bin/wazuh-control" ]; then
  echo "Wazuh agent installation not found at $WAZUH_HOME." >&2
  exit 1
fi
if ! id wazuh >/dev/null 2>&1; then
  echo "Expected Wazuh service account 'wazuh' was not found." >&2
  exit 1
fi
if ! command -v iptables >/dev/null 2>&1; then
  echo "iptables is required for this Linux-only response." >&2
  exit 1
fi
if [ ! -x /usr/bin/python3 ]; then
  echo "/usr/bin/python3 is required." >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd is required for the persistent TTL watchdog." >&2
  exit 1
fi

install -d -o root -g wazuh -m 0750 "$BIN_DIR"
install -o root -g wazuh -m 0640 "$ROOT/integrations/wazuh_agent/satark_response_state.py" "$BIN_DIR/satark_response_state.py"
install -o root -g wazuh -m 0750 "$ROOT/integrations/wazuh_agent/satark-firewall-drop" "$BIN_DIR/satark-firewall-drop"
install -o root -g wazuh -m 0750 "$ROOT/integrations/wazuh_agent/satark-response-watchdog.py" "$BIN_DIR/satark-response-watchdog.py"

install -d -o root -g root -m 0700 /var/lib/satark-response
install -o root -g root -m 0644 "$ROOT/integrations/wazuh_agent/satark-response-watchdog.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable --now satark-response-watchdog.service
systemctl is-active --quiet satark-response-watchdog.service

echo "SATARK TTL watchdog installed and active on this Linux lab agent."
echo "Live response must remain disabled until the lab verifies add, expiry, reversal and reboot recovery."
