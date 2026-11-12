#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
WAZUH_HOME="${WAZUH_MANAGER_HOME:-/var/ossec}"
CONFIG="$WAZUH_HOME/etc/ossec.conf"
SNIPPET="$ROOT/integrations/wazuh_manager/satark-firewall-drop.xml"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root on an authorized disposable Wazuh Manager." >&2
  exit 1
fi
if [ "${SATARK_WAZUH_LAB_CONFIRM:-}" != "I_HAVE_AUTHORIZED_THIS_DISPOSABLE_LAB" ]; then
  echo "Set SATARK_WAZUH_LAB_CONFIRM=I_HAVE_AUTHORIZED_THIS_DISPOSABLE_LAB to modify this Manager." >&2
  exit 1
fi
if [ ! -f "$CONFIG" ] || [ ! -f "$SNIPPET" ]; then
  echo "Wazuh Manager configuration or SATARK command definition is missing." >&2
  exit 1
fi

python3 - "$CONFIG" "$SNIPPET" <<'PY'
import pathlib
import sys
import xml.etree.ElementTree as ET

config = pathlib.Path(sys.argv[1])
snippet = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
text = config.read_text(encoding="utf-8")
if "<name>satark-firewall-drop</name>" in text:
    ET.fromstring(text)
    print("SATARK command is already present; no duplicate added.")
    raise SystemExit(0)
closing = "</ossec_config>"
index = text.rfind(closing)
if index < 0:
    raise SystemExit("Could not find the closing ossec_config element.")
updated = text[:index] + "\n  " + snippet.strip().replace("\n", "\n  ") + "\n" + text[index:]
ET.fromstring(updated)
backup = config.with_suffix(config.suffix + ".satark-backup")
if not backup.exists():
    backup.write_text(text, encoding="utf-8")
config.write_text(updated, encoding="utf-8")
print(f"Installed SATARK command definition; backup saved to {backup}.")
PY

if [ "${SATARK_WAZUH_RESTART_MANAGER:-false}" = "true" ]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart wazuh-manager
    systemctl is-active --quiet wazuh-manager
  else
    "$WAZUH_HOME/bin/wazuh-control" restart
  fi
else
  echo "Configuration written but Manager not restarted."
  echo "After reviewing the diff, restart wazuh-manager during the authorized lab maintenance window."
fi
