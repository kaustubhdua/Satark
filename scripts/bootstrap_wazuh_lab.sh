#!/usr/bin/env bash
set -euo pipefail

VERSION="v4.14.10"
DEST="${1:-$HOME/wazuh-docker}"
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "Docker Engine and the Docker Compose plugin are required." >&2
  exit 2
fi
if ! command -v git >/dev/null 2>&1; then
  echo "git is required." >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required to validate the lab bind address." >&2
  exit 2
fi
BIND_ADDRESS="${WAZUH_LAB_BIND_ADDRESS:-127.0.0.1}"
DEST="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$DEST")"
python3 - "$BIND_ADDRESS" <<'PY'
import ipaddress
import sys
address = ipaddress.ip_address(sys.argv[1])
if not isinstance(address, ipaddress.IPv4Address) or not (address.is_loopback or address.is_private):
    raise SystemExit("WAZUH_LAB_BIND_ADDRESS must be a loopback or private IPv4 address.")
PY
MAP_COUNT="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
if [ "$MAP_COUNT" -lt 262144 ]; then
  echo "Wazuh Indexer requires vm.max_map_count >= 262144 (current: $MAP_COUNT)." >&2
  echo "On Linux, run: sudo sysctl -w vm.max_map_count=262144" >&2
  exit 2
fi
if [ -e "$DEST" ]; then
  echo "Refusing to overwrite existing path: $DEST" >&2
  exit 2
fi
git clone --depth 1 --branch "$VERSION" https://github.com/wazuh/wazuh-docker.git "$DEST"
cd "$DEST/single-node"
COMPOSE_FILE="docker-compose.yml"
sed -i \
  -e "s|\"1514:1514\"|\"$BIND_ADDRESS:1514:1514\"|" \
  -e "s|\"1515:1515\"|\"$BIND_ADDRESS:1515:1515\"|" \
  -e "s|\"514:514/udp\"|\"$BIND_ADDRESS:514:514/udp\"|" \
  -e "s|\"55000:55000\"|\"$BIND_ADDRESS:55000:55000\"|" \
  -e "s|\"9200:9200\"|\"$BIND_ADDRESS:9200:9200\"|" \
  -e "s|443:5601|$BIND_ADDRESS:8443:5601|" "$COMPOSE_FILE"
docker compose -f generate-indexer-certs.yml run --rm generator

# Prepare one disposable Linux agent container using the official Wazuh agent
# image. Host networking lets it reach the manager's loopback/private bind;
# it monitors only its own container filesystem, never the host.
mkdir -p "$DEST/wazuh-agent/config" "$DEST/wazuh-agent/events/fim"
touch "$DEST/wazuh-agent/events/auth.log"
chmod 700 "$DEST/wazuh-agent/events" "$DEST/wazuh-agent/events/fim"
chmod 600 "$DEST/wazuh-agent/events/auth.log"
cat > "$DEST/wazuh-agent/config/satark-lab-ossec.conf" <<AGENTCONF
<ossec_config>
  <client>
    <server>
      <address>$BIND_ADDRESS</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>
  <syscheck>
    <disabled>no</disabled>
    <frequency>30</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories check_all="yes" realtime="yes">/tmp/satark-lab/fim</directories>
  </syscheck>
  <localfile>
    <log_format>syslog</log_format>
    <location>/tmp/satark-lab/auth.log</location>
  </localfile>
</ossec_config>
AGENTCONF
cat > "$DEST/wazuh-agent/docker-compose.satark-lab.yml" <<'AGENTCOMPOSE'
services:
  wazuh.agent:
    image: wazuh/wazuh-agent:4.14.10
    hostname: satark-lab-agent
    restart: unless-stopped
    network_mode: ${WAZUH_LAB_AGENT_NETWORK_MODE:-host}
    cap_add:
      - NET_ADMIN
    environment:
      - WAZUH_MANAGER_SERVER=$BIND_ADDRESS
      - WAZUH_MANAGER_PORT=1514
      - WAZUH_AGENT_NAME=satark-lab-agent
    volumes:
      - ./config/satark-lab-ossec.conf:/wazuh-config-mount/etc/ossec.conf:ro
      - satark_lab_agent_data:/var/ossec/data
      - satark_lab_agent_logs:/var/ossec/logs
      - ./events:/tmp/satark-lab
volumes:
  satark_lab_agent_data:
  satark_lab_agent_logs:
AGENTCOMPOSE
chmod 600 "$DEST/wazuh-agent/config/satark-lab-ossec.conf" "$DEST/wazuh-agent/docker-compose.satark-lab.yml"
cat <<EOF

Wazuh $VERSION lab files and TLS certificates are prepared at:
  $DEST/single-node

Before starting the stack:
  1. Review the upstream Wazuh Docker security/password instructions.
  2. Replace every default password and rotate the manager API credentials.
  3. Ports are bound to $BIND_ADDRESS (loopback by default); use only a private lab IPv4 address for remote disposable agents. The dashboard is exposed locally on port 8443.

Start the central Manager, Indexer and Dashboard first:
  cd "$DEST/single-node"
  docker compose up -d

Then start the prepared disposable Linux agent (it monitors only its own container):
  cd "$DEST/wazuh-agent"
  WAZUH_MANAGER_SERVER="$BIND_ADDRESS" docker compose -f docker-compose.satark-lab.yml up -d
Wait for it to appear as Active in the Wazuh Dashboard and record its numeric ID.

Generate synthetic events inside the agent container:
  docker compose -f docker-compose.satark-lab.yml exec wazuh.agent sh -lc 'touch /tmp/satark-lab/fim/marker.txt; printf "<14>%s satark-lab-agent sshd: Failed password for invalid user satark-lab from 198.51.100.23 port 2222 ssh2\n" "$(date "+%b %d %H:%M:%S")" >> /tmp/satark-lab/auth.log'
Verify actual alerts in the Indexer; do not treat the command itself as proof of ingestion.

Configure FIRSTLIGHT_WAZUH_MANAGER_API_URL, USERNAME, PASSWORD,
MANAGER_CA_BUNDLE and RESPONSE_AGENT_IDS in SATARK's private .env.
Confirm the manager certificate SAN matches the URL used by SATARK.

Local endpoints (when using the default loopback bind):
  Manager API: https://127.0.0.1:55000
  Indexer:     https://127.0.0.1:9200
  Dashboard:   https://127.0.0.1:8443

This script prepares a lab; it does not expose services publicly or enable
SATARK live response. SATARK live response remains disabled by default.
EOF
