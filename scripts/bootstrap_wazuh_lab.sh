#!/usr/bin/env bash
set -euo pipefail

VERSION="${WAZUH_DOCKER_VERSION:-v4.14.10}"
DEST="${1:-$HOME/wazuh-docker}"
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "Docker Engine and the Docker Compose plugin are required." >&2
  exit 2
fi
if ! command -v git >/dev/null 2>&1; then
  echo "git is required." >&2
  exit 2
fi
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
docker compose -f generate-indexer-certs.yml run --rm generator
cat <<EOF

Wazuh $VERSION lab files and TLS certificates are prepared at:
  $DEST/single-node

Before starting the stack:
  1. Review the upstream Wazuh Docker security/password instructions.
  2. Replace every default password and rotate the manager API credentials.
  3. Keep ports 55000, 9200 and 443 on a private lab network only.
  4. Enroll disposable test agents and record their numeric IDs.
  5. Configure FIRSTLIGHT_WAZUH_MANAGER_API_URL, USERNAME, PASSWORD,
     MANAGER_CA_BUNDLE and RESPONSE_AGENT_IDS in SATARK's private .env.
  6. Confirm the manager certificate SAN matches the URL used by SATARK.

Then start the lab from this directory:
  docker compose up -d

This script prepares a lab; it does not expose services publicly or enable
SATARK live response. SATARK live response remains disabled by default.
EOF
