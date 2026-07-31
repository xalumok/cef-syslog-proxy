#!/bin/sh
# Start ssagent and Vector together.
#
# Order matters. ssagent fetches a bundle first so Vector has something to run. If the
# control plane is unreachable and no cached bundle exists, the node starts with a
# forward-everything config rather than not starting at all: an unconfigured proxy that
# forwards is safe, and one that drops or refuses to start is not.

set -eu

CONFIG_DIR="${SS_CONFIG_DIR:-/etc/vector}"
CONFIG_FILE="${CONFIG_DIR}/vector.toml"
INTERVAL="${SS_AGENT_INTERVAL:-15}"

mkdir -p "${CONFIG_DIR}"

if [ ! -f "${CONFIG_FILE}" ]; then
  echo "no cached bundle; fetching one before starting vector" >&2
  ssagent --once --control-plane-url "${SS_CONTROL_PLANE_URL}" --config-dir "${CONFIG_DIR}" || true
fi

if [ ! -f "${CONFIG_FILE}" ]; then
  echo "still no bundle; starting in forward-everything mode" >&2
  cat > "${CONFIG_FILE}" <<EOF
[sources.ingest]
type = "socket"
mode = "udp"
address = "${SS_LISTEN_ADDRESS:-0.0.0.0:5514}"
max_length = 65536

[sinks.elk]
type = "socket"
mode = "udp"
inputs = ["ingest"]
address = "${SS_ELK_ADDRESS:-127.0.0.1:5140}"
encoding.codec = "text"
EOF
fi

vector --config "${CONFIG_FILE}" --watch-config &
VECTOR_PID=$!
echo "${VECTOR_PID}" > "${CONFIG_DIR}/vector.pid"

ssagent \
  --control-plane-url "${SS_CONTROL_PLANE_URL}" \
  --config-dir "${CONFIG_DIR}" \
  --vector-pid-file "${CONFIG_DIR}/vector.pid" \
  --interval "${INTERVAL}" &
AGENT_PID=$!

# If Vector exits, the node is useless, so take the whole container down and let the
# orchestrator restart it. If the agent exits, Vector keeps forwarding on cached config.
trap 'kill ${VECTOR_PID} ${AGENT_PID} 2>/dev/null || true' TERM INT
wait "${VECTOR_PID}"
