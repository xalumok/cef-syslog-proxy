#!/usr/bin/env bash
# One-command local demo. Starts everything, sends traffic, and shows the filtering working.
#
#   ./scripts/demo.sh
#
# Then open http://127.0.0.1:8000 and sign in as analyst / demo1234.
# Press Ctrl-C to stop everything.

set -euo pipefail
cd "$(dirname "$0")/.."

VENV="${VENV:-.venv}"
PY="$VENV/bin/python"
export PATH="$PWD/.tools:$PATH"
export SS_DATABASE_URL="sqlite+pysqlite:///./demo.db"
export SS_JWT_SECRET="local-demo-secret-at-least-32-bytes!"
export SS_VECTOR_LISTEN_ADDRESS="127.0.0.1:5514"
export SS_VECTOR_ELK_ADDRESS="127.0.0.1:5140"
export SS_VECTOR_DROP_AUDIT_ADDRESS="127.0.0.1:5141"
export SS_CONTROL_PLANE_URL="http://127.0.0.1:8000"

PIDS=()
cleanup() {
  echo ""
  echo "stopping..."
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

need() { command -v "$1" >/dev/null || { echo "missing: $1. Run 'make setup' and 'make vector'."; exit 1; }; }
[ -x "$PY" ] || { echo "no venv. Run 'make setup' first."; exit 1; }
need vector

step() { printf "\n\033[36m==> %s\033[0m\n" "$1"; }

# ---------------------------------------------------------------- fake ELK ----
step "Starting a fake ELK receiver on 5140 (forwarded) and 5141 (drop audit)"
"$PY" - > /tmp/ss-elk.log 2>&1 <<'PYEOF' &
import socket, threading
def listen(port, label):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    while True:
        data, _ = s.recvfrom(65536)
        print(f"[{label}] {data.decode('utf-8', 'replace')}", flush=True)
threading.Thread(target=listen, args=(5141, "DROP-AUDIT"), daemon=True).start()
listen(5140, "FORWARDED")
PYEOF
PIDS+=($!)

# ----------------------------------------------------------- control plane ----
step "Seeding the database"
rm -f demo.db demo.db-wal demo.db-shm
"$VENV/bin/ssctl" init-db >/dev/null
"$VENV/bin/ssctl" adduser analyst --role rule-editor --password demo1234 >/dev/null
"$VENV/bin/ssctl" adduser watcher --role viewer --password demo1234 >/dev/null
echo "  analyst / demo1234  (rule-editor)"
echo "  watcher / demo1234  (viewer, cannot see event contents)"

step "Starting the control plane on http://127.0.0.1:8000"
"$VENV/bin/ssctl" serve > /tmp/ss-control.log 2>&1 &
PIDS+=($!)

for _ in $(seq 1 40); do
  curl -sf http://127.0.0.1:8000/api/health >/dev/null 2>&1 && break
  sleep 0.25
done
curl -sf http://127.0.0.1:8000/api/health >/dev/null || { echo "control plane did not start; see /tmp/ss-control.log"; exit 1; }

# ------------------------------------------------------------------ rules ----
step "Creating two rules and publishing a bundle"
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/auth/token \
  -d "username=analyst&password=demo1234" | "$PY" -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
AUTH="Authorization: Bearer $TOKEN"

curl -s -X POST http://127.0.0.1:8000/api/rules -H "$AUTH" -H "Content-Type: application/json" -d '{
  "name": "Suppress nightly scanner",
  "description": "Known-benign vulnerability scan from scanner01",
  "action": "drop", "order": 0,
  "conditions": [{"field": "filterhostname", "operator": "eq", "value": "scanner01"}]
}' >/dev/null
echo "  1. drop  filterhostname eq scanner01"

curl -s -X POST http://127.0.0.1:8000/api/rules -H "$AUTH" -H "Content-Type: application/json" -d '{
  "name": "Drop lab subnet",
  "action": "drop", "order": 1, "retain_payload": true,
  "conditions": [{"field": "filteripaddress", "operator": "cidr", "value": "10.42.0.0/16"}]
}' >/dev/null
echo "  2. drop  filteripaddress cidr 10.42.0.0/16   (retains the full event in the audit record)"

curl -s -X POST http://127.0.0.1:8000/api/bundles/publish -H "$AUTH" \
  -H "Content-Type: application/json" -d '{"note":"demo"}' \
  | "$PY" -c 'import sys,json; b=json.load(sys.stdin); print("  published bundle v%s (%s), %s rules" % (b["version"], b["checksum"][:12], b["rule_count"]))'

# ------------------------------------------------------------- data plane ----
step "Starting Vector with the published config"
curl -s http://127.0.0.1:8000/api/bundles/active/config -H "$AUTH" > /tmp/ss-vector.toml
vector --quiet --config /tmp/ss-vector.toml > /tmp/ss-vector.log 2>&1 &
PIDS+=($!)
sleep 4

# --------------------------------------------------------------- traffic ----
step "Sending traffic"
: > /tmp/ss-elk.log
"$VENV/bin/cefgen" send 127.0.0.1:5514 -n 60 -r 60 2>/dev/null
sleep 2

FWD=$(grep -c "FORWARDED" /tmp/ss-elk.log || true)
DRP=$(grep -c "DROP-AUDIT" /tmp/ss-elk.log || true)

step "Result"
echo "  forwarded to ELK : $FWD"
echo "  dropped (audited): $DRP"
echo ""
echo "  Sample of what ELK received:"
grep "FORWARDED" /tmp/ss-elk.log | head -2 | sed 's/^/    /'
echo ""
echo "  Sample drop audit record:"
grep "DROP-AUDIT" /tmp/ss-elk.log | head -1 | sed 's/^/    /'

cat <<EOF

--------------------------------------------------------------------------
Everything is running. Open http://127.0.0.1:8000

  Sign in:   analyst / demo1234
  Try:       Rules -> New rule, then Bundles -> Publish
             Live decisions -> watch traffic arrive
             Audit log -> see who changed what

  More traffic:
    .venv/bin/cefgen send 127.0.0.1:5514 -n 500 -r 200
    .venv/bin/cefgen send 127.0.0.1:5514 -n 100 --adversarial-share 0.5

  Sign in as watcher / demo1234 to see server-side redaction.

  Logs: /tmp/ss-control.log  /tmp/ss-vector.log  /tmp/ss-elk.log

Press Ctrl-C to stop.
--------------------------------------------------------------------------
EOF

tail -f /tmp/ss-elk.log
