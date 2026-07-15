#!/usr/bin/env bash
# Live production test for 1claw-vault-auth against api.1claw.xyz
#
# Quick start (uses packages/1claw-kong-plugin/.env):
#   cd packages/1claw-kong-plugin
#   # .env needs ONECLAW_API_KEY=1ck_...
#   ./spec/live/bootstrap.sh
#   source .kong-live-test.env && ./spec/live/run-live-test.sh
#
# Or set these manually:
#   ONECLAW_AGENT_API_KEY, ONECLAW_VAULT_ID, ONECLAW_SECRET_PATH
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ -f "$PLUGIN_ROOT/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$PLUGIN_ROOT/.env"
  set +a
fi

if [ -z "${ONECLAW_AGENT_API_KEY:-}" ] && [ -f "$PLUGIN_ROOT/.kong-live-test.env" ]; then
  # shellcheck disable=SC1091
  source "$PLUGIN_ROOT/.kong-live-test.env"
fi

: "${ONECLAW_AGENT_API_KEY:?Run ./spec/live/bootstrap.sh first or set ONECLAW_AGENT_API_KEY}"
: "${ONECLAW_VAULT_ID:?Set ONECLAW_VAULT_ID}"
: "${ONECLAW_SECRET_PATH:?Set ONECLAW_SECRET_PATH}"

API_BASE="${ONECLAW_API_BASE:-https://api.1claw.xyz}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== 1. Verify agent token exchange ==="
TOKEN_BODY=$(python3 -c "import json,os; print(json.dumps({'api_key': os.environ['ONECLAW_AGENT_API_KEY']} | ({'agent_id': os.environ['ONECLAW_AGENT_ID']} if os.environ.get('ONECLAW_AGENT_ID') else {})))")
TOKEN_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_BASE/v1/auth/agent-token" \
  -H "Content-Type: application/json" \
  -d "$TOKEN_BODY")
TOKEN_CODE=$(echo "$TOKEN_RESP" | tail -1)
TOKEN_JSON=$(echo "$TOKEN_RESP" | sed '$d')

if [ "$TOKEN_CODE" != "200" ]; then
  echo "FAIL: agent-token returned $TOKEN_CODE"
  echo "$TOKEN_JSON"
  exit 1
fi
echo "PASS: agent-token exchange"

AGENT_ID=$(echo "$TOKEN_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('agent_id',''))")
ACCESS_TOKEN=$(echo "$TOKEN_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
echo "  agent_id: $AGENT_ID"

echo ""
echo "=== 2. Verify vault secret read (what Kong will fetch) ==="
SECRET_RESP=$(curl -s -w "\n%{http_code}" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$API_BASE/v1/vaults/$ONECLAW_VAULT_ID/secrets/$ONECLAW_SECRET_PATH")
SECRET_CODE=$(echo "$SECRET_RESP" | tail -1)
SECRET_JSON=$(echo "$SECRET_RESP" | sed '$d')

if [ "$SECRET_CODE" != "200" ]; then
  echo "FAIL: secret read returned $SECRET_CODE"
  echo "$SECRET_JSON"
  echo "Ensure the agent has a read policy on this vault/path."
  exit 1
fi
echo "PASS: secret readable (value redacted in output)"
SECRET_LEN=$(echo "$SECRET_JSON" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('value','')))")
echo "  secret length: $SECRET_LEN chars"

EXECUTION_AVAILABLE="${ONECLAW_EXECUTION_AVAILABLE:-0}"
if [ -n "${ONECLAW_BINDING:-}" ] && [ "$EXECUTION_AVAILABLE" = "1" ]; then
  echo ""
  echo "=== 3. Direct API execute (real jsonplaceholder.typicode.com via 1Claw) ==="
  EXEC_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_BASE/v1/agents/$AGENT_ID/execute" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"binding\":\"$ONECLAW_BINDING\",\"intent_type\":\"http\",\"params\":{\"method\":\"GET\",\"path\":\"/todos/1\"}}")
  EXEC_CODE=$(echo "$EXEC_RESP" | tail -1)
  EXEC_JSON=$(echo "$EXEC_RESP" | sed '$d')
  if [ "$EXEC_CODE" != "200" ]; then
    echo "FAIL: execute returned $EXEC_CODE"
    echo "$EXEC_JSON"
    exit 1
  fi
  if echo "$EXEC_JSON" | python3 -c "
import json, sys
d = json.load(sys.stdin)
r = d.get('result', {})
if r.get('status') != 200:
    sys.exit(1)
body = r.get('body', {})
if isinstance(body, str):
    try:
        body = json.loads(body)
    except json.JSONDecodeError:
        sys.exit(1)
sys.exit(0 if body.get('id') == 1 and body.get('title') else 1)
"; then
    echo "PASS: 1Claw reached jsonplaceholder.typicode.com and returned todos/1"
  else
    echo "FAIL: unexpected execute response"
    echo "$EXEC_JSON" | python3 -m json.tool | head -30
    exit 1
  fi
elif [ "${ONECLAW_EXECUTION_AVAILABLE:-0}" != "1" ]; then
  echo ""
  echo "=== 3. Execute mode (skipped) ==="
  echo "  tier=${ONECLAW_BILLING_TIER:-unknown}; needs Pro+ and execution_intents_enabled"
  echo "  Re-run ./spec/live/bootstrap.sh after upgrading, or test vault mode only."
fi

echo ""
echo "=== 4. Start Kong with plugin (vault mode smoke test) ==="
docker compose -f "$SCRIPT_DIR/docker-compose.live.yml" down -v 2>/dev/null || true

cat > "$SCRIPT_DIR/kong.live.yml" <<EOF
_format_version: "3.0"
services:
  - name: live-upstream
    url: http://httpbin:80
    routes:
      - name: live-route
        paths:
          - /live-test
    plugins:
      - name: 1claw-vault-auth
        config:
          agent_api_key: "$ONECLAW_AGENT_API_KEY"
          agent_id: "${ONECLAW_AGENT_ID:-}"
          oneclaw_api_base: "$API_BASE"
          mode: vault
          vault_id: "$ONECLAW_VAULT_ID"
          secret_path: "$ONECLAW_SECRET_PATH"
          injection_target: header
          injection_key: X-Injected-Credential
          cache_ttl_seconds: 30
          fail_mode: close
          connect_timeout_ms: 5000
          read_timeout_ms: 10000
EOF

docker compose -f "$SCRIPT_DIR/docker-compose.live.yml" up -d --wait

echo "Hitting Kong proxy (should inject secret into httpbin)..."
PROXY_RESP=$(curl -s -w "\n%{http_code}" http://localhost:8000/live-test/headers)
PROXY_CODE=$(echo "$PROXY_RESP" | tail -1)
PROXY_BODY=$(echo "$PROXY_RESP" | sed '$d')

if [ "$PROXY_CODE" != "200" ]; then
  echo "FAIL: Kong proxy returned $PROXY_CODE"
  echo "$PROXY_BODY"
  docker compose -f "$SCRIPT_DIR/docker-compose.live.yml" logs kong
  docker compose -f "$SCRIPT_DIR/docker-compose.live.yml" down -v
  exit 1
fi

if echo "$PROXY_BODY" | grep -qi "X-Injected-Credential"; then
  echo "PASS: Kong injected credential header into upstream"
else
  echo "FAIL: injected header not found in upstream echo"
  echo "$PROXY_BODY"
  docker compose -f "$SCRIPT_DIR/docker-compose.live.yml" logs kong
  docker compose -f "$SCRIPT_DIR/docker-compose.live.yml" down -v
  exit 1
fi

if [ -n "${ONECLAW_BINDING:-}" ] && [ "${ONECLAW_EXECUTION_AVAILABLE:-0}" = "1" ]; then
  echo ""
  echo "=== 5. Kong execute mode (1Claw calls jsonplaceholder, Kong returns result) ==="
  docker compose -f "$SCRIPT_DIR/docker-compose.live.yml" down -v 2>/dev/null || true

  cat > "$SCRIPT_DIR/kong.live.yml" <<EOF
_format_version: "3.0"
services:
  - name: live-upstream
    url: http://httpbin:80
    routes:
      - name: live-route
        paths:
          - /live-test
    plugins:
      - name: 1claw-vault-auth
        config:
          agent_api_key: "$ONECLAW_AGENT_API_KEY"
          agent_id: "${ONECLAW_AGENT_ID:-}"
          oneclaw_api_base: "$API_BASE"
          mode: vault
          vault_id: "$ONECLAW_VAULT_ID"
          secret_path: "$ONECLAW_SECRET_PATH"
          injection_target: header
          injection_key: X-Injected-Credential
          cache_ttl_seconds: 30
          fail_mode: close
          connect_timeout_ms: 5000
          read_timeout_ms: 10000

  - name: live-execute
    url: http://httpbin:80
    routes:
      - name: execute-todos-route
        paths:
          - /todos/1
    plugins:
      - name: 1claw-vault-auth
        config:
          agent_api_key: "$ONECLAW_AGENT_API_KEY"
          agent_id: "${ONECLAW_AGENT_ID:-}"
          oneclaw_api_base: "$API_BASE"
          mode: execute
          binding: "$ONECLAW_BINDING"
          intent_type: http
          cache_ttl_seconds: 0
          fail_mode: close
          connect_timeout_ms: 5000
          read_timeout_ms: 15000
EOF

  docker compose -f "$SCRIPT_DIR/docker-compose.live.yml" up -d --wait

  EXEC_PROXY_RESP=$(curl -s -w "\n%{http_code}" "http://localhost:8000/todos/1")
  EXEC_PROXY_CODE=$(echo "$EXEC_PROXY_RESP" | tail -1)
  EXEC_PROXY_BODY=$(echo "$EXEC_PROXY_RESP" | sed '$d')

  if [ "$EXEC_PROXY_CODE" != "200" ]; then
    echo "FAIL: Kong execute mode returned $EXEC_PROXY_CODE"
    echo "$EXEC_PROXY_BODY"
    docker compose -f "$SCRIPT_DIR/docker-compose.live.yml" logs kong
    docker compose -f "$SCRIPT_DIR/docker-compose.live.yml" down -v
    exit 1
  fi

  if echo "$EXEC_PROXY_BODY" | python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get('id')==1 and d.get('title') else 1)"; then
    echo "PASS: Kong execute mode returned live jsonplaceholder /todos/1 response"
  else
    echo "FAIL: execute response missing expected httpbin args"
    echo "$EXEC_PROXY_BODY" | head -c 500
    docker compose -f "$SCRIPT_DIR/docker-compose.live.yml" logs kong
    docker compose -f "$SCRIPT_DIR/docker-compose.live.yml" down -v
    exit 1
  fi
fi

echo ""
echo "=== All live tests passed ==="
docker compose -f "$SCRIPT_DIR/docker-compose.live.yml" down -v
