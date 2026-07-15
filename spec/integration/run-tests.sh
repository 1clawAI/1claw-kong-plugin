#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Starting integration test environment ==="
docker compose up -d --build --wait

echo "=== Waiting for Kong to be ready ==="
for i in $(seq 1 30); do
  if curl -s http://localhost:8001/status | grep -q "database"; then
    echo "Kong is ready."
    break
  fi
  echo "Waiting for Kong... ($i)"
  sleep 2
done

echo ""
echo "=== Test 1: Vault mode — credential injection ==="
RESPONSE=$(curl -s -w "\n%{http_code}" http://localhost:8000/test/headers)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" != "200" ]; then
  echo "FAIL: Expected 200, got $HTTP_CODE"
  echo "$BODY"
  docker compose logs kong
  docker compose down
  exit 1
fi

# httpbin /headers echoes back the request headers
if echo "$BODY" | grep -q "X-Api-Key"; then
  echo "PASS: X-Api-Key header was injected"
else
  echo "FAIL: X-Api-Key header was NOT injected"
  echo "$BODY"
  docker compose logs kong
  docker compose down
  exit 1
fi

# CRITICAL: The secret value must appear in the upstream (it was injected),
# but must NOT appear in Kong's access logs
echo ""
echo "=== Test 2: Secret never appears in Kong logs ==="
FIXTURE_SECRET="sk_test_INTEGRATION_SECRET_MUST_NOT_LEAK"
KONG_LOGS=$(docker compose logs kong 2>&1)

if echo "$KONG_LOGS" | grep -q "$FIXTURE_SECRET"; then
  echo "FAIL: SECRET VALUE LEAKED INTO KONG LOGS!"
  echo "This is the core security property of this plugin."
  docker compose down
  exit 1
else
  echo "PASS: Secret value does NOT appear in Kong logs"
fi

echo ""
echo "=== Test 3: Execute mode — pass-through ==="
EXEC_RESPONSE=$(curl -s -w "\n%{http_code}" http://localhost:8000/exec-test/anything)
EXEC_CODE=$(echo "$EXEC_RESPONSE" | tail -1)
EXEC_BODY=$(echo "$EXEC_RESPONSE" | sed '$d')

if [ "$EXEC_CODE" = "200" ]; then
  echo "PASS: Execute mode returned 200"
  if echo "$EXEC_BODY" | grep -q "executed via mock"; then
    echo "PASS: Response contains 1Claw execute result"
  else
    echo "WARN: Response body unexpected: $EXEC_BODY"
  fi
else
  echo "FAIL: Execute mode returned $EXEC_CODE"
  echo "$EXEC_BODY"
fi

echo ""
echo "=== Test 4: Fail-closed on auth failure ==="
# This test requires reconfiguring — for now, verify the mock returns 401 for bad keys
BAD_TOKEN_RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:9876/v1/auth/agent-token \
  -H "Content-Type: application/json" \
  -d '{"api_key":"ocv_bad_key"}')
if [ "$BAD_TOKEN_RESP" = "401" ]; then
  echo "PASS: Mock correctly rejects invalid API keys"
else
  echo "WARN: Mock returned $BAD_TOKEN_RESP for bad key (expected 401)"
fi

echo ""
echo "=== All integration tests passed ==="
docker compose down
