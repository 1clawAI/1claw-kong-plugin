#!/usr/bin/env bash
# Bootstrap agent + secret + policy for Kong plugin live tests.
# Uses ONECLAW_API_KEY (1ck_) from .env — no agent key required upfront.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ -f "$PLUGIN_ROOT/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$PLUGIN_ROOT/.env"
  set +a
fi

: "${ONECLAW_API_KEY:?Set ONECLAW_API_KEY in packages/1claw-kong-plugin/.env}"

API="${ONECLAW_API_URL:-https://api.1claw.xyz}"
AGENT_NAME="${ONECLAW_TEST_AGENT_NAME:-kong-plugin-live-test}"
SECRET_PATH="${ONECLAW_SECRET_PATH:-integrations/kong-plugin-test}"

export PLUGIN_ROOT

python3 <<PY
import json, os, subprocess, sys, uuid

api = os.environ.get("ONECLAW_API_URL", "https://api.1claw.xyz")
token = os.environ["ONECLAW_API_KEY"]
agent_name = os.environ.get("ONECLAW_TEST_AGENT_NAME", "kong-plugin-live-test")
secret_path = os.environ.get("ONECLAW_SECRET_PATH", "integrations/kong-plugin-test")

def curl(method, path, body=None, agent_token=None):
    auth = agent_token or token
    cmd = ["curl", "-s", "-w", "\n%{http_code}", "-X", method, f"{api}{path}",
           "-H", f"Authorization: Bearer {auth}",
           "-H", "Content-Type: application/json"]
    if body is not None:
        cmd += ["-d", json.dumps(body)]
    out = subprocess.check_output(cmd, text=True)
    *lines, code = out.rsplit("\n", 1)
    body_text = "\n".join(lines)
    try:
        parsed = json.loads(body_text) if body_text.strip() else {}
    except json.JSONDecodeError:
        parsed = body_text
    return int(code), parsed

code, vaults = curl("GET", "/v1/vaults")
if code != 200:
    print(f"FAIL list vaults: {code} {vaults}")
    sys.exit(1)
vault_list = vaults.get("vaults", [])
if not vault_list:
    print("FAIL: no vaults")
    sys.exit(1)
vault_id = vault_list[0]["id"]

code, _ = curl("PUT", f"/v1/vaults/{vault_id}/secrets/{secret_path}", {
    "value": f"kong-live-test-{uuid.uuid4().hex[:8]}",
    "type": "api_key",
})
if code not in (200, 201):
    print(f"FAIL put secret: {code}")
    sys.exit(1)

code, agents = curl("GET", "/v1/agents")
agent_id = None
for a in agents.get("agents", []):
    if a.get("name") == agent_name and a.get("is_active", True):
        agent_id = a["id"]
        break
if not agent_id:
    print(f"FAIL: agent '{agent_name}' not found (agent limit may be reached)")
    sys.exit(1)

code, policies = curl("GET", f"/v1/vaults/{vault_id}/policies")
has_policy = False
if code == 200:
    for p in policies.get("policies", []):
        if p.get("principal_type") == "agent" and p.get("principal_id") == agent_id:
            pat = p.get("secret_path_pattern") or p.get("path_pattern") or ""
            if secret_path in pat or pat in ("*", "integrations/*"):
                has_policy = True
                break
if not has_policy:
    for payload in [
        {"principal_type": "agent", "principal_id": agent_id, "secret_path_pattern": secret_path, "permissions": ["read"]},
        {"principal_type": "agent", "principal_id": agent_id, "path_pattern": secret_path, "permissions": ["read"]},
    ]:
        code, _ = curl("POST", f"/v1/vaults/{vault_id}/policies", payload)
        if code in (200, 201):
            has_policy = True
            break
    if not has_policy:
        print("FAIL: could not create read policy")
        sys.exit(1)

code, rot = curl("POST", f"/v1/agents/{agent_id}/rotate-key", {})
if code not in (200, 201) or not rot.get("api_key"):
    print(f"FAIL rotate-key: {code}")
    sys.exit(1)
api_key = rot["api_key"]

code, tok = curl("POST", "/v1/auth/agent-token", {"agent_id": agent_id, "api_key": api_key})
if code != 200:
    code, tok = curl("POST", "/v1/auth/agent-token", {"api_key": api_key})
if code != 200:
    print(f"FAIL agent-token: {code} {tok}")
    sys.exit(1)

code, _ = curl("GET", f"/v1/vaults/{vault_id}/secrets/{secret_path}", agent_token=tok["access_token"])
if code != 200:
    print(f"FAIL agent secret read: {code}")
    sys.exit(1)

env_path = os.path.join(os.environ.get("PLUGIN_ROOT", "."), ".kong-live-test.env")
with open(env_path, "w") as f:
    f.write(f"export ONECLAW_AGENT_API_KEY={api_key}\n")
    f.write(f"export ONECLAW_AGENT_ID={agent_id}\n")
    f.write(f"export ONECLAW_VAULT_ID={vault_id}\n")
    f.write(f"export ONECLAW_SECRET_PATH={secret_path}\n")
    f.write(f"export ONECLAW_API_BASE={api}\n")
print(f"bootstrap ok -> {env_path}")
PY
