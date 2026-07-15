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

# Optional human JWT login for binding create (1ck_ keys fail on POST /bindings until vault middleware fix ships)
MONOREPO_ENV="$(cd "$PLUGIN_ROOT/../.." && pwd)/.env"
if [ -f "$MONOREPO_ENV" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$MONOREPO_ENV"
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
human_token = token  # 1ck_ key works for most endpoints; binding POST needs JWT (see below)
agent_name = os.environ.get("ONECLAW_TEST_AGENT_NAME", "kong-plugin-live-test")
secret_path = os.environ.get("ONECLAW_SECRET_PATH", "integrations/kong-plugin-test")

def resolve_human_jwt():
    """Binding create/update routes require a parseable JWT before auth middleware runs."""
    if os.environ.get("ONECLAW_HUMAN_TOKEN"):
        return os.environ["ONECLAW_HUMAN_TOKEN"]
    email = os.environ.get("ONECLAW_TEST_EMAIL") or os.environ.get("ONECLAW_EMAIL") or os.environ.get("ADMIN_EMAIL")
    password = os.environ.get("ONECLAW_TEST_PASSWORD") or os.environ.get("ONECLAW_PASSWORD") or os.environ.get("ADMIN_PASSWORD")
    if email and password:
        code, body = curl("POST", "/v1/auth/token", {"email": email, "password": password})
        if code == 200 and body.get("access_token"):
            return body["access_token"]
    return None

def curl(method, path, body=None, agent_token=None, user_token=None):
    auth = user_token or agent_token or token
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
    code, created = curl("POST", "/v1/agents", {
        "name": agent_name,
        "description": "Kong plugin live tests",
        "execution_intents_enabled": True,
    })
    if code in (200, 201):
        agent_id = created.get("agent", {}).get("id") or created.get("id")
        api_key_from_create = created.get("api_key")
    else:
        print(f"FAIL: agent '{agent_name}' not found and create returned {code}: {created}")
        sys.exit(1)
else:
    api_key_from_create = None

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
    if api_key_from_create:
        api_key = api_key_from_create
    else:
        print(f"FAIL rotate-key: {code}")
        sys.exit(1)
else:
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

binding_name = os.environ.get("ONECLAW_BINDING_NAME", "kong-httpbin-live")
execution_available = False
tier = "unknown"

code, sub = curl("GET", "/v1/billing/subscription")
if code == 200:
    tier = sub.get("tier", "unknown")

code, _ = curl("PATCH", f"/v1/agents/{agent_id}", {"execution_intents_enabled": True})
if code == 200:
    jwt = resolve_human_jwt()
    if not jwt:
        print("WARN: binding create needs a human JWT — set ONECLAW_TEST_EMAIL/PASSWORD or ONECLAW_HUMAN_TOKEN")
    code, bindings = curl("GET", f"/v1/agents/{agent_id}/bindings")
    has_binding = False
    if code == 200:
        for b in bindings.get("bindings", []):
            if b.get("name") == binding_name and b.get("is_active", True):
                has_binding = True
                break
    if not has_binding:
        code, created = curl(
            "POST",
            f"/v1/agents/{agent_id}/bindings",
            {
                "name": binding_name,
                "binding_type": "http",
                "config": {
                    "base_url": "https://jsonplaceholder.typicode.com",
                    "auth_type": "none",
                    "allowed_hosts": ["jsonplaceholder.typicode.com"],
                    "allowed_paths": ["/*"],
                },
            },
            user_token=jwt,
        )
        if code not in (200, 201):
            print(f"WARN: binding create returned {code}: {created}")
        else:
            has_binding = True
    if has_binding:
        code, tok2 = curl("POST", "/v1/auth/agent-token", {"api_key": api_key})
        if code == 200 and tok2.get("access_token"):
            exec_claims = json.loads(
                __import__("base64").urlsafe_b64decode(
                    tok2["access_token"].split(".")[1] + "=="
                ).decode()
            )
            if exec_claims.get("execution_intents_enabled"):
                code, exec_test = curl(
                    "POST",
                    f"/v1/agents/{agent_id}/execute",
                    {
                        "binding": binding_name,
                        "intent_type": "http",
                        "params": {"method": "GET", "path": "/todos/1"},
                    },
                    agent_token=tok2["access_token"],
                )
                if code == 200 and exec_test.get("status") == "success":
                    execution_available = True
                    print(f"execute probe ok (tier={tier}, binding={binding_name})")
                else:
                    print(f"WARN: execute probe returned {code}: {exec_test}")
            else:
                print("WARN: JWT missing execution_intents_enabled after PATCH")
else:
    print(f"WARN: could not enable execution_intents on agent ({code})")

env_path = os.path.join(os.environ.get("PLUGIN_ROOT", "."), ".kong-live-test.env")
with open(env_path, "w") as f:
    f.write(f"export ONECLAW_AGENT_API_KEY={api_key}\n")
    f.write(f"export ONECLAW_AGENT_ID={agent_id}\n")
    f.write(f"export ONECLAW_VAULT_ID={vault_id}\n")
    f.write(f"export ONECLAW_SECRET_PATH={secret_path}\n")
    f.write(f"export ONECLAW_API_BASE={api}\n")
    f.write(f"export ONECLAW_BILLING_TIER={tier}\n")
    if execution_available:
        f.write(f"export ONECLAW_BINDING={binding_name}\n")
        f.write("export ONECLAW_EXECUTION_AVAILABLE=1\n")
    else:
        f.write("export ONECLAW_EXECUTION_AVAILABLE=0\n")
print(f"bootstrap ok -> {env_path}")
if not execution_available:
    print("NOTE: execute mode skipped — requires Pro+ plan, execution_intents_enabled, and HTTP binding")
PY
