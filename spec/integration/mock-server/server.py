"""Mock 1Claw API server for Kong plugin integration tests."""
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

FIXTURE_SECRET = "sk_test_INTEGRATION_SECRET_MUST_NOT_LEAK"
VALID_API_KEY = "ocv_integration_test_key"
VALID_AGENT_ID = "test-agent-uuid"


@app.route("/health")
def health():
    return "ok"


@app.route("/v1/auth/agent-token", methods=["POST"])
def agent_token():
    body = request.get_json(silent=True) or {}
    api_key = body.get("api_key", "")

    if api_key != VALID_API_KEY:
        return jsonify({"error": "unauthorized"}), 401

    return jsonify({
        "access_token": "mock_jwt_token_for_testing",
        "agent_id": VALID_AGENT_ID,
        "expires_in": 3600,
        "vault_ids": ["test-vault-uuid"],
    })


@app.route("/v1/vaults/<vault_id>/secrets/<path:secret_path>", methods=["GET"])
def get_secret(vault_id, secret_path):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"detail": "unauthorized"}), 401

    if vault_id != "test-vault-uuid":
        return jsonify({"detail": "vault not found"}), 404

    if secret_path == "integrations/test-api-key":
        return jsonify({
            "value": FIXTURE_SECRET,
            "path": secret_path,
            "type": "api_key",
            "version": 1,
        })

    return jsonify({"detail": "secret not found"}), 404


@app.route("/v1/agents/<agent_id>/execute", methods=["POST"])
def execute(agent_id):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"detail": "unauthorized"}), 401

    body = request.get_json(silent=True) or {}

    return jsonify({
        "execution_id": "exec-mock-uuid",
        "status": "success",
        "duration_ms": 42,
        "redactions_applied": 0,
        "execution_surface": "vault",
        "result": {
            "status_code": 200,
            "body": {"message": "executed via mock", "binding": body.get("binding")},
        },
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9876)
