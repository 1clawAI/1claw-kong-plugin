# 1claw-vault-auth

A Kong Gateway plugin that resolves short-TTL credentials from [1Claw](https://1claw.xyz)'s HSM/MPC-backed vault at proxy time and injects them into upstream requests. The raw secret never appears in Kong's plugin config, logs, Konnect analytics, or error responses.

## How it works

```
┌────────┐         ┌──────────────┐         ┌─────────────┐         ┌──────────┐
│ Client │──req──▶│ Kong Gateway │──req──▶│ 1Claw Vault │         │ Upstream │
│        │         │  + plugin    │◀─secret─│             │         │          │
│        │         │              │──req+cred────────────────────▶│          │
│        │◀─resp──│              │◀─resp───────────────────────────│          │
└────────┘         └──────────────┘                                 └──────────┘
```

1. Client sends a request to Kong.
2. In the `access` phase, the plugin exchanges the agent API key for a short-lived JWT.
3. Using the JWT, it fetches the credential from 1Claw's vault (cached per TTL).
4. The credential is injected into the upstream request (header, query param, or body field).
5. Kong proxies to the upstream with the credential attached.
6. The credential exists only in plugin memory during the access phase, never in logs or config.

## Two modes

| Mode | Description | Use case |
|------|-------------|----------|
| `vault` (default) | Fetches a raw secret value and injects it into Kong's upstream request | Standard API key/token injection |
| `execute` | Calls 1Claw Execution Intents; 1Claw makes the upstream call, Kong returns the result | When 1Claw must control the full request lifecycle |

## Kong vault:// vs. this plugin

These are complementary, not competing:

- **Kong vault references** (`{vault://env/MY_KEY}`) solve: "How does Kong fetch its own plugin config secrets?" Use this for the `agent_api_key` field itself.
- **This plugin** solves: "How does Kong fetch upstream application credentials for the request it's proxying?" The credential is fetched JIT per request (or from cache), not stored in Kong's config at all.

Use them together: set `agent_api_key` to `{vault://env/ONECLAW_AGENT_KEY}` so the 1Claw agent key is never stored in plaintext in Kong's data store.

## Quickstart

### 1. Install

```bash
luarocks install 1claw-vault-auth
```

Or mount the plugin directory and add to `KONG_PLUGINS`:

```bash
KONG_PLUGINS=bundled,1claw-vault-auth
KONG_LUA_PACKAGE_PATH=/path/to/plugin/?.lua;;
```

### 2. Configure (vault mode)

```bash
curl -X POST http://localhost:8001/services/my-service/plugins \
  -d "name=1claw-vault-auth" \
  -d "config.agent_api_key=ocv_your_agent_key" \
  -d "config.agent_id=your-agent-uuid" \
  -d "config.mode=vault" \
  -d "config.vault_id=your-vault-uuid" \
  -d "config.secret_path=integrations/stripe-key" \
  -d "config.injection_target=header" \
  -d "config.injection_key=Authorization" \
  -d "config.injection_prefix=Bearer " \
  -d "config.cache_ttl_seconds=60"
```

### 3. Configure (execute mode)

```bash
curl -X POST http://localhost:8001/services/my-service/plugins \
  -d "name=1claw-vault-auth" \
  -d "config.agent_api_key=ocv_your_agent_key" \
  -d "config.agent_id=your-agent-uuid" \
  -d "config.mode=execute" \
  -d "config.binding=stripe-api" \
  -d "config.intent_type=http"
```

## Configuration reference

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `agent_api_key` | string | yes | — | 1Claw agent API key (`ocv_...`). **Referenceable** — use `{vault://...}` |
| `agent_id` | string | no | — | Agent UUID. If omitted, auto-resolved from key exchange |
| `oneclaw_api_base` | string | no | `https://api.1claw.xyz` | 1Claw API base URL |
| `mode` | string | no | `vault` | `vault` or `execute` |
| `vault_id` | string | vault mode | — | 1Claw vault UUID containing the secret |
| `secret_path` | string | vault mode | — | Path to the secret within the vault |
| `binding` | string | execute mode | — | Execution Intent binding name |
| `intent_type` | string | no | `http` | Execution intent type |
| `injection_target` | string | no | `header` | Where to inject: `header`, `query`, or `body` |
| `injection_key` | string | no | `Authorization` | Header name, query param, or JSON field |
| `injection_prefix` | string | no | `""` | Prefix prepended to the secret value (e.g. `Bearer `) |
| `cache_ttl_seconds` | number | no | `60` | How long to cache the resolved secret (0 = no cache) |
| `fail_mode` | string | no | `close` | `close` (502 on failure) or `open` (proceed without injection) |
| `connect_timeout_ms` | number | no | `2000` | TCP connect timeout to 1Claw |
| `read_timeout_ms` | number | no | `3000` | Read timeout for 1Claw responses |

## Security properties

- The resolved secret value **never** enters `kong.log.*` calls.
- The secret is **never** included in error response bodies.
- The secret exists only in Lua local variables during the `access` phase.
- The `agent_api_key` field is marked `encrypted = true` and `referenceable = true`.
- In `fail_mode = close` (default), a failed credential resolution returns a generic 502 with no internal details.

## Fail-open mode (security tradeoff)

Setting `fail_mode = "open"` allows requests to proceed to the upstream **without** the injected credential when 1Claw is unreachable. This is a deliberate security tradeoff: use it only when the upstream can handle unauthenticated requests gracefully (e.g., a public endpoint that returns limited data without auth). For any sensitive upstream, leave `fail_mode = "close"`.

## Observability

The plugin emits structured metadata under the `ai.1claw` namespace in Kong's log serializer:

| Key | Type | Description |
|-----|------|-------------|
| `ai.1claw.plugin_version` | string | Plugin version |
| `ai.1claw.mode` | string | `vault` or `execute` |
| `ai.1claw.agent_id` | string | Resolved agent UUID |
| `ai.1claw.cache_hit` | boolean | Whether the secret was served from cache |
| `ai.1claw.resolve_latency_ms` | number | Time to fetch from 1Claw (on cache miss) |
| `ai.1claw.status` | string | `injected`, `executed`, `token_error`, `fetch_error`, `execute_error` |
| `ai.1claw.secret_path` | string | Vault secret path (vault mode only) |
| `ai.1claw.binding` | string | Binding name (execute mode only) |

## Testing

### Unit tests (Busted)

```bash
busted spec/unit/
```

### Integration tests (Docker Compose)

```bash
cd spec/integration
./run-tests.sh
```

## Development

```
packages/1claw-kong-plugin/
├── kong/plugins/1claw-vault-auth/
│   ├── handler.lua          # Core plugin logic (access phase)
│   └── schema.lua           # Configuration schema
├── spec/
│   ├── unit/                # Busted unit tests
│   └── integration/         # Docker Compose + mock server
├── .github/workflows/
│   ├── ci.yml               # Lint + test on push/PR
│   └── release.yml          # Tag-triggered LuaRocks publish
├── 1claw-kong-plugin-0.1.0-0.rockspec
├── CHANGELOG.md
├── LICENSE                  # MIT
└── README.md
```

## License

MIT. See [LICENSE](./LICENSE).
