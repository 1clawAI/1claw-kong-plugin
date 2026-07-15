# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-15

### Added

- Initial release of `1claw-vault-auth` Kong Gateway plugin.
- **Vault mode**: Fetch raw secrets from 1Claw Vault and inject into upstream requests (header, query, or body).
- **Execute mode**: Call 1Claw Execution Intents API for full server-side credential injection and request execution.
- Agent JWT token exchange with automatic caching and renewal.
- Per-worker LRU cache for resolved secrets with configurable TTL.
- Fail-closed (default) and fail-open resilience modes.
- Structured observability metadata under `ai.1claw` namespace (agent_id, mode, cache_hit, resolve_latency_ms, status).
- `referenceable` and `encrypted` annotations on `agent_api_key` for Kong vault:// integration.
- Conditional schema validation (vault_id/secret_path required in vault mode, binding required in execute mode).
- Busted unit tests covering cache hit/miss, TTL expiry, auth failures, all injection modes, and the log-leak security assertion.
- Docker Compose integration test environment with mock 1Claw server.
- LuaRocks packaging via `.rockspec`.
- GitHub Actions CI (luacheck lint + busted tests) and release (tag-triggered LuaRocks publish scaffold).
