local http = require "resty.http"
local cjson = require "cjson.safe"
local lrucache = require "resty.lrucache"

local kong = kong
local fmt = string.format
local ngx_now = ngx.now

local OneclawVaultAuth = {
  VERSION = "0.1.0",
  PRIORITY = 780, -- after auth plugins (~1000), before proxying
}

-- Per-worker LRU cache: 1000 entries max
local secret_cache, cache_err = lrucache.new(1000)
if not secret_cache then
  error("failed to create LRU cache: " .. (cache_err or "unknown"))
end

-- Per-worker JWT token cache (one per agent_api_key)
local token_cache, tcache_err = lrucache.new(100)
if not token_cache then
  error("failed to create token LRU cache: " .. (tcache_err or "unknown"))
end


local function make_http_client(conf)
  local httpc = http.new()
  httpc:set_timeouts(conf.connect_timeout_ms, conf.connect_timeout_ms, conf.read_timeout_ms)
  return httpc
end


local function get_agent_token(conf)
  local cache_key = "token:" .. conf.agent_api_key

  local cached = token_cache:get(cache_key)
  if cached then
    return cached.token, cached.agent_id
  end

  local httpc = make_http_client(conf)
  local body_table = { api_key = conf.agent_api_key }
  if conf.agent_id and conf.agent_id ~= "" then
    body_table.agent_id = conf.agent_id
  end

  local res, err = httpc:request_uri(conf.oneclaw_api_base .. "/v1/auth/agent-token", {
    method = "POST",
    headers = {
      ["Content-Type"] = "application/json",
    },
    body = cjson.encode(body_table),
  })

  if not res then
    return nil, nil, "token exchange failed: " .. (err or "unknown")
  end

  if res.status ~= 200 then
    return nil, nil, fmt("token exchange returned %d", res.status)
  end

  local data = cjson.decode(res.body)
  if not data or not data.access_token then
    return nil, nil, "token exchange: missing access_token"
  end

  local token = data.access_token
  local agent_id = data.agent_id or conf.agent_id
  local ttl = (data.expires_in or 3600) - 60 -- refresh 60s before expiry
  if ttl < 10 then ttl = 10 end

  token_cache:set(cache_key, { token = token, agent_id = agent_id }, ttl)
  return token, agent_id
end


local function fetch_secret_from_vault(conf, token)
  local cache_key = fmt("secret:%s:%s", conf.vault_id, conf.secret_path)

  local cached = secret_cache:get(cache_key)
  if cached then
    kong.log.set_serialize_value("ai.1claw.cache_hit", true)
    return cached
  end

  kong.log.set_serialize_value("ai.1claw.cache_hit", false)

  local httpc = make_http_client(conf)
  local url = fmt("%s/v1/vaults/%s/secrets/%s", conf.oneclaw_api_base, conf.vault_id, conf.secret_path)

  local start_time = ngx_now()
  local res, err = httpc:request_uri(url, {
    method = "GET",
    headers = {
      ["Authorization"] = "Bearer " .. token,
    },
  })
  local resolve_ms = math.floor((ngx_now() - start_time) * 1000)
  kong.log.set_serialize_value("ai.1claw.resolve_latency_ms", resolve_ms)

  if not res then
    return nil, "vault fetch failed: " .. (err or "unknown")
  end

  if res.status ~= 200 then
    return nil, fmt("vault fetch returned %d", res.status)
  end

  local data = cjson.decode(res.body)
  if not data or not data.value then
    return nil, "vault response missing 'value'"
  end

  local ttl = conf.cache_ttl_seconds
  if ttl > 0 then
    secret_cache:set(cache_key, data.value, ttl)
  end

  return data.value
end


local function execute_intent(conf, token, agent_id)
  local cache_key = fmt("exec:%s:%s", agent_id or "unknown", conf.binding)

  local cached = secret_cache:get(cache_key)
  if cached then
    kong.log.set_serialize_value("ai.1claw.cache_hit", true)
    return cached
  end

  kong.log.set_serialize_value("ai.1claw.cache_hit", false)

  local httpc = make_http_client(conf)

  -- Build the execute request from the incoming Kong request
  local method = kong.request.get_method()
  local path = kong.request.get_path()
  local query = kong.request.get_raw_query()
  if query and query ~= "" then
    path = path .. "?" .. query
  end

  local req_headers = kong.request.get_headers()
  -- Strip hop-by-hop and Kong internal headers
  req_headers["host"] = nil
  req_headers["connection"] = nil
  req_headers["transfer-encoding"] = nil

  local req_body = kong.request.get_raw_body()

  local execute_body = {
    binding = conf.binding,
    intent_type = conf.intent_type,
    params = {
      method = method,
      path = path,
      headers = req_headers,
    },
  }
  if req_body and req_body ~= "" then
    execute_body.params.body = req_body
  end

  local url = fmt("%s/v1/agents/%s/execute", conf.oneclaw_api_base, agent_id)

  local start_time = ngx_now()
  local res, err = httpc:request_uri(url, {
    method = "POST",
    headers = {
      ["Authorization"] = "Bearer " .. token,
      ["Content-Type"] = "application/json",
    },
    body = cjson.encode(execute_body),
  })
  local resolve_ms = math.floor((ngx_now() - start_time) * 1000)
  kong.log.set_serialize_value("ai.1claw.resolve_latency_ms", resolve_ms)

  if not res then
    return nil, "execute request failed: " .. (err or "unknown")
  end

  if res.status ~= 200 then
    return nil, fmt("execute returned %d", res.status)
  end

  local data = cjson.decode(res.body)
  if not data then
    return nil, "execute: invalid JSON response"
  end

  if data.status ~= "success" then
    return nil, fmt("execute status: %s, error: %s", data.status or "unknown", data.error or "none")
  end

  return data.result
end


local function inject_secret(conf, secret_value)
  local value = secret_value
  if conf.injection_prefix and conf.injection_prefix ~= "" then
    value = conf.injection_prefix .. value
  end

  if conf.injection_target == "header" then
    kong.service.request.set_header(conf.injection_key, value)
  elseif conf.injection_target == "query" then
    local args = kong.request.get_query()
    args[conf.injection_key] = value
    kong.service.request.set_query(args)
  elseif conf.injection_target == "body" then
    local body = kong.request.get_raw_body() or ""
    local parsed = {}
    if body ~= "" then
      parsed = cjson.decode(body) or {}
    end
    parsed[conf.injection_key] = value
    kong.service.request.set_raw_body(cjson.encode(parsed))
    kong.service.request.set_header("Content-Type", "application/json")
  end
end


function OneclawVaultAuth:access(conf)
  kong.log.set_serialize_value("ai.1claw.plugin_version", self.VERSION)
  kong.log.set_serialize_value("ai.1claw.mode", conf.mode)

  -- Step 1: Get an agent JWT
  local token, agent_id, token_err = get_agent_token(conf)
  if not token then
    kong.log.err("[1claw-vault-auth] token exchange failed: ", token_err)
    kong.log.set_serialize_value("ai.1claw.status", "token_error")
    if conf.fail_mode == "close" then
      return kong.response.exit(502, { message = "upstream credential resolution failed" })
    end
    return -- fail open: proceed without injection
  end

  kong.log.set_serialize_value("ai.1claw.agent_id", agent_id)

  if conf.mode == "vault" then
    -- Step 2a: Fetch raw secret and inject
    local secret_value, fetch_err = fetch_secret_from_vault(conf, token)
    if not secret_value then
      kong.log.err("[1claw-vault-auth] secret fetch failed: ", fetch_err)
      kong.log.set_serialize_value("ai.1claw.status", "fetch_error")
      if conf.fail_mode == "close" then
        return kong.response.exit(502, { message = "upstream credential resolution failed" })
      end
      return
    end

    inject_secret(conf, secret_value)
    kong.log.set_serialize_value("ai.1claw.status", "injected")
    kong.log.set_serialize_value("ai.1claw.secret_path", conf.secret_path)

  elseif conf.mode == "execute" then
    -- Step 2b: Execute intent (1Claw makes the upstream call)
    local result, exec_err = execute_intent(conf, token, agent_id)
    if not result then
      kong.log.err("[1claw-vault-auth] execute failed: ", exec_err)
      kong.log.set_serialize_value("ai.1claw.status", "execute_error")
      if conf.fail_mode == "close" then
        return kong.response.exit(502, { message = "upstream credential resolution failed" })
      end
      return
    end

    -- In execute mode, return the 1Claw response directly to the client.
    -- Kong does not proxy upstream; 1Claw already did.
    local response_status = 200
    local response_body = result
    if type(result) == "table" then
      if result.status_code then
        response_status = result.status_code
      end
      response_body = cjson.encode(result.body or result)
    else
      response_body = tostring(result)
    end

    kong.log.set_serialize_value("ai.1claw.status", "executed")
    kong.log.set_serialize_value("ai.1claw.binding", conf.binding)
    return kong.response.exit(response_status, response_body, {
      ["Content-Type"] = "application/json",
    })
  end
end


return OneclawVaultAuth
