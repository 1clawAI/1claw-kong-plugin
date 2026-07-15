local cjson = require "cjson"

-- Minimal mocks for Kong PDK and dependencies
local captured_logs = {}
local captured_serialize = {}
local captured_headers = {}
local captured_query = {}
local captured_body = nil
local captured_exit = nil

local function reset_mocks()
  captured_logs = {}
  captured_serialize = {}
  captured_headers = {}
  captured_query = {}
  captured_body = nil
  captured_exit = nil
end

-- Mock kong global
local mock_kong = {
  log = {
    err = function(...)
      table.insert(captured_logs, table.concat({...}, ""))
    end,
    warn = function(...)
      table.insert(captured_logs, table.concat({...}, ""))
    end,
    set_serialize_value = function(key, val)
      captured_serialize[key] = val
    end,
  },
  service = {
    request = {
      set_header = function(name, value)
        captured_headers[name] = value
      end,
      set_query = function(args)
        captured_query = args
      end,
      set_raw_body = function(body)
        captured_body = body
      end,
    },
  },
  request = {
    get_method = function() return "GET" end,
    get_path = function() return "/v1/test" end,
    get_raw_query = function() return "" end,
    get_headers = function() return { ["accept"] = "application/json" } end,
    get_raw_body = function() return "" end,
    get_query = function() return {} end,
  },
  response = {
    exit = function(status, body, headers)
      captured_exit = { status = status, body = body, headers = headers }
    end,
  },
}

-- Mock resty.http
local mock_http_responses = {}
local mock_http = {
  new = function()
    return {
      set_timeouts = function() end,
      request_uri = function(self, url, opts)
        for _, entry in ipairs(mock_http_responses) do
          if url:find(entry.pattern, 1, true) then
            return entry.response, entry.err
          end
        end
        return nil, "no mock for URL: " .. url
      end,
    }
  end,
}

-- Mock resty.lrucache with a simple table
local mock_lru_store = {}
local mock_lrucache = {
  new = function()
    return {
      get = function(self, key)
        local entry = mock_lru_store[key]
        if entry and entry.expires_at > ngx.now() then
          return entry.value
        end
        mock_lru_store[key] = nil
        return nil
      end,
      set = function(self, key, value, ttl)
        mock_lru_store[key] = { value = value, expires_at = ngx.now() + (ttl or 60) }
      end,
    }, nil
  end,
}

-- Install mocks
package.loaded["resty.http"] = mock_http
package.loaded["resty.lrucache"] = mock_lrucache
package.loaded["cjson.safe"] = cjson

-- Mock ngx
_G.ngx = _G.ngx or {}
ngx.now = ngx.now or function() return os.time() end

-- Mock kong global
_G.kong = mock_kong

-- Load handler
local handler = require "kong.plugins.1claw-vault-auth.handler"


describe("1claw-vault-auth handler", function()

  before_each(function()
    reset_mocks()
    mock_http_responses = {}
    mock_lru_store = {}
  end)


  describe("vault mode", function()
    local base_conf = {
      agent_api_key = "ocv_test_key_123",
      agent_id = "agent-uuid-1234",
      oneclaw_api_base = "https://api.1claw.xyz",
      mode = "vault",
      vault_id = "vault-uuid-5678",
      secret_path = "integrations/stripe-key",
      binding = "",
      intent_type = "http",
      injection_target = "header",
      injection_key = "Authorization",
      injection_prefix = "Bearer ",
      cache_ttl_seconds = 60,
      fail_mode = "close",
      connect_timeout_ms = 2000,
      read_timeout_ms = 3000,
    }

    it("fetches token, fetches secret, injects header on cache miss", function()
      mock_http_responses = {
        {
          pattern = "/v1/auth/agent-token",
          response = {
            status = 200,
            body = cjson.encode({
              access_token = "jwt_token_abc",
              agent_id = "agent-uuid-1234",
              expires_in = 3600,
            }),
          },
        },
        {
          pattern = "/v1/vaults/vault-uuid-5678/secrets/integrations/stripe-key",
          response = {
            status = 200,
            body = cjson.encode({
              value = "sk_live_secret_value_xyz",
              path = "integrations/stripe-key",
            }),
          },
        },
      }

      handler:access(base_conf)

      assert.is_nil(captured_exit)
      assert.equals("Bearer sk_live_secret_value_xyz", captured_headers["Authorization"])
      assert.equals("injected", captured_serialize["ai.1claw.status"])
      assert.equals(false, captured_serialize["ai.1claw.cache_hit"])
    end)

    it("uses cached secret on second call", function()
      -- Seed the cache
      mock_lru_store["token:ocv_test_key_123"] = {
        value = { token = "jwt_cached", agent_id = "agent-uuid-1234" },
        expires_at = ngx.now() + 3000,
      }
      mock_lru_store["secret:vault-uuid-5678:integrations/stripe-key"] = {
        value = "sk_cached_value",
        expires_at = ngx.now() + 60,
      }

      handler:access(base_conf)

      assert.is_nil(captured_exit)
      assert.equals("Bearer sk_cached_value", captured_headers["Authorization"])
      assert.equals(true, captured_serialize["ai.1claw.cache_hit"])
    end)

    it("returns 502 on token failure with fail_mode=close", function()
      mock_http_responses = {
        {
          pattern = "/v1/auth/agent-token",
          response = { status = 401, body = '{"error":"unauthorized"}' },
        },
      }

      handler:access(base_conf)

      assert.is_not_nil(captured_exit)
      assert.equals(502, captured_exit.status)
      assert.equals("upstream credential resolution failed", captured_exit.body.message)
      assert.equals("token_error", captured_serialize["ai.1claw.status"])
    end)

    it("proceeds without injection on token failure with fail_mode=open", function()
      local open_conf = {}
      for k, v in pairs(base_conf) do open_conf[k] = v end
      open_conf.fail_mode = "open"

      mock_http_responses = {
        {
          pattern = "/v1/auth/agent-token",
          response = { status = 500, body = "" },
        },
      }

      handler:access(open_conf)

      assert.is_nil(captured_exit)
      assert.is_nil(captured_headers["Authorization"])
      assert.equals("token_error", captured_serialize["ai.1claw.status"])
    end)

    it("returns 502 on vault fetch failure with fail_mode=close", function()
      mock_http_responses = {
        {
          pattern = "/v1/auth/agent-token",
          response = {
            status = 200,
            body = cjson.encode({ access_token = "jwt_ok", agent_id = "a1", expires_in = 3600 }),
          },
        },
        {
          pattern = "/v1/vaults/",
          response = { status = 403, body = '{"detail":"forbidden"}' },
        },
      }

      handler:access(base_conf)

      assert.is_not_nil(captured_exit)
      assert.equals(502, captured_exit.status)
      assert.equals("fetch_error", captured_serialize["ai.1claw.status"])
    end)

    it("injects into query param when injection_target=query", function()
      local query_conf = {}
      for k, v in pairs(base_conf) do query_conf[k] = v end
      query_conf.injection_target = "query"
      query_conf.injection_key = "api_key"
      query_conf.injection_prefix = ""

      mock_http_responses = {
        {
          pattern = "/v1/auth/agent-token",
          response = {
            status = 200,
            body = cjson.encode({ access_token = "jwt_ok", agent_id = "a1", expires_in = 3600 }),
          },
        },
        {
          pattern = "/v1/vaults/",
          response = {
            status = 200,
            body = cjson.encode({ value = "key_123" }),
          },
        },
      }

      handler:access(query_conf)

      assert.is_nil(captured_exit)
      assert.equals("key_123", captured_query["api_key"])
    end)

    it("injects into JSON body when injection_target=body", function()
      local body_conf = {}
      for k, v in pairs(base_conf) do body_conf[k] = v end
      body_conf.injection_target = "body"
      body_conf.injection_key = "token"
      body_conf.injection_prefix = ""

      mock_http_responses = {
        {
          pattern = "/v1/auth/agent-token",
          response = {
            status = 200,
            body = cjson.encode({ access_token = "jwt_ok", agent_id = "a1", expires_in = 3600 }),
          },
        },
        {
          pattern = "/v1/vaults/",
          response = {
            status = 200,
            body = cjson.encode({ value = "tok_abc" }),
          },
        },
      }

      handler:access(body_conf)

      assert.is_nil(captured_exit)
      assert.is_not_nil(captured_body)
      local parsed = cjson.decode(captured_body)
      assert.equals("tok_abc", parsed.token)
    end)

    -- CRITICAL: The core security property of this plugin
    it("NEVER leaks the secret value into kong log output", function()
      local secret_fixture = "sk_live_SUPER_SECRET_MUST_NEVER_LEAK"

      mock_http_responses = {
        {
          pattern = "/v1/auth/agent-token",
          response = {
            status = 200,
            body = cjson.encode({ access_token = "jwt_ok", agent_id = "a1", expires_in = 3600 }),
          },
        },
        {
          pattern = "/v1/vaults/",
          response = {
            status = 200,
            body = cjson.encode({ value = secret_fixture }),
          },
        },
      }

      handler:access(base_conf)

      -- Check captured logs for the secret value
      local all_logs = table.concat(captured_logs, "\n")
      assert.is_nil(string.find(all_logs, secret_fixture, 1, true),
        "SECRET VALUE LEAKED INTO LOGS: " .. secret_fixture)

      -- Check serialize values for the secret value
      for key, val in pairs(captured_serialize) do
        if type(val) == "string" then
          assert.is_nil(string.find(val, secret_fixture, 1, true),
            "SECRET VALUE LEAKED INTO SERIALIZE KEY '" .. key .. "'")
        end
      end
    end)
  end)


  describe("execute mode", function()
    local exec_conf = {
      agent_api_key = "ocv_exec_key",
      agent_id = "agent-exec-1",
      oneclaw_api_base = "https://api.1claw.xyz",
      mode = "execute",
      vault_id = "",
      secret_path = "",
      binding = "stripe-api",
      intent_type = "http",
      injection_target = "header",
      injection_key = "Authorization",
      injection_prefix = "",
      cache_ttl_seconds = 0,
      fail_mode = "close",
      connect_timeout_ms = 2000,
      read_timeout_ms = 5000,
    }

    it("calls execute endpoint and returns result to client", function()
      mock_http_responses = {
        {
          pattern = "/v1/auth/agent-token",
          response = {
            status = 200,
            body = cjson.encode({ access_token = "jwt_exec", agent_id = "agent-exec-1", expires_in = 3600 }),
          },
        },
        {
          pattern = "/v1/agents/agent-exec-1/execute",
          response = {
            status = 200,
            body = cjson.encode({
              execution_id = "exec-uuid-1",
              status = "success",
              duration_ms = 120,
              redactions_applied = 0,
              result = { data = { customers = {} } },
            }),
          },
        },
      }

      handler:access(exec_conf)

      assert.is_not_nil(captured_exit)
      assert.equals(200, captured_exit.status)
      assert.equals("executed", captured_serialize["ai.1claw.status"])
    end)

    it("returns 502 when execute returns error status", function()
      mock_http_responses = {
        {
          pattern = "/v1/auth/agent-token",
          response = {
            status = 200,
            body = cjson.encode({ access_token = "jwt_exec", agent_id = "agent-exec-1", expires_in = 3600 }),
          },
        },
        {
          pattern = "/v1/agents/",
          response = {
            status = 200,
            body = cjson.encode({
              execution_id = "exec-uuid-2",
              status = "denied",
              duration_ms = 5,
              redactions_applied = 0,
              error = "SSRF blocked",
            }),
          },
        },
      }

      handler:access(exec_conf)

      assert.is_not_nil(captured_exit)
      assert.equals(502, captured_exit.status)
      assert.equals("execute_error", captured_serialize["ai.1claw.status"])
    end)
  end)
end)
