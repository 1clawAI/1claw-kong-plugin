local typedefs = require "kong.db.schema.typedefs"

local PLUGIN_NAME = "1claw-vault-auth"

return {
  name = PLUGIN_NAME,
  fields = {
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          -- 1Claw agent credentials (referenceable so they can use vault://)
          {
            agent_api_key = {
              type = "string",
              required = true,
              referenceable = true,
              encrypted = true,
            },
          },
          {
            agent_id = {
              type = "string",
              required = false,
              referenceable = true,
            },
          },
          {
            oneclaw_api_base = {
              type = "string",
              default = "https://api.1claw.xyz",
            },
          },

          -- Mode: "vault" fetches a raw secret and injects it.
          -- "execute" calls Execution Intents (1Claw makes the upstream call).
          {
            mode = {
              type = "string",
              default = "vault",
              one_of = { "vault", "execute" },
            },
          },

          -- Vault mode fields
          {
            vault_id = {
              type = "string",
              required = false,
            },
          },
          {
            secret_path = {
              type = "string",
              required = false,
            },
          },

          -- Execute mode fields
          {
            binding = {
              type = "string",
              required = false,
            },
          },
          {
            intent_type = {
              type = "string",
              default = "http",
            },
          },

          -- Injection (vault mode only)
          {
            injection_target = {
              type = "string",
              default = "header",
              one_of = { "header", "query", "body" },
            },
          },
          {
            injection_key = {
              type = "string",
              default = "Authorization",
            },
          },
          {
            injection_prefix = {
              type = "string",
              required = false,
            },
          },

          -- Caching
          {
            cache_ttl_seconds = {
              type = "number",
              default = 60,
              between = { 0, 86400 },
            },
          },

          -- Resilience
          {
            fail_mode = {
              type = "string",
              default = "close",
              one_of = { "close", "open" },
            },
          },
          {
            connect_timeout_ms = {
              type = "number",
              default = 2000,
              between = { 100, 30000 },
            },
          },
          {
            read_timeout_ms = {
              type = "number",
              default = 3000,
              between = { 100, 30000 },
            },
          },
        },

        entity_checks = {
          {
            conditional = {
              if_field = "mode",
              if_match = { eq = "vault" },
              then_field = "vault_id",
              then_match = { required = true },
            },
          },
          {
            conditional = {
              if_field = "mode",
              if_match = { eq = "vault" },
              then_field = "secret_path",
              then_match = { required = true },
            },
          },
          {
            conditional = {
              if_field = "mode",
              if_match = { eq = "execute" },
              then_field = "binding",
              then_match = { required = true },
            },
          },
        },
      },
    },
  },
}
