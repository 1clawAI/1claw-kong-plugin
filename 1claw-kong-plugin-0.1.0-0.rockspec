local plugin_name = "1claw-vault-auth"
local package_name = "1claw-kong-plugin"
local package_version = "0.1.0"
local rockspec_revision = "0"

package = package_name
version = package_version .. "-" .. rockspec_revision

source = {
  url = "git+https://github.com/1clawAI/1claw-kong-plugin.git",
  tag = "v" .. package_version,
}

description = {
  summary = "Kong Gateway plugin for just-in-time credential injection from 1Claw Vault",
  detailed = [[
    1claw-vault-auth resolves short-TTL credentials from 1Claw's HSM/MPC-backed
    vault at proxy time and injects them into upstream requests. The raw secret
    never appears in Kong's plugin config, logs, analytics, or error responses.
  ]],
  homepage = "https://github.com/1clawAI/1claw-kong-plugin",
  license = "MIT",
}

dependencies = {
  "lua >= 5.1",
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins." .. plugin_name .. ".handler"] = "kong/plugins/" .. plugin_name .. "/handler.lua",
    ["kong.plugins." .. plugin_name .. ".schema"] = "kong/plugins/" .. plugin_name .. "/schema.lua",
  },
}
