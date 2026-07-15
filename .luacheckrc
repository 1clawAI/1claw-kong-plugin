std = "ngx_lua+busted"
max_line_length = false

globals = {
  "kong",
  "ngx",
}

read_globals = {
  "describe",
  "it",
  "before_each",
  "after_each",
  "setup",
  "teardown",
  "assert",
  "spy",
  "stub",
  "mock",
  "finally",
}

exclude_files = {
  "spec/integration/",
}
