package = "glp-token-validate"  
                                  
version = "1.1-1"     -- renumber, must match the info in the filename of this rockspec!
                      -- The version '0.1.0' is the source code version, the trailing '1' is the version of this rockspec.
                      -- whenever the source version changes, the rockspec should be reset to 1. The rockspec version is only
                      -- updated (incremented) when this file changes, but the source remains the same.

-- supported_platforms = {"linux", "macosx"}

source = {
  url = "git://github.com/vikaskmr1008/glp-token-validate"
  -- tag = "1.1-1"
}

description = {
  summary = "A Kong plugin, that validate expiry of oauth token",
  license = "Apache 2.0"
}

dependencies = {
  "lua >= 5.1"
  -- If you depend on other rocks, add them here
}

-- local pluginName = "glp-token-validate"
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.glp-token-validate.access"] = "src/access.lua",
    ["kong.plugins.glp-token-validate.handler"] = "src/handler.lua",
    ["kong.plugins.glp-token-validate.schema"] = "src/schema.lua"
  }
}
