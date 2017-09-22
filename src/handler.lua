-- load the base plugin object
local BasePlugin = require "kong.plugins.base_plugin"

-- local header_filter = require "kong.plugins.token-validation.header_filter"
local access = require "kong.plugins.glp-token-validate.access"

-- creating a subclass 
local plugin = BasePlugin:extend()
plugin.PRIORITY = 2

-- constructor
function plugin:new()
  plugin.super.new(self, "glp-token-validate")
  end
  
function plugin:access(plugin_conf) -- Executed for every request upon it's reception from a client and before it is being proxied to the upstream service.
  plugin.super.access(self)
  access.run(plugin_conf) -- `execute()` and passing it the plugin's configuration.
end

return plugin
