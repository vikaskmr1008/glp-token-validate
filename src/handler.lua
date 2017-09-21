-- load the base plugin object
local BasePlugin = require "kong.plugins.base_plugin"
local http = require "resty.http"
local cjson = require "cjson"
-- local header_filter = require "kong.plugins.token-validation.header_filter"
-- local access = require "kong.plugins.token-validation.access"

-- creating a subclass 
local plugin = BasePlugin:extend()
plugin.PRIORITY = 2

-- constructor
function plugin:new()
  plugin.super.new(self, "oauth-token-validate")
  end
  
function plugin:access(plugin_conf) -- Executed for every request upon it's reception from a client and before it is being proxied to the upstream service.
  plugin.super.access(self)

  -- access.execute(conf)
  ngx.log(ngx.ERR, "============ plugin_conf.header_name! ============" .. plugin_conf.login_uri)
  ngx.log(ngx.ERR, "============ plugin_conf.header_name! ============" .. plugin_conf.token_validate_url)
  ngx.log(ngx.ERR, "============ ngx.var.uri! ============" .. ngx.var.uri)
  
  local login_uri = plugin_conf.login_uri
  local request_uri = ngx.var.uri
  
  if request_uri ~= login_uri then
      -- local authorization_header = request.get_headers()["x-authorization"]
      local authorization_header = req_get_headers()["x-authorization"]

       if not authorization_header then 
          -- throw error here
          return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
        else  
          -- send token validation API call
          local httpc = http:new()
          --local url = "http://iam_con.weave.local:9049/iam/v1/oauth/" .. authorization_header .. "/validate"
          local url = plugin_conf.token_validate_url .. authorization_header .. "/validate"
          ngx.log(ngx.ERR, url)
      
          local res, err = httpc:request_uri(url, {
            method = "POST",
            --ssl_verify = false,
            headers = {
                ["Content-Type"] = "application/json",
                ["CorrelationId"] = "123"
              }
          
          })
        
        local json = cjson.decode(res.body)
      
        local statusCode = json.data.statusCode
        local isValid = json.data.valid
        
        ngx.log(ngx.ERR, statusCode)
        ngx.log(ngx.ERR, isValid)
        
        if not statusCode and isValid  then
            ngx.status = 501
            ngx.say("failed to request....")
            ngx.exit(ngx.HTTP_OK)
        end
        
        if statusCode ~= 200 and isValid ~= true then
          ngx.status = 419
          ngx.header.content_type = 'application/json'
          ngx.print('{"errorDescription": "You have been signed out due to lack of activity. To continue using your account, please sign in again.", "statusCode": 419, "valid": false}')
          ngx.exit(419)
        end
        
        end
   
  end
    
end

return plugin
