-- load the base plugin object
local BasePlugin = require "kong.plugins.base_plugin"
local responses = require "kong.tools.responses"
local constants = require "kong.constants"

-- local header_filter = require "kong.plugins.token-validation.header_filter"
-- local access = require "kong.plugins.token-validation.access"

local http = require "resty.http"

local cjson = require "cjson.safe"
local pl_stringx = require "pl.stringx"

local string_format = string.format
local ngx_re_gmatch = ngx.re.gmatch

local req_set_header = ngx.req.set_header
local req_get_headers = ngx.req.get_headers
local clear_header = ngx.req.clear_header
local ngx_req_read_body = ngx.req.read_body
local get_method = ngx.req.get_method

local set_uri_args = ngx.req.set_uri_args
local get_uri_args = ngx.req.get_uri_args

local ngx_log = ngx.log


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
  ngx.log(ngx.ERR, "============ Oauth Plugin Executing! ============")
   
  ngx.log(ngx.ERR, "============ plugin_conf.header_name! ============" .. plugin_conf.header_name)
  
  ngx.log(ngx.ERR, "============ ngx.var.uri! ============" .. ngx.var.uri)
 
  
  local login_uri = "/iam/v1/oauth/authenticate"
  local request_uri = ngx.var.uri
  
  if request_uri ~= login_uri then
    ngx.log(ngx.ERR, "============ excuting if block ============")
  
      -- local authorization_header = request.get_headers()["x-authorization"]
      local authorization_header = req_get_headers()["x-authorization"]
    
      ngx.log(ngx.ERR, "============ authorization_header ============" .. authorization_header)
      
        if not authorization_header then 
          -- throw error here
        ngx.log(ngx.ERR, "============exiting if block bz authorization_header is null ============" .. authorization_header)
          return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
    
        else  
          -- send token validation API call
         --[[ local httpc = http:new()
          local url = "http://54.169.6.248:8000/iam/v1/oauth/" .. authorization_header .. "/validate"
          ngx.log(ngx.ERR, "============Oauth token validating url ============" .. url)
          local res, err = httpc:request_uri(url, {
            method = "POST",
            --ssl_verify = false,
            headers = {
                ["Content-Type"] = "application/json",
              }
          
          })
      --]]
      
      local httpc = http:new()
          local url = "http://54.169.6.248:8000/m"
          ngx.log(ngx.ERR, "============Oauth token validating url ============" .. url)
          local res, err = httpc:request_uri(url, {
            method = "GET",
            --ssl_verify = false         
          })
      
         
      ngx.log(ngx.ERR, "============ Response ============ " .. res)
          
        if res.status ~= 200 then
           ngx.status = 401
           ngx.header.content_type = 'application/json'
           ngx.print('{"error":"not authorized"}')
           ngx.exit(401)
        end
        
        --[[
        if not res then
            ngx.status = res.status
            ngx.say("failed to request: ", err)
            ngx.exit(ngx.HTTP_OK)
        end
        --]]
        
        local json = cjson.decode(res.body)
        local statusCode = json.data.statusCode
        local isValid = json.data.valid
        
      ngx.log(ngx.ERR, "============ statusCode ============" .. statusCode .. "isValid  - " .. isValid)
        ngx.say("statusCode - " .. statusCode)
        ngx.print("statusCode - " .. statusCode)
        
        ngx.say("isValid - " .. isValid)
        ngx.print("isValid - " .. isValid)
        
        ngx.say("response - " .. res)
        ngx.print("json response - " .. json)
        
        
        if not statusCode and isValid  then
            ngx.status = 501
            ngx.say("failed to request....")
            ngx.exit(ngx.HTTP_OK)
        end
        
        if statusCode ~= 200 and isValid ~= true then
          ngx.status = 401
          ngx.header.content_type = 'application/json'
          ngx.print('{"error":"not authorized"}')
          ngx.exit(401)
        end
        
        
        
        end
   
  end
    
end

  
--[[function plugin:header_filter(plugin_conf) -- Executed when all response headers bytes have been received from the upstream service.
  plugin.super.header_filter(self)
  -- custom code for setting values in header
  -- header_filter.execute(conf)
  -- ngx.header["custom-header"] = "/json: " .. authorization_header .. "/json: " .. json .. "/request_uri: " .. request_uri;
  end 
--]]
  
return plugin
