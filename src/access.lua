local _M = {}

local http = require "resty.http"
local cjson = require "cjson"
local req_get_headers = ngx.req.get_headers

function _M.run(plugin_conf)

  local request_uri = ngx.var.uri
  
  if request_uri ~= plugin_conf.login_uri then
      local authorization_header = req_get_headers()["x-authorization"]

       if not authorization_header then 
          invalidRequest()
        else  
          -- execute token validation API call
          local httpc = http:new()
          local url = plugin_conf.token_validate_url .. authorization_header .. "/validate"
          ngx.log(ngx.ERR, url)
      
          local res, err = httpc:request_uri(url, {
            method = "POST",
            --ssl_verify = false,
            headers = {
                ["Content-Type"] = "application/json",
                ["CorrelationId"] = "12345"
              }
          })
        
        local json = cjson.decode(res.body)
      
        local statusCode = json.data.statusCode
        local isValid = json.data.valid
        
        ngx.log(ngx.ERR, statusCode)
        ngx.log(ngx.ERR, isValid)
        
        if not statusCode and isValid  then
          invalidRequest()
        end
        
        if statusCode ~= 200 and isValid ~= true then
          invalidRequest()
        end
        
       end
   
  end
 
 end -- ending M_execute function
 
 function invalidRequest()
     ngx.status = 400
     ngx.header.content_type = 'application/json'
     ngx.print('{"status": 401, "errors": [{"status": 401, "code": "BAD_REQUEST", "message": "Access Denied"}]}')
     ngx.exit(400)
 
 end
 
 return _M