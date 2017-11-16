local http = require "http"
local httpspider = require "httpspider"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"
local smb = require "smb"
local smb2 = require "smb2"
local url = require "url"


description = [[
NMAP NSE script that detects potential recent vulnerabilities published by Microsoft in Windows machines.
]]


--- 
-- Script inspired on http-auth-finder
--
-- @usage
-- nmap --script winVulnDetection --script-args 'csvPath=<path>' <target>
-- @usageExample
-- nmap --script=./winVulnDetection.nse --script-args 'csvPath=./vulns.csv' localhost
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |   datesSearch:
-- |   http://localhost/4-Microsoft%20Security%20Bulletin%20Summary%20for%20March%202017.html    FORM
-- |   2017-11-09                                                                                DATE
---


author = "Ignacio Marín & Valentín Blanco"
categories = {"discovery", "safe"}


hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host)
  local fecha_server = fechaServer(host)
  local csvPath = stdnse.get_script_args("csvPath")
  local output = stdnse.output_table()
  local lineasCsv = lines_from(csvPath)
  
  stdnse.debug("Server date: %s", os.date("%x", fecha_server))
  stdnse.debug("CSV path: %s", csvPath)
  
  -- TODO: for urls en csv coger fecha url y comparar.
  for k, linea in pairs(lineasCsv) do
    if k ~= 1 then
      local pubDate, bulletinId
      pubDate = linea[5]
      --print("DATE"..date)
      bulletinId = linea[1]
      
      if not serverActualizado(fecha_server, toDate(pubDate)) then
        output[bulletinId] = "VULNERABLE!"
      else
        stdnse.debug("Host not vulnerable to %s", bulletinId)
      end
    end 
  end
  
  return output

  -- local d = getDate("http://localhost/5-Microsoft%20Security%20Bulletin%20MS17-006.html")
  -- local fecha_url = dat(d)
  -- print("FECHA URL: "..os.date("%x",fecha_url))
  -- local isServerUpdated = serverActualizado(fecha_server,fecha_url)
  -- if isServerUpdated
  --   then print("El server está actualizado")
  -- else print("El server no está actualizado")
  -- end
end

-- Función que devuelve fecha en formato os.time de uptime del servidor obtenida según smb2.time.nse
function fechaServer(host)
  local smbstate, status, overrides, start_date
  overrides = {}
  status, smbstate = smb.start(host)
  status = smb2.negotiate_v2(smbstate, overrides)

  if status then
    stdnse.debug("SMB2: Date: %s (%s) Start date:%s (%s)",
                  smbstate['date'], smbstate['time'],
                  smbstate['start_date'], smbstate['start_time'])
    stdnse.debug("Negotiation suceeded")
    start_date = string.sub(smbstate['start_date'], 1, 10)
    
    -- TODO se ha probado con p.e. días que no sean de dos dígitos (3/2/1999)?
    return os.time{day=tonumber(string.sub(start_date, 9, 10)), year=tonumber(string.sub(start_date, 1, 4)), month=tonumber(string.sub(start_date, 6, 7))}
  else
    return "Protocol negotiation failed (SMB2)"
  end
end

-- Función que devuelve un objeto os.time a partir del string de fecha obtenido de la web.
function toDate(dateStr)
  local it = string.gmatch(dateStr, "%S+")
  local m = it():lower()
  local d = tonumber(it():sub(1, -2))
  local y = tonumber(it())

  if (m == "january")
    then m = 1
  elseif (m == "february")
    then m = 2
  elseif (m == "march")
    then m = 3
  elseif (m == "april")
    then m = 4
  elseif (m == "may")
    then m = 5
  elseif (m == "june")
    then m = 6
  elseif (m == "july")
    then m = 7
  elseif (m == "august")
    then m = 8
  elseif (m == "september")
    then m = 9
  elseif (m == "october")
    then m = 10
  elseif (m == "november")
    then m = 11
  elseif (m == "december")
    then m = 12
  end

  return os.time{day=d, year=y, month=m}
end

--Función que devuelve un booleano tras pasarle la fehca del server y del boletín, ambas en formato os.time
--Ej:
--fechaServer = os.time{day=15, year=2017, month=2}
--fechaBoletin = os.time{day=15, year=2016, month=2}
--serverActualizado(fechaServer,fechaBoletin)
--Devuelve true
function serverActualizado(fechaServer, fechaBoletin)
  daysfrom = os.difftime(fechaServer, fechaBoletin) / (24 * 60 * 60) -- seconds in a day
  wholedays = math.floor(daysfrom)
  --print(wholedays)
  local actualizado = true;
  if wholedays<0 
    then actualizado = false;
  end
  return actualizado
end

-- Función que dada una url (con formato que incluya el puerto) devuelve la url dividia en partes
function splitUrl(urld)
  local host, port, path
  urld = url.parse(urld)
  host = urld.authority
  --TODO: change 
  port = urld.port
  if(port==nil)
    then if(urld.scheme=="https")
        then port = "443"
       else port = "80"
       end
  end 

  local i,j 
  --print("HOSTTTTTT "..host)
  i,j = string.find(host,":")
 --print(i,j)
  if(i ~= nil)
    then host = string.sub(host,1,i-1)
  end
  path = urld.path

  local list = {host=host,path=path,port=port}

  return list
end

-- Función que dada una url de Microsoft extrae la fecha.
function getDate(url)
  --print("URL: "..url) 
  local url = splitUrl(url)
  --print("host: "..url.host.." port: "..url.port.." path: "..url.path)
  local get = http.generic_request(url.host,url.port,"GET",url.path)
  local body = get.body
  --print("Body"..body)
  --Se saca la fecha de la web
    i, j = string.find(body, "<p>Published: %u")
    k, l = string.find(body, "%a %d%d, %d%d%d%d")
    local fecha = string.sub(body, j, l)
    --print("FECHA: "..fecha)
    return fecha
end

-- Code added for parsing csv
-- Usage: 
--
-- local file = "vulns.csv" 
-- local lineas = lines_from(file)
-- for i, v in ipairs(lineas) do print(i, v[5]) end
-- -- dates are 5
-- print(lineas[2][5])
-- Code modified from https://stackoverflow.com/questions/11201262/how-to-read-data-from-a-file-in-lua
function lines_from(file)
 --print("LINES FROM")
  if not file_exists(file) then return {} end
  lines = {}
  for line in io.lines(file) do 
    --print("not empty")
    table.insert(lines, ParseCSVLine(line,";"))
  end
  return lines
end

function file_exists(file)
  local f = io.open(file, "rb")
  if f then f:close() end
  return f ~= nil
end

-- Code from http://lua-users.org/wiki/LuaCsv
function ParseCSVLine (line,sep) 
  local res = {}
  local pos = 1
  sep = sep or ','
  while true do 
    local c = string.sub(line,pos,pos)
    if (c == "") then break end
    if (c == '"') then
      -- quoted value (ignore separator within)
      local txt = ""
      repeat
        local startp,endp = string.find(line,'^%b""',pos)
        txt = txt..string.sub(line,startp+1,endp-1)
        pos = endp + 1
        c = string.sub(line,pos,pos) 
        if (c == '"') then txt = txt..'"' end 
        -- check first char AFTER quoted string, if it is another
        -- quoted string without separator, then append it
        -- this is the way to "escape" the quote char in a quote. example:
        --   value1,"blub""blip""boing",value3  will result in blub"blip"boing  for the middle
      until (c ~= '"')
      table.insert(res,txt)
      assert(c == sep or c == "")
      pos = pos + 1
    else  
      -- no quotes used, just look for the first separator
      local startp,endp = string.find(line,sep,pos)
      if (startp) then 
        table.insert(res,string.sub(line,pos,startp-1))
        pos = endp + 1
      else
        -- no separator found -> use rest of string and terminate
        table.insert(res,string.sub(line,pos))
        break
      end 
    end
  end
  return res
end