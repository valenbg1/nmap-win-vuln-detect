local http = require "http"
--local httpspider = require "httpspider"
--local nmap = require "nmap"
--local shortport = require "shortport"
local stdnse = require "stdnse"
--local tab = require "tab"
local table = require "table"
local smb = require "smb"
local smb2 = require "smb2"
local url = require "url"


description = [[
NMAP NSE script that detects potential recent vulnerabilities published by Microsoft in Windows machines.
]]


---
-- @usage
-- nmap --script winVulnDetection --script-args "csvPath=<path>" <target>
--
-- @usageExample
-- nmap --script=./winVulnDetection.nse --script-args "csvPath=./vulns.csv" localhost
--
-- @output
--
---


author = "Ignacio Marín & Valentín Blanco"
categories = {"discovery", "safe"}


hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host)
  local uptime_server = fechaServer(host)
  local csvPath = stdnse.get_script_args("csvPath")
  local output = stdnse.output_table()
  local lineasCsv = readCsv(csvPath)
  
  stdnse.debug("CSV path: %s", csvPath)
  stdnse.debug("Host uptime: %s", os.date("%x", uptime_server))
  
  -- TODO: for urls en csv coger fecha url y comparar.
  for n, linea in pairs(lineasCsv) do
    if n ~= 1 then
      local bulletinId = linea[1]
      local restartRequired = linea[3]
      local pubDate = linea[5]
      
      stdnse.debug("%s CSV publication date: %s", bulletinId, pubDate)
      stdnse.debug("%s Microsoft last update date: %s", bulletinId, os.date("%x", getDate(linea[4])))
      
      if restartRequired:lower() == "yes" and not serverActualizado(uptime_server, toDate(pubDate)) then
        output[bulletinId] = stdnse.output_table()
		output[bulletinId].severity = linea[2]
		output[bulletinId].restartRequired = restartRequired
		output[bulletinId].link = linea[4]
		output[bulletinId].publicationDate = pubDate
		output[bulletinId].summary = linea[6]
      else
        stdnse.debug("Host not vulnerable to %s, with publication date: %s and restart required: %s", bulletinId,
		  pubDate, restartRequired)
      end
    end 
  end
  
  return output
end

-- Función que devuelve fecha en formato os.time de uptime del servidor obtenida según smb2.time.nse
function fechaServer(host)
  local smbstate, status, overrides
  overrides = {}
  status, smbstate = smb.start(host)
  status = smb2.negotiate_v2(smbstate, overrides)

  if status then
    stdnse.debug("SMB2: Date: %s (%s) Start date:%s (%s)",
                  smbstate['date'], smbstate['time'],
                  smbstate['start_date'], smbstate['start_time'])
    stdnse.debug("Negotiation suceeded")

    return toDate(smbstate['start_date'])
  else
    return "Protocol negotiation failed (SMB2)"
  end
end

-- Función que devuelve un objeto os.time a partir del string de fecha obtenido de la web o por SMB2.
function toDate(dateStr)
  local m, d, y

  if string.find(dateStr, "-") then
    local it = string.gmatch(dateStr, "[^-%s]+")
    y = tonumber(it())
    m = tonumber(it())
    d = tonumber(it())
  else
    local it = string.gmatch(dateStr, "%S+")
    m = it():lower()
    d = tonumber(it():sub(1, -2))
    y = tonumber(it())
    
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
  end

  return os.time{day=d, year=y, month=m}
end

--Función que devuelve un booleano tras pasarle la fecha de uptime del server y del boletín, ambas en formato os.time
--Ej:
--fechaServer = os.time{day=15, year=2017, month=2}
--fechaBoletin = os.time{day=15, year=2016, month=2}
--serverActualizado(fechaServer,fechaBoletin)
--Devuelve true
function serverActualizado(fechaServer, fechaBoletin)
  return os.difftime(fechaServer, fechaBoletin) >= 0
end

-- Función que dada una URL de boletín de Microsoft extrae la fecha más reciente.
function getDate(url)
  local urlBody = http.get_url(url).body
  
  -- Se saca la fecha de la web.
  local pubDate = string.match(urlBody, "[Pp]ublished:%s(%a+%s%d+,%s%d+)")
  local updDate = string.match(urlBody, "[Uu]pdated:%s(%a+%s%d+,%s%d+)")
  
  if updDate then
    return toDate(updDate)
  else
    return toDate(pubDate)
  end
end

-- Code added for parsing csv
-- Usage: 
--
-- local file = "vulns.csv" 
-- local lineas = readCsv(file)
-- for i, v in ipairs(lineas) do print(i, v[5]) end
-- -- dates are 5
-- print(lineas[2][5])
function readCsv(file)
  local lIt = assert(io.lines(file))
  local values = {}
  
  for l in lIt do
    local vuln = {}
    
    for v in string.gmatch(l, "[^;]+") do
      table.insert(vuln, v)
    end
    
    table.insert(values, vuln)
  end
  
  return values
end