local http = require "http"
local stdnse = require "stdnse"
local smb = require "smb"
local smb2 = require "smb2"


description = [[
NMAP NSE script that detects potential recent vulnerabilities published by Microsoft in Windows machines.
]]


---
-- @usage
-- nmap --script winVulnDetection --script-args "csvPath=<path>, updateCsvFile=[yes|no]" <target>
--
-- @usageExample
-- nmap --script=./winVulnDetection.nse --script-args "csvPath=./vulns.csv, updateCsv=yes" localhost
--
-- @output
-- Host script results:
-- | winVulnDetection: 
-- |   MS17-006: 
-- |     severity: Critical
-- |     restartRequired: Yes
-- |     link: https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/MS17-006
-- |     lastUpdated: March 14, 2017
-- |     summary: Cumulative Security Update for Internet Explorer (4013073)
-- |   MS17-014: 
-- |     severity: Important
-- |     restartRequired: Yes
-- |     link: https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/MS17-014
-- |     lastUpdated: April 11, 2017
-- |_    summary: Security Update for Microsoft Office (4013241)
---


author = "Valentín Blanco & Ignacio Marín"
categories = {"discovery", "safe"}


hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host)
  local uptimeServer = smb2HostUptime(host)
  local csvPath = stdnse.get_script_args("csvPath") or "vulns.csv"
  local updateCsvFile = stdnse.get_script_args("updateCsvFile") or "yes"
  local output = stdnse.output_table()
  
  stdnse.debug("CSV path: %s", csvPath)
  stdnse.debug("Host uptime: %s", os.date("%x", uptimeServer))
  
  stdnse.debug("Reading CSV file")
  local csv = readCsv(csvPath)
  
  stdnse.debug("Updating CSV data with data from Microsoft's bulletins")
  updateCsv(csv)
  
  if updateCsvFile:lower() == "yes" then
    stdnse.debug("Saving updated CSV")
    writeCsv(csv, csvPath)
  end
  
  for i, vuln in pairs(csv) do
    if i > 1 then
      if vuln.restartRequired:lower() == "yes" and not hostUpdated(uptimeServer, toDate(vuln.lastUpdated)) then
        output[vuln.bulletinId] = stdnse.output_table()
        output[vuln.bulletinId].severity = vuln.severity
        output[vuln.bulletinId].restartRequired = vuln.restartRequired
        output[vuln.bulletinId].link = vuln.link
        output[vuln.bulletinId].lastUpdated = vuln.lastUpdated
        output[vuln.bulletinId].summary = vuln.summary
      else
        stdnse.debug("Host not vulnerable to %s, with publication date: %s and restart required: %s",
          vuln.bulletinId, vuln.lastUpdated, vuln.restartRequired)
      end
    end
  end
  
  return output
end

-- Función que devuelve fecha en formato os.time de uptime del servidor obtenida según smb2.time.nse
function smb2HostUptime(host)
  local smbstate, status, overrides
  overrides = {}
  status, smbstate = smb.start(host)
  status = smb2.negotiate_v2(smbstate, overrides)

  if status then
    stdnse.debug("SMB2: Date: %s (%s) Start date:%s (%s)",
                  smbstate["date"], smbstate["time"],
                  smbstate["start_date"], smbstate["start_time"])
    stdnse.debug("Negotiation suceeded")

    return toDate(smbstate["start_date"])
  else
    return "Protocol negotiation failed (SMB2)"
  end
end

-- Función que devuelve un objeto os.time a partir del string de fecha obtenido de la web o por SMB2.
function toDate(dateStr)
  local m, d, y

  if string.find(dateStr, "-") then
    y, m, d = string.match(dateStr, "(%d+)-(%d+)-(%d+)")
  else
    m, d, y = string.match(dateStr, "(%a+)%s(%d+),%s(%d+)")
    m = m:lower()
    
    if m == "january"
      then m = 1
    elseif m == "february"
      then m = 2
    elseif m == "march"
      then m = 3
    elseif m == "april"
      then m = 4
    elseif m == "may"
      then m = 5
    elseif m == "june"
      then m = 6
    elseif m == "july"
      then m = 7
    elseif m == "august"
      then m = 8
    elseif m == "september"
      then m = 9
    elseif m == "october"
      then m = 10
    elseif m == "november"
      then m = 11
    elseif m == "december"
      then m = 12
    end
  end

  return os.time{day=d, year=y, month=m}
end

-- Función que devuelve un booleano tras pasarle la fecha de uptime del host y del boletín, ambas en formato os.time.
-- Considera que si bulletinDate y hostDate son el mismo día, el host no está actualizado y por lo tanto es vulnerable.
--
-- Ej:
-- hostDate = os.time{day=15, year=2017, month=2}
-- bulletinDate = os.time{day=15, year=2016, month=2}
-- hostUpdated(hostDate,bulletinDate)
-- Devuelve true
function hostUpdated(hostDate, bulletinDate)
  return os.difftime(hostDate, bulletinDate) > 0
end

-- Función que dada una URL de boletín de Microsoft extrae la fecha más reciente.
function extractLastDate(url)
  local urlBody = http.get_url(url).body
  
  if urlBody ~= nil then
    -- Se saca la fecha de la web.
    local pubDate = string.match(urlBody, "Published:%s(%a+%s%d+,%s%d+)")
    local updDate = string.match(urlBody, "Updated:%s(%a+%s%d+,%s%d+)")
      
    if updDate then
      return updDate
    else
      return pubDate
    end
  end
end


---
-- Funciones para el CSV.
---


-- Parseo del CSV.
--
-- Usage example: 
-- local file = "vulns.csv" 
-- local lineas = readCsv(file)
-- for i, v in pairs(lineas) do print(i, v.bulletinId) end
function readCsv(file)
  local csv = {}
  
  for l in assert(io.lines(file)) do
    local vuln = {}
    local vulnIt = string.gmatch(l, "[^;]+")
    
    vuln.bulletinId = vulnIt()
    vuln.severity = vulnIt()
    vuln.restartRequired = vulnIt()
    vuln.link = vulnIt()
    vuln.lastUpdated = vulnIt()
    vuln.summary = vulnIt()
    
    table.insert(csv, vuln)
  end
  
  return csv
end

function updateCsv(csv)
  for i, vuln in pairs(csv) do
    if i > 1 then
      local lastDate = extractLastDate(vuln.link)
      
      if lastDate ~= nil then
        stdnse.debug("%s CSV last updated date: %s, Microsoft's bulletin last updated date: %s",
          vuln.bulletinId, vuln.lastUpdated, lastDate)
        vuln.lastUpdated = lastDate
      end
    end
  end
end

function writeCsv(csv, file)
  local f = assert(io.open(file, "w"))

  for i, vuln in pairs(csv) do
    f:write(vuln.bulletinId, ";", vuln.severity, ";", vuln.restartRequired, ";", vuln.link,
      ";", vuln.lastUpdated, ";", vuln.summary, "\n")
  end
  
  f:close()
end