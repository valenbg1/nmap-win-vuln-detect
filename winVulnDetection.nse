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
Spiders a web site to find web pages requiring form-based or HTTP-based authentication. The results are returned in a table with each url and the
detected method.
]]

--- SCRIPT BASADO en http-auth-finder
-- @usage
-- nmap -p 80 --script http-auth-finder <ip>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |   datesSearch:
-- |   http://localhost/4-Microsoft%20Security%20Bulletin%20Summary%20for%20March%202017.html    FORM
-- |   2017-11-09                                                                                DATE
--


author = "Ignacio Marín & Valentín Blanco"
categories = {"discovery", "safe"}


portrule = function(host,port)
  return smb.get_port(host) ~= nil
end

action = function(host, port)
    local fecha_server = fechaServer(host,port)
    print("FECHA SERVER: "..os.date("%x",fecha_server))

    --TODO: for urls en csv coger fecha url y comparar
    local d = getDate("http://localhost/5-Microsoft%20Security%20Bulletin%20MS17-006.html")
    local fecha_url = dat(d)
    print("FECHA URL: "..os.date("%x",fecha_url))
    local isServerUpdated = serverActualizado(fecha_server,fecha_url)
    if isServerUpdated
      then print("El server está actualizado")
    else print("El server no está actualizado")
    end
end

-- Función que devuelve fecha en formato os.time de reinicio del servidor obtenida con smb2

function fechaServer(host, port)
  local smbstate, status, overrides, date, start_date
  overrides = {}
  status, smbstate = smb.start(host)
  status = smb2.negotiate_v2(smbstate, overrides)


  if status then
    stdnse.debug2("SMB2: Date: %s (%s) Start date:%s (%s)",
                        smbstate['date'], smbstate['time'],
            smbstate['start_date'], smbstate['start_time'])
    date = smbstate['date']
    -- Hardcoded
    start_date = "2017-07-20 09:29:49" --smbstate['start_date']
    stdnse.debug2("Negotiation suceeded")
    start_date = string.sub(start_date,1,10)
    local date = os.time{day=tonumber(string.sub(start_date,9,10)), year=tonumber(string.sub(start_date,1,4)), month=tonumber(string.sub(start_date,6,7))}
    return date
  else
    
    return " Protocol negotiation failed (SMB2)"
  end
end

--Funcion que devuelve un objeto de tipo os.time a partir del string de fecha obtenido de la web

function dat(fech)
  local month = nil

  i, j = string.find(fech, "%d%d")
  local day = string.sub(fech, i, j)

  i, j = string.find(fech, "%d%d%d%d")
  local year = string.sub(fech, i, j)


  if(string.find(fech, "January"))
    then month = "1"
  end
  if(string.find(fech, "February"))
    then month = "2"
  end
  if(string.find(fech, "March"))
    then month = "3"
  end
  if(string.find(fech, "April"))
    then month = "4"
  end
  if(string.find(fech, "May"))
    then month = "5"
  end
  if(string.find(fech, "June"))
    then month = "6"
  end
  if(string.find(fech, "July"))
    then month = "7"
  end
  if(string.find(fech, "August"))
    then month = "8"
  end
  if(string.find(fech, "September"))
    then month = "9"
  end
  if(string.find(fech, "October"))
    then month = "10"
  end
  if(string.find(fech, "November"))
    then month = "11"
  end
  if(string.find(fech, "November"))
    then month = "12"
  end

  local date = os.time{day=tonumber(day), year=tonumber(year), month=tonumber(month)}
  return date
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
  print(wholedays)
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
  port = "80"
  path = urld.path

  local list = {host=host,path=path,port=port}

  return list
end

-- Función que dada una url de Microsoft extrae la fecha.
function getDate(url)
  print("URL: "..url) 
  local url = splitUrl(url)
  print("host: "..url.host.."port: "..url.port.."path: "..url.path)
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