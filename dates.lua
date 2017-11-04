local http = require("socket.http")

--función para cambiar el formato de la fecha 
function date(fech)
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
	local date =  month.."/"..day.."/"..year
	return date
end


--varios ejemplos con distintos documentos
body,c,l,h = http.request('http://localhost:8080/5-Microsoft%20Security%20Bulletin%20MS17-006.html')
i, j = string.find(body, "<p>Published: %u")
k, l = string.find(body, "%a %d%d, %d%d%d%d")
fecha = string.sub(body, j, l)
print(fecha)
print(date(fecha))

body,c,l,h = http.request("http://localhost:8080/4-Microsoft%20Security%20Bulletin%20Summary%20for%20March%202017.html")
i, j = string.find(body, "<p>Published: %u")
k, l = string.find(body, "%a %d%d, %d%d%d%d")
fecha = string.sub(body, j, l)
print(fecha)
print(date(fecha))

body,c,l,h = http.request("http://localhost:8080/Microsoft%20Security%20Bulletin%20Summary%20for%20August%202013.html")
i, j = string.find(body, "<p>Published: %u")
k, l = string.find(body, "%a %d%d, %d%d%d%d")
fecha = string.sub(body, j, l)
print(fecha)
print(date(fecha))

body,c,l,h = http.request("http://localhost:8080/Microsoft%20Security%20Bulletin%20Summary%20for%20January%202017.html")
i, j = string.find(body, "<p>Published: %u")
k, l = string.find(body, "%a %d%d, %d%d%d%d")
fecha = string.sub(body, j, l)
print(fecha)
print(date(fecha))

body,c,l,h = http.request("http://localhost:8080/Microsoft%20Security%20Bulletin%20Summary%20for%20September%202010.html")
i, j = string.find(body, "<p>Published: %u")
k, l = string.find(body, "%a %d%d, %d%d%d%d")
fecha = string.sub(body, j, l)
print(fecha)
print(date(fecha))



