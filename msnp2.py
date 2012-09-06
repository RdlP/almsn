# -*- coding: utf-8 -*-
#TODO Falta implementar los mensajes que manda el servidor
#si el usuario no ha podido autenticarse, bien por que
#ha puesto su usuario mal, o por que la contraseña es incorrecta
#TODO Programar un Parser para tratar los datos de los contactos
#que nos envía el servidor
import socket
import select
import StringIO, gzip
import hashlib
import time
import urllib
import httplib
import urlparse
import hmac
import struct
import random
import base64
import xml.dom.minidom
import xml.sax.saxutils
import soap
import signal
import sys
import parser
import colorText
import protocol
import getpass
import RecvCommand
try:
    from hashlib import sha1
except ImportError:
    import sha
    sha1 = sha.new
import pydes
CALC_3DES = 0x6603
CALG_SHA1 = 0x8004


dic = {
    '\"'    :    '&quot;',
    '\''    :    '&apos;'
}

sockLogin=socket.socket()

def signal_handler(signal, frame):
	print colorText.colores["ROJO"] + 'Cerrando el programa correctamente...' + colorText.colores["NORMAL"]
	salir(1)

def salir(pout):
	sockLogin.close()
	sys.exit(pout)

def encrypt(key, nonce):
    def derive_key(key, magic):
        hash1 = hmac.new(key, magic, sha1).digest()
        hash2 = hmac.new(key, hash1 + magic, sha1).digest()
        hash3 = hmac.new(key, hash1, sha1).digest()
        hash4 = hmac.new(key, hash3 + magic, sha1).digest()
        return hash2 + hash4[0:4]

    #hm = lambda k, m: hmac.new(k, m, sha1).digest()
    #lambda k, m: hm(k, hm(k, m) + m) + hm(k, hm(k, hm(k, m)) + m)[0:4]
    key1 = base64.standard_b64decode(key)
    key2 = derive_key(key1, "WS-SecureConversationSESSION KEY HASH")
    key3 = derive_key(key1, "WS-SecureConversationSESSION KEY ENCRYPTION")

    hash = hmac.new(key2, nonce, sha1).digest()

    iv = struct.pack("Q", random.getrandbits(8 * 8))  # 8 bytes

    ciph = pydes.triple_des(key3, pydes.CBC, iv).encrypt(nonce + \
        "\x08\x08\x08\x08\x08\x08\x08\x08")
  
    blob = struct.pack("<LLLLLLL", 28, pydes.CBC, CALC_3DES, CALG_SHA1,
                       len(iv), len(hash), len(ciph)) + iv + hash + ciph
    return base64.standard_b64encode(blob)


def escape(string):
    return xml.sax.saxutils.escape(string, dic)
#Comprueba si el correo electrónico introducido es correcto
def comprobarCorreo(usuario):
	i = usuario.split('@')
	correcto = i[1].find("hotmail")
	if correcto == -1:
		return False
	else:
		return True

#Devuelve el parametro apuntado por n
def parametros (mensaje, n):
	lista = [];
	lista = mensaje.split(" ")
	return lista[n]

def autenticacion(nonce, usuario, contrasenya, policy="MBI"):
	# Sustituimos %s en soap.passport por el usuario y la contraseña
	body = soap.passport % (usuario, escape(contrasenya))
    #Si '@msn.com' no esta contenido en usuario:
	_server = "login.live.com"
	_url = "/RST.srf"
    #else:
    #    _server = "msnia.login.live.com"
    #    _url = "/pp550/RST.srf"

    #Creamos la cabecera
	headers = {
            "Accept":  "text/*",
            "User-Agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
            "Host": _server,
            "Content-Length": str(len(body)),
            "Connection": "Keep-Alive",
            "Cache-Control": "no-cache",
            "Accept-encoding": "gzip",
        }

	succeeded = False
	for i in range(5):
		response = None
		# send the SOAP request
		for i in range(3):
			conn = httplib.HTTPSConnection(_server,443)
			conn.request("POST", _url, body, headers)
			response = conn.getresponse()
			break

		if response:
			data = response.read()
			isGzipd = response.getheader('Content-Encoding', '')
			if isGzipd == 'gzip':
				# data is gzipped, unzipit!
				cstream = StringIO.StringIO(data)
				gzpr = gzip.GzipFile(fileobj=cstream)
				data = gzpr.read()
		else:
			print "No ha sido posible la autenticación: No hay respuesta del Servidor"
			salir(1)

		if data.find('<faultcode>psf:Redirect</faultcode>') > 0:
			_url = urlparse.urlparse(data.split('<psf:redirectUrl>')\
				[ 1 ].split('</psf:redirectUrl>')[ 0 ])
			_server=_url[ 1 ]
			_url=_url[ 2 ]
		else:
			succeeded = True
			break

	if not succeeded:
		print "No ha sido posible la autenticación"
		salir(1)

	# Intentamos obtener el ticket de los datos que nos envie el servidor
	tokens = parser.SSoParser(data).tokens
	if 'messengerclear.live.com' not in tokens:
		print "No ha sido posible la autenticación: La contraseña es incorrecta"
		salir(1)

	mbiblob = encrypt(
		tokens['messengerclear.live.com']['secret'], nonce)
	return tokens['messengerclear.live.com']['security']\
			.replace("&amp;" , "&"), mbiblob, tokens


def peticionSOAP(tokens, body, peticiondst, SOAPaccion, server):
	if server in tokens:
		body = body.replace("&tickettoken;", tokens[server]['security']\
					.replace('&', '&amp;'))
	headers = {
		"SOAPAction": SOAPaccion,
		"Content-Type": "text/xml; charset=utf-8",
		"Host": server,
		"Content-Length": str(len(body)),
		"User-Agent": "MSN Explorer/9.0 (MSN 8.0; TmstmpExt)",
		"Connection": "Keep-Alive",
		"Cache-Control": "no-cache",
		"Accept-encoding": "gzip", # highly improves bandwidth usage
	}
	conn = httplib.HTTPSConnection(server, 443)
	conn.request("POST", peticiondst, body, headers)
	response = conn.getresponse()
	data = response.read()
	isGzipd = response.getheader('Content-Encoding', '')
	if isGzipd == 'gzip':
		cstream = StringIO.StringIO(data)
		gzpr = gzip.GzipFile(fileobj=cstream)
		data = gzpr.read()
	return data

def	obtenerContactos(tokens):
	body = soap.membershipList
	host = "local-bay.contacts.msn.com"
	peticiondst = "/abservice/SharingService.asmx"
	SOAPaccion = "http://www.msn.com/webservices/AddressBook/FindMembership"
	data = peticionSOAP(tokens, body, peticiondst, SOAPaccion, host)
	inicio = data.find("<PreferredHostName>") + len("<PreferredHostName>")
	fin = data.find("</PreferredHostName>")
	hostNamePreferido = data[inicio:fin]
	newhost = hostNamePreferido.replace("proxy","local")
	if (newhost != host):
		tokens[newhost] = {'security' : tokens[host]['security']}
		data = peticionSOAP(tokens, body, peticiondst, SOAPaccion, newhost)
	
	
	return parser.MembershipParser(data), newhost #parser.MembershipParser(data)

def	obtenerLibretaDirecciones(tokens, host):
	body = soap.addressBook
	peticiondst = "/abservice/abservice.asmx"
	SOAPaccion = "http://www.msn.com/webservices/AddressBook/ABFindAll"
	data = peticionSOAP(tokens, body, peticiondst, SOAPaccion, host)
	return data

def posLogin():
	

def login():
	print "Introduce un ID de MSN:"
	usuario = raw_input(">")
	correcto = comprobarCorreo(usuario)
	if correcto == False:
		print "Correo no Válido"
		salir(1)
	print "Introduzca su contraseña de MSN:"
	contrasenya = getpass.getpass(">")
	trid = 1
	# p2p features support number
	CLIENT_ID = 0x50000000 | 0x2  # msnc5 + reset capabilities
	CLIENT_ID |= 0x4     # ink
	CLIENT_ID |= 0x20    # multi-packet MIME messages
	CLIENT_ID |= 0x8000  # winks
	CLIENT_ID |= 0x40000 # voice clips
	#MSN Utiliza varios servidores para poder conectarte a su servicio, el primer servidor es messenger.hotmail.com por el puerto 1863, debemos ejecutar los comandos VER, CVR y USR, despues de USR el servidor nos proporcionara una direccion de otro servidor, hay que conectarse a ese servidor y ejecutar de nuevo los comandos VER CVR y USR
	sockLogin = socket.socket()
	sockLogin.connect(("messenger.hotmail.com", 1863))
	#MENSAJE VER
	VER = protocol.VER % trid
	print colorText.colores["ROJO"] + ">>>>"+ colorText.colores["NORMAL"]+ VER[:-1]
	sockLogin.send(VER)
	trid +=1
	mensaje = sockLogin.recv(1024)
	print colorText.colores["AZUL"] + "<<<<" + colorText.colores["NORMAL"] + mensaje[:-1]
	#MENSAJE CVR
	CVR = protocol.CVR % (trid, usuario)
	print colorText.colores["ROJO"] + ">>>>" + colorText.colores["NORMAL"] + CVR[:-1]
	sockLogin.send(CVR)
	trid += 1
	mensaje = sockLogin.recv(1024)
	print colorText.colores["AZUL"] + "<<<<" + colorText.colores["NORMAL"] + mensaje[:-1]
	#MENSAJE USR
	USR = protocol.USR_I % (trid, usuario)
	print colorText.colores["ROJO"] + ">>>>" + colorText.colores["NORMAL"] + USR[:-1]
	sockLogin.send(USR)
	trid += 1
	mensaje = sockLogin.recv(1024)
	print colorText.colores["AZUL"] + "<<<<" + colorText.colores["NORMAL"] + mensaje[:-1]

	#Si todo ha salido bien, en el ultimo mensaje recibido nos deberia aparecer una direccion ip del siguiente servidor al que hay que conectarse y volver a ejecutar los comandos.
	
	nuevaConexion = parametros(mensaje, 3)
	ip_puerto = nuevaConexion.split(":")
	ip = ip_puerto[0]
	puerto = ip_puerto[1]
	trid = 1
	print colorText.colores["ROJO"] + "Conexion cerrada con messenger.hotmail.com:1863 conectado ahora con el servidor " + nuevaConexion + colorText.colores["NORMAL"]
	sockLogin.close()
	sockLogin = socket.socket()
	sockLogin.connect((ip, int(puerto)))
	#MENSAJE VER
	VER = protocol.VER % trid
	print colorText.colores["ROJO"] + ">>>>"+ colorText.colores["NORMAL"]+ VER[:-1]
	sockLogin.send(VER)
	trid += 1
	mensaje = sockLogin.recv(1024)
	print colorText.colores["AZUL"] + "<<<<" + colorText.colores["NORMAL"] + mensaje[:-1]
	#MENSAJE CVR
	CVR = protocol.CVR % (trid, usuario)
	print colorText.colores["ROJO"] + ">>>>" + colorText.colores["NORMAL"] + CVR[:-1]
	sockLogin.send(CVR)
	trid += 1
	mensaje = sockLogin.recv(1024)
	print colorText.colores["AZUL"] + "<<<<" + colorText.colores["NORMAL"] + mensaje[:-1]
	#MENSAJE USR
	USR = protocol.USR_I % (trid, usuario)
	print colorText.colores["ROJO"] + ">>>>" + colorText.colores["NORMAL"] + USR[:-1]
	sockLogin.send(USR)
	trid += 1
	mensaje = sockLogin.recv(1024)
	print colorText.colores["AZUL"] + "<<<<" + colorText.colores["NORMAL"] + mensaje[:-1]
	parametro3=(parametros(mensaje,2).split("\n"))
	tam_paquete = int(parametro3[0])
	mensaje2 = mensaje[mensaje.index('<'):]
	print tam_paquete
	contador = len(mensaje2)
	while ((contador < tam_paquete)):
		quedan = tam_paquete-contador
		if (contador < tam_paquete):
			mensaje = sockLogin.recv(quedan)
		print mensaje
		contador = contador + len(mensaje)

	#Contesta el Servidor de nuevo
	mensaje = sockLogin.recv(1024)
	print colorText.colores["AZUL"] + "<<<<" + colorText.colores["NORMAL"] + mensaje[:-1]
	hash = parametros(mensaje,5)
	hash = hash[:-2]
	(passportid,mbiblob,tokens) = autenticacion(hash, usuario, contrasenya)
	#try:
	#	t = passportid.split('&p=')[0][2:]
	#	MSPProf = passportid.split('&p=')[1]
	#except:
	#	print "ERRORRRR USR"
	USR = protocol.USR_S % (trid, passportid, mbiblob)
	sockLogin.send(USR)
	trid += 1
	print colorText.colores["ROJO"] + ">>>>" + colorText.colores["NORMAL"]+ USR[:-1]
	mensaje = sockLogin.recv(15 + len(usuario))
	print colorText.colores["AZUL"] + "<<<<" + colorText.colores["NORMAL"]+ mensaje[:-1]
	mensaje = sockLogin.recv(12)
	print colorText.colores["AZUL"] + "<<<<" + colorText.colores["NORMAL"]+ mensaje[:-1]
	mensaje = sockLogin.recv(1024)
	print colorText.colores["AZUL"] + "<<<<" + colorText.colores["NORMAL"]+ mensaje[:-1]
	parametro = parametros(mensaje, 3).split("\n")
	tam_paquete = int (parametro[0])
	mensaje2 = mensaje[mensaje.find("MIME"):]
	contador = len(mensaje2)
	while ((contador < tam_paquete)):
		quedan = tam_paquete-contador
		if (contador < tam_paquete):
			mensaje = sockLogin.recv(quedan)
		print mensaje
		contador = contador + len(mensaje)
	print colorText.colores["ROJO"] + "El proceso de login ha sido exitoso" + colorText.colores["NORMAL"]
	contactos, host = obtenerContactos(tokens)
	#PARA QUE MUESTRE LOS CONTACTOS EN FORMATO XML DESCOMENTA LA LINEA DE ABAJO
	#TODO Iterar los contactos para contarlos y saber el total de contactos
	print contactos.memberships
	libreta = obtenerLibretaDirecciones(tokens, host)
	#print libreta
	client_id = '' + str(CLIENT_ID)
	CHG = protocol.CHG % (trid, "NLN", client_id)
	trid +=1
	sockLogin.send(CHG)
	print colorText.colores["ROJO"] + ">>>>" + colorText.colores["NORMAL"]+ CHG[:-1]
	#mensaje = sockLogin.recv(len(CHG))
	#print colorText.colores["AZUL"] + "<<<<" + colorText.colores["NORMAL"]+ mensaje[:-1]
	#recibir = RecvCommand.RecvCommand(sockLogin)
	#recibir.start()
	#while(True):
	#	comando = raw_input(">")
	#	comando += "\r\n"
	#	sockLogin.send(comando)
	#	m=1
	

def main():
	signal.signal(signal.SIGINT, signal_handler)
	login()

if __name__ == "__main__":
    main()

