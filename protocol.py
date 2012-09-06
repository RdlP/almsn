# -*- coding: utf-8 -*-
# Este archivo representa al protocolo utilizado por la red MSN

VER = "VER %s MSNP15 CVR0\r\n" #Comando de presentación
CVR = "CVR %s 0x0c0a winnt 5.1 i386 MSNMSGR 8.1.0178 msmsgs %s\r\n" #Comando que informa del SO, la arquitectura de la máquina y la versión del cliente, 0x0C0A es un flag que indica nuestra ubicación
USR_I = "USR %s SSO I %s\r\n" #Mandamos nuestro usuario
USR_S = "USR %s SSO S %s %s\r\n" #Mandamos la autenticación
CHG = "CHG %s %s %s 0\r\n"
