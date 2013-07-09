#!/usr/bin/env python
# -*- coding: utf-8 -*-

from libinfo import EncryptionHandler
import socket
import binascii

class SocketHandler:

	def __init__(self, server, port):

		if not isinstance(server, str):
			raise TypeError("Server's IP Adress must be str")
			return False
		if not isinstance(port, int):
			raise TypeError("Server's Port must be int")
			return False

		self.server = server
		self.port = port
		self.max_rcv = 4096
		self.sock = Socket()

		self.sid = None
		self.uidstring = None

		self.sesskey = None
		self.counter = None

		if not self.get_sesskey():
			raise RuntimeError("Error in client-server communication: DH exchange failed")


	def send(self, data, type_of_package):
		"""
		Sendet einen Datensatz in der Paketstruktur verpackt an den Server und gibt antwort zurueck

		@param data: Datensatz
		@type_of_package data: str

		@param type_of_package: Typ des Pakets
		@type type_of_package: str

		@return: str - Ergebnis, None bei Fehler
		"""

		if not isinstance(type_of_package, str):
			raise TypeError("Type must be str")
			return False

		# Paket nach Protokollstandart zusammenbauen

		msg = type_of_package + ":"
		msg += "12.12.12" + ":"

		if self.sid == None:
			msg += "x"
		else:
			msg += self.sid

		msg +=";"

		if type_of_package != "DHEX":
			if self.sesskey == None:
				raise Exception("No sesskey defined - aborting")
				return False

			msg += self.ec.encrypt(self.sesskey, self.counter, data)
		else:
			msg += data


		self.sock.connect((self.server, self.port))
		self.sock.send(msg)

		# Auf Antwort warten
		for attempt in range(10):
		    try:
		       ret_data = self.sock.recv(self.max_rcv)
		    except EnvironmentError as exc:
		        if exc.errno == errno.ECONNREFUSED:
		            time.sleep(1)
		        else:
		            raise
		    else:
		        break
		else: 
		    raise RuntimeError("maximum number of unsuccessful attempts reached")
		    return False

		self.sock.close()

		return ret_data


	def parse_error(self, data):
		"""
		Extrahiert Fehlermeldungen aus einem Antwortpaket

		@param data: Antwortpaket
		@type data: str

		@return: 2x Tuple (str - Stelle, str - Fehler), False falls es kein Fehler ist
		"""

		if not isinstance(date, str):
            raise TypeError("Data must be str")
            return False

        try:
			if data.find("error", beg=0 end=4) == -1 :
	            return False
	        else:
	            data = data.split(" - ", 3)
	            return (data[2], data[1])

	    except TypeError:
	    	raise RuntimeError("Wrong server response")
	    	return False



	def get_sesskey(self):
		"""
		Generiert einen Sessionkey durch einen DH-Schluesselaustausch mit dem Server

		@return: Boolean success
		"""

		proot = 3
		#prime = 2959259
		prime = 13
		num = random.randrange(1, prime - 2, 1)

		a = proot**num % prime

		b_data = self.send(str(a), "dhex")

		try:

			# Antwortpaket auswerten
			b_data = re.split(":", b_data)

			# Session-ID
			self.sid = data[0]

			# Sessionkey
			self.sesskey = self.ec.generate_sesskey(num, int(b_data[1]), prime)

			# Counter
			iv = data[2]
			iv = binascii.unhexlify(iv)
			self.counter = Counter.new(128, initial_value=long(iv.encode("hex"), 16))
			return True

		except IndexError:
			return False



	def auth(self, username, password, stay_logged_in):	
		"""
		Authentifiziert einen Nutzer

		@param username: Nutzername
		@type username: str

		@param password: Passwort
		@type password: str

		@param stay_logged_in: Boolean ob der Nutzer eingeloggt beleiben soll
		@type stay_logged_in: Boolean

		@return: Boolean Success
		"""

		if not isinstance(username, str):
			raise TypeError("username must be str")
			return False
		if not isinstance(password, str):
			raise TypeError("password must be str")
			return False
		if not isinstance(stay_logged_in, bool):
			raise TypeError("stay_logged_in must be bool")
			return False

		if (username == None) or (password == None):
			if exists("login.dat") == True:
			    plain = open('login.dat', 'r').read().close()
			    plain_list = plain.split('\n')

			    if len(plain_list) > 0:
			        plain = str(plain_list[0])
			    else:
			    	raise RuntimeError("Login.dat content invalid and no password/username given")
			    	return False
			else:
			    
			    if stay_loged_in == True:
			        self.write_loginfile(username, password)

			    password = self.ec.get_hash(password)
				plain = username + ":" + password

			response = self.send(plain, "AUTH")
			error = self.parse_error(response)

			if error == False:
				self.uidstring = response
				return True
			else:
				return False


    def write_loginfile(self, username, plain_password):
    	"""
    	Schreibt eine valide Login.dat Datei

    	@param username: Nutzername
    	@type username: str

    	@param plain_password: Passwort im Klartext
    	@type plain_password: str

    	@return: None
    	"""

    	data = username + self.ec.get_hash(plain_password)

		loginfile = open("login.dat", 'w')
        loginfile.write(data)
        loginfile.close()    