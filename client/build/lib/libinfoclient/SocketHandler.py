#!/usr/bin/env python
# -*- coding: utf-8 -*-

from libinfo import EncryptionHandler
import socket
import binascii
import base64
from re import split
import random
import string
from os.path import exists
import simplejson as json

from Crypto.Util import Counter as Counter
from Crypto.Cipher import AES as AES

import ftplib
import os
import shutil

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
		self.max_rcv = 2048
		self.sock = socket.socket()

		self.crypt = EncryptionHandler()

		self.sid = None
		self.uidstring = None

		self.sesskey = None
		self.counter = None

		self.retry_counter = None
		self.max_retry = 10

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

		#if (type_of_package != "dhex") or not "get" in type_of_package :
		if type_of_package != "dhex":
			if self.sesskey == None:
				raise RuntimeError("No sesskey defined - aborting")
				return False


			data = data.encode("utf-8")
			#msg += self.crypt.encrypt(self.sesskey, self.counter, data)
			msg += data

		else:
			msg += data

		self.sock = socket.socket()
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

		try:
			if type_of_package != "dhex":
				if "error" in ret_data:
					return ret_data

				ret_data = ret_data.split(";", 2)
				ret_data = ret_data[1]
				#ret_data = self.crypt.decrypt(self.sesskey, self.counter, ret_data)

				if ("get" in type_of_package) and not type_of_package == "getfile":
					try:
						ret_data = json.loads(ret_data)

					except ValueError as error:
						print "Error in JSON decoding :" + ret_data
						raise RuntimeError(error)
						return False
				else:
						ret_data = ret_data.decode("utf-8", "ignore")

		except IndexError as error:
			raise IndexError(error)
			return False

		return ret_data


	def parse_error(self, data):
		"""
		Extrahiert Fehlermeldungen aus einem Antwortpaket

		@param data: Antwortpaket
		@type data: str

		@return: 2x Tuple (str - Stelle, str - Fehler), False falls es kein Fehler ist
		"""

		try:
			#if string.find(data,"error", 0, 4) == -1 :
			if not "error - " in data:
				return False
			else:
				data = data.split(" - ", 3)
				return (data[2], data[1])

		except IndexError:
			if isinstance(data, list):
				for item in data:
					print "error: " + item
			else:
				raise RuntimeError("Wrong server response :" + data)

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
			b_data = split(":", b_data)

			# Session-ID
			self.sid = b_data[0]

			# Sessionkey
			self.sesskey = self.crypt.generate_sesskey(num, int(b_data[1]), prime)

			# Counter
			iv = b_data[2]
			#iv = binascii.unhexlify(iv)
			self.counter = Counter.new(128, initial_value=long(iv, 16))
			return True

		except IndexError as error:
			print error
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

		if not isinstance(stay_logged_in, bool):
			raise TypeError("stay_logged_in must be bool")
			return False

		if (username == None) or (password == None):
			print("Error no Username or Password given")

			    
		else:
			if stay_logged_in == True:
				self.write_loginfile(username, password)

			password = self.crypt.get_hash(password)
			plain = username + ":" + password

		response = self.send(plain, "auth")

		error = self.parse_error(response)

		if not error:
			self.uidstring = response
			return True
		else:
			#raise RuntimeError(error)
			print error
			return False

	def auth_stayLogedIn(self):	
		"""
		Authentifiziert einen Nutzer anhand der login.dat
		@return: Boolean Success
		"""
		plain = open('login.dat', 'r').read()
		plain_list = plain.split('\n')
		if len(plain_list) > 0:
			plain = str(plain_list[0])
		else:
			raise RuntimeError("Login.dat content invalid and no password/username given")
			return False

		response = self.send(plain, "auth")
		error = self.parse_error(response)

		if not error:
			self.uidstring = response
			return True
		else:
			#raise RuntimeError(error)
			print error
			return False



	def write_message(self, receiver, content):
		"""
		Schickt eine Nachricht an einen User

		@param receiver: Empfaenger
		@type receiver: str

		@param content: Inhalt
		@type content: str

		@return: Boolean Success
		"""

		if not isinstance(receiver, str):
			raise TypeError("receiver must be str")
			return False
		if not isinstance(content, str):
			raise TypeError("content must be str")
			return False


		data = self.uidstring + ":"
		data += receiver + ":"
		data += content

		response = self.send(data, "msg")
		error = self.parse_error(response)

		if error == False:
			return True
		else:
			raise RuntimeError(error)
			return False



	def get_messages(self, last_mid):
		"""
		Ruft Nachrichten vom Server ab

		@param last_mid: Letzte bekannte Gruppennachrichten-ID
		@type last_mid: int

		@return: Array [str - sender, str - content], False bei Fehler, None bei keinen neuen Nachrichten
		"""

		msg = self.uidstring + ":" + str(last_mid)

		try:
			messages = self.send(msg, "getmsg")

		except (RuntimeError, ValueError, TypeError) as error:
			print error
			return False
		#messages = pickle.loads(messages)
		ret_msg = []

		#if not messages:
		#	raise RuntimeError("No messages have been received")
		#	return False

		if isinstance(messages, int):
			raise RuntimeError("server communication failed")
			return False

		if len(messages) == 0:
			raise RuntimeError("Messages empty")
			return None

		elif isinstance(messages, str):
			error = self.parse_error(messages)

			if not error:
				return messages
			else:
				return False
		else:
			try:
				for item in messages:
					#parts = split(":", item, 2)
					ret_msg.append((item[0], item[1]))
				print "returning ret_msg"
				return ret_msg
			except IndexError as error:
				print error
				return False



	def write_group_message(self, group_receiver, content):
		"""
		Schickt eine Nachricht an eine Gruppe

		@param group_receiver: Empfaenger (Gruppe)
		@type group_receiver: str

		@param content: Inhalt
		@type content: str

		@return: Boolean Success
		"""

		if not isinstance(group_receiver, str):
			raise TypeError("group_receiver must be str")
			return False
		if not isinstance(content, str):
			raise TypeError("content must be str")
			return False


		data = self.uidstring + ":" + str(group_receiver) + ":" + str(content)

		response = self.send(data, "gmsg")
		error = self.parse_error(response)

		if error == False:
			return True
		else:
			raise RuntimeError(error)
			return False



	def get_group_messages(self, last_gmid):
		"""
		Ruft Gruppennachrichten vom Server ab

		@param last_gmid: Letzte bekannte Gruppennachrichten-ID
		@type last_gmid: int

		@return: Array [str - sender, str - gruppe, str - content], False bei Fehler, None bei keinen neuen Nachrichten
		"""

		if not isinstance(last_gmid, int):
			raise TypeError("last_gmid must be int")
			return False


		msg = self.uidstring + ":" + str(last_gmid)


		messages = self.send(msg, "getgmsg")
		ret_msg = []

		if len(messages) == 0:
			return None

		elif len(messages) == 1:
			error = self.parse_error(messages)

			if not error:
				return messages
			else:
				raise RuntimeError(error)
				return False
		else:
			for item in messages:
				parts = split(":", item, 3)
				ret_msg.append((parts[0], parts[1], parts[1]))
			return ret_msg


	def write_loginfile(self, username, plain_password) :
		"""
		Schreibt eine valide Login.dat Datei

		@param username: Nutzername
		@type username: str

		@param plain_password: Passwort im Klartext
		@type plain_password: str

		@return: None
		"""

		data = username + ":" + self.crypt.get_hash(plain_password)

		loginfile = open("login.dat", 'w')
		loginfile.write(data)
		loginfile.close() 



	def request_file(self):
		"""
		Beantragt einen neuen Dateiupload

		@return Dateiname
		"""

		ret = self.send("", "reqfile")

		error = self.parse_error(ret)
		if not error:
				return ret
		else:
			raise RuntimeError(error)
			return False


	def get_globalname(self, filestring):
		"""
		Findet den Dateinamen der Datei heraus

		@param filestring: Dateistring
		@type filestring: str

		@return: str - globalname
		"""

		ret = self.send(filestring, "getfile")

		error = self.parse_error(ret)
		if not error:
				return ret
		else:
			raise RuntimeError(error)
			return False



	def get_file(self, filestring):
		"""
		Laedt eine Datei von dem Server herunter

		@param filestring: Dateistring auf dem server
		@type filestring: str

		@return: Boolean Erfolg
		"""

		ftp = ftplib.FTP("127.0.0.1")
		ftp.login("ftp-user", "test")

		f = open("./data/" + filestring, "wr")
		data = ""

		ftp.retrbinary("RETR " + filestring, f.write)
		f.write(data)
		ftp.quit()
		f.close()

		name = self.get_globalname(filestring)
		print name
		if name:
			os.rename("./data/" + filestring, "./data/" + name)
			return "./data/" + name
		else:
			return False



	def upload_file(self, filestring, localfile, localname):
		"""
		Laedt eine Datei auf den Server hoch

		@param filestring: Dateistring auf dem Server
		@type filestring: str

		@param localfile: Lokale Datei
		@type localfile: str

		@return: Boolean Erfolg
		"""

		try:		
			shutil.copyfile(localfile, "./tmp/" + filestring)
			ftp = ftplib.FTP("127.0.0.1")
			ftp.login("ftp-user", "test")

			f = open("./tmp/" + filestring, "r")

			#ftp.cwd("pub")

			ftp.storbinary("STOR " + filestring, f)
			f.close()
			ftp.quit()

			msg = filestring + ":"
			msg += localname

			ret = self.send(msg, "regfile")
			print ret

			error = self.parse_error(ret)

			if not error:
				return True
			return False

		except ftplib.all_errors as error:
			raise RuntimeError(error)
			return False


	def get_profile_pic(self, username):
		"""
		Speichert das Profilbild fuer einen Nutzer

		@param username: Nutzername
		@type username: str

		@return: None
		"""

		ret = self.send(username, "getpic")

		error = self.parse_error(ret)

		if not error:
			ret = self.get_file(ret)
			error = self.parse_error(ret)
			if not error:
				shutil.copyfile("./data/" + username + ".jpg", "./pic/" + username + ".jpg")
				return None
		
		shutil.copyfile("./pic/default.jpg", "./pic/" + username + ".jpg")


