#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import socket
import re
import sys
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Util import Counter
import random
import errno, time
import binascii
from libinfo import EncryptionHandler
from os.path import exists
import sys
import codecs


# Port binden
port = int(sys.argv[1])
# Maximal 10000 Bytes aus einer Socket lesen
max_rcv = 10000

# Socket erstellen, Hashgenerator bauen
sock = socket.socket()
hashengine = SHA256.new()


# Primitivwurzel
proot = 3
# Primzahl
#prime = 2959259
prime = 13
# Zufaellige Nummer
num = random.randrange(1, prime - 2, 1)


if exists("login.dat") == True:
    plain_read = open('login.dat', 'r').read()
    plain_list = plain_read.split('\n')
    if len(plain_list) > 0:
        plain = str(plain_list[0])

elif exists("login.dat") == False:
    user = raw_input("Username:")
    password = raw_input("Passwort:")
    stay_loged_in = raw_input("Stay Logedin:")
    hash_password = EncryptionHandler()
    hash_password_output = hash_password.get_hash(password)
    plain = user + ":" + hash_password_output
    if stay_loged_in == 'yes':
        save_info_user = open("login.dat", 'w')
        save_info_user.write(plain)
    else: pass

    
    




#if Checkbox Safe my data is checked:
#hash_password = EncryptionHandler()
#hash_password_output = hash_password.get_hash(password) #Give Password here

#save_string = user + ":" + hash_password_output

message_input_raw = raw_input("Ihre Nachricht:")
stdout_encoding = sys.stdout.encoding or sys.getfilesystemencoding()

#message_input_raw = unicode(message_input_raw_unicode)
message_input = message_input_raw.decode("iso-8859-1").encode("utf-8")
a = proot**num % prime

# Paket mit A an server senden
msg = "dhex:12.12.12:x:x;" + str(a)
sock.connect(("127.0.0.1", port))
sock.send(msg)

# Auf Antwort warten
for attempt in range(10):
    try:
       data = sock.recv(max_rcv)
    except EnvironmentError as exc:
        if exc.errno == errno.ECONNREFUSED:
            time.sleep(1)
        else:
            raise
    else:
        break
else: 
    raise RuntimeError("maximum number of unsuccessful attempts reached")



sock.close()

# Antwortpaket auswerten
data = re.split(":", data)
# Sessionkey aus eigenem Secret und B generieren
sesskey = int(data[1])**num % prime
# Counter aus dem Paket extrahieren und initialisieren
iv = data[2]
iv = binascii.unhexlify(iv)
ctr = Counter.new(128, initial_value=long(iv.encode("hex"), 16))

hashengine.update(str(sesskey))
sesskey = hashengine.digest()

#plain = "gu"
#iv = 'asdfasdfasdfasdf'


# AES-Engine bauen
cipher = AES.new(sesskey, AES.MODE_CTR, counter=ctr)
#msg = ""
#msg += "mesg" + ":"
#msg += "none" + ":"
#msg += "12.12.12" + ":"
#msg += data[0] + ";"
#msg += iv + ":"
#msg += cipher.encrypt(plain)

#sock = socket.socket()
#sock.connect(("127.0.0.1", port))
#sock.send(msg)
#sock.close()

# Authentifizierungspaket senden



#plain = user+":"+hash_password_output
#On Startup checks if the files are there



    #send the info and request a confirmation from the server if not right send user to Login screen
#else:


#plain = "meop:8b2d38b789e90bb18567c2be4abbd4295f461f6453dd0447a3bf248a75eb0ae7"
msg = ""
msg += "auth" + ":"
msg += "12.12.12" + ":"
msg += data[0] + ";"
msg += cipher.encrypt(plain)

sid = data[0]

sock = socket.socket()
sock.connect(("127.0.0.1", port))
sock.send(msg)


# Auf Antwort warten
for attempt in range(10):
    try:
       data = sock.recv(max_rcv)
    except EnvironmentError as exc:
        if exc.errno == errno.ECONNREFUSED:
            time.sleep(1)
        else:
            raise
    else:
        break
else: 
    raise RuntimeError("maximum number of unsuccessful attempts reached")

# Nachricht entschluesseln
cipher = AES.new(sesskey, AES.MODE_CTR, counter=ctr)
tmp = re.split(";", data, 1)
msg = cipher.decrypt(tmp[1])

print "Antwort auf Auth:" + msg

# UID-String uebernehmen
uidstring = msg

# Neue Gruppennachricht schicken
rcv_group = "meop"

plain = uidstring + ":" + rcv_group + ":" + message_input
msga = ""
msga += "msg" + ":"
msga += "12.12.12" + ":"
msga += str(sid) + ";"
msga += cipher.encrypt(plain)

sock = socket.socket()
sock.connect(("127.0.0.1", port))
sock.send(msga)


# Auf Antwort warten
for attempt in range(10):
    try:
       data = sock.recv(max_rcv)
    except EnvironmentError as exc:
        if exc.errno == errno.ECONNREFUSED:
            time.sleep(1)
        else:
            raise
    else:
        break
else: 
    raise RuntimeError("maximum number of unsuccessful attempts reached")


# Antwort entschluesseln
cipher = AES.new(sesskey, AES.MODE_CTR, counter=ctr)
tmp = re.split(";", data, 1)
msg = cipher.decrypt(tmp[1])

print "Antwort auf Mesg:" + msg

sock.close()

