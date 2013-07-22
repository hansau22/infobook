#!/usr/bin/env python
import hashlib
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
from infolib import EncryptionHandler

port = int(sys.argv[1])
max_rcv = 10000

sock = socket.socket()
hashengine = SHA256.new()

proot = 3
#prime = 2959259
prime = 13
num = random.randrange(1, prime - 2, 1)
a = proot**num % prime

user = raw_input("Username:")
password = raw_input("Passwort:")

#if Checkbox Safe my data is checked:
hash_password = EncryptionHandler()
hash_password_output = hash_password.get_hash(password) #Give Password here

save_info_user = open("login_data_user", 'w')
save_info_user.write(user)
save_info_password = open("login_data_password", 'w')
save_info_password.write(hash_password_output)
message_input = raw_input("Ihre Nachricht:")

plain = "meop:8b2d38b789e90bb18567c2be4abbd4295f461f6453dd0447a3bf248a75eb0ae7"
#plain = user+":"+hash_password_output
print(plain)

msg = "dhex:12.12.12:x:x;" + str(a)

sock.connect(("127.0.0.1", port))
sock.send(msg)

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

data = re.split(":", data)
sesskey = int(data[1])**num % prime
iv = data[2]
iv = binascii.unhexlify(iv)
ctr = Counter.new(128, initial_value=long(iv.encode("hex"), 16))

hashengine.update(str(sesskey))
sesskey = hashengine.digest()

cipher = AES.new(sesskey, AES.MODE_CTR, counter=ctr)

msg = ""
msg += "auth" + ":"
msg += "12.12.12" + ":"
msg += data[0] + ";"
msg += cipher.encrypt(plain)

sid = data[0]

sock = socket.socket()
sock.connect(("127.0.0.1", port))
sock.send(msg)


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

cipher = AES.new(sesskey, AES.MODE_CTR, counter=ctr)
tmp = re.split(";", data, 1)
msg = cipher.decrypt(tmp[1])

print "Antwort auf Auth:" + msg

uidstring = msg
rcv_group = "asdf"

plain = uidstring + ":" + rcv_group + ":" +"test2"
msga = ""
msga += "brdc" + ":"
date = "12.12.12"
msga += date + ":"
msga += str(sid) + ";"
msga += cipher.encrypt(plain)

sock = socket.socket()
sock.connect(("127.0.0.1", port))
sock.send(msga)
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

cipher = AES.new(sesskey, AES.MODE_CTR, counter=ctr)
tmp = re.split(";", data, 1)
msg = cipher.decrypt(tmp[1])

print "Antwort auf Mesg:" + msg

sock.close()





#On Startup checks if the files are there
#try:
#	with open('/Users/jan/Desktop/moep.txt'): pass
#	auto_login = true
#except IOError: pass
#        auto_login = false

#if(auto_login == true):
#    open_info_user = open('login_data_user', 'r')
#    open_info_password = open('login_data_password', 'r')
    # send the info and request a confirmation from the server if not right send user to Login screen
#else:
    #Login screens
