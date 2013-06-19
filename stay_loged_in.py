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

#if Checkbox Safe my data is checked:
hash_user = EncryptionHandler()
hash_password = EncryptionHandler()
hash_passord_output = hash_password.get_hash(password) #Give Password here
hash_user_output = hash_user.get_hash(user) #Give User here

save_info_user = open('login_data_user', 'w')
safe_info.write(hash_user_output)
save_info_password = open('login_data_password', 'w')
safe_info.write(hash_password_output)


#On Startup checks if the files are there
try:
	with open('/Users/jan/Desktop/moep.txt'): pass
	auto_login = true
except IOError: pass
	auto_login = false

if(auto_login = true):
    open_info_user = open('login_data_user', 'r')
    open_info_password = open('login_data_password', 'r')
    # send the info and request a confirmation from the server if not right send user to Login screen
else:
    #Login screen
