import socket
import re
import sys
import os
import random
import dh
from infolib import *

class ConnectionHandler:

    def __init__(self):
        self.database = DatabaseHandler("gu.db")
        self.crypt = EncryptionHandler()
        self.users = []

        self.ivs = []
        #: Enthaelt die Initialisierungsvektoren
        self.ctr = []
        #: Enthaelt die Counter
        self.sesskey = []
        #: Enthaelt die Sessionkeys
        self.uidstrings = []
        #: Enthaelt die User-ID-Strings
        self.sid_Pool = Pool(0)
        
        serv_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serv_soc.bind(("", int(sys.argv[1])))
        serv_soc.listen(1)
        
        try:
            while True: 
                komm, addr = serv_soc.accept() 
                while True: 
                    data = komm.recv(8192)

                    if not data: 
                        komm.close() 
                        break
                        
                    if self.crypt.is_encrypted(data):
                        body = self.decrypt(data)

                    data = re.split(";", data, 1)
                    self.header = self.parse_header(data[0])
                    data = data[1]
                    
                    resp = "invalid request"

                    if self.header[0] == "dhex":
                        resp = self.init_dh(data)                      
                    elif self.header[0] == "auth":
                        resp = self.auth_user(body)
                    elif self.header[0] == "mesg":
                        resp = self.recv_msg(body)
                    elif self.header[0] == "file":
                        resp = self.recv_file(body)
                    elif self.header[0] == "brdc":
                        resp = self.recv_brdc(body)
                    
                    if self.header[0] == "dhex":
                        komm.send(resp)
                    else:
                        komm.send(self.build_pack(resp))
                        
                    komm.close()
                    break
                    
        finally:
            serv_soc.close()

    def init_dh(self, data):
        ret = self.crypt.init_dh_b(self.sid_Pool.give_next(),data)
        self.users.append("")
        self.uidstrings.append("")
        self.ivs.append(ret[0])
        self.ctr.append(ret[1])
        self.sesskey.append(ret[2])
        return ret[3]

    def decrypt(self, data):
        tmp = re.split(";", data, 1)
        sid = re.split(":", tmp[0], 2)
        sid = int(sid[2])
        tmp = re.split(":", tmp[1], 1)
        data = self.crypt.decrypt(self.sesskey[sid], self.ctr[sid], tmp[0])
        return data
            
    def encrypt(self, data):
        sid = self.header[2]
        return self.crypt.encrypt(self.sesskey[sid], self.ctr[sid], data)
            
    def parse_header(self, data):
        header = re.split(":", data, 2)
        if not header[0] == "dhex":
            header[2] = int(header[2])
        return header
        
    def build_pack(self, msg):
        package = "none" + ":" + "12.12.12" + ":" + str(self.header[2]) + ";"
        iv = "asdf"
        package += self.encrypt(msg)
        return package


    def auth_user(self, data):
        cred = re.split(":", data, 1)
        if self.database.auth_user(cred[0], cred[1]) == True:
            dig = self.crypt.get_hash(self.sesskey[self.header[2]] + cred[0])
            self.uidstrings[self.header[2]] = dig
            self.users[self.header[2]] = self.database.get_user_id(cred[0])
            return dig
        else:
            return "wrong creditials"


    def check_uidstring(self, index, string):
        if self.uidstrings[index] == string:
            return True
        return False
        
    def recv_msg(self, data):
        sid = self.header[2]
        tmp = re.split(":", data, 2)
        if len(tmp) != 3:
            return "Not long enough"

        if self.check_uidstring(sid, tmp[0]):
            rcv_uid = self.database.get_user_id(tmp[1])
            snd_uid = self.users[self.header[2]]
            if not self.database.rcv_message(snd_uid, rcv_uid, tmp[2]):
                print "error in rcv_message"
        else:
            print "error - wrong uidstring :" + tmp[0]
        return ""
        
    def recv_file(self, data):
        
        return ""


       
conn = ConnectionHandler()