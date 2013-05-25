import socket
import re
import sys
import os
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256
import random
import sqlite3
import dh

class ConnectionHandler:
    def __init__(self):
        self.database = DatabaseHandler("gu.db")
        self.sid_Pool = Pool(0)
        self.sesskey = []
        self.ivs = []
        self.uidstrings = []
        self.hashengine = SHA256.new()
        
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
                        
                    if self.is_encrypted(data):
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
            
            
    def parse_header(self, data):
        return re.split(":", data, 2)
        
    def build_pack(self, msg):
        print "msg:" + msg
        package = "none" + ":" + "12.12.12" + ":" + self.header[2] + ";"
        iv = "asdf"
        package += self.encrypt(msg)
        return package
        
    def is_encrypted(self, data):
        tmp = re.split(":", data, 2)
        if tmp[0] == "dhex":
            return False
        return True

    def init_dh(self, data):
        print "a:  " + data
        sessid = self.sid_Pool.give_next()
        proot = 3
        #prime = 2959259
        prime = 13
        num = random.randrange(1, prime - 2, 1)
        b = proot**num % prime
        #b = dh.generate_b()
        print "b:  " + str(b)
        resp = str(sessid) + ":" + str(b) + ":"
        sesskey = int(data)**num % prime
        self.hashengine.update(str(sesskey))
        sesskey = self.hashengine.digest()
        #iv = Random.new().read(AES.block_size)
        iv = 'asdfasdfasdfasdf'
        self.ivs.append(iv)
        self.sesskey.append(sesskey)
        self.uidstrings.append("")
        resp += iv
        print "sesskey:  " + str(sesskey)
        self.hashengine.update("")
        return resp
        
    def decrypt(self, data):
        tmp = re.split(";", data, 1)
        skeyid = re.split(":", tmp[0], 2)
        skeyid = int(skeyid[2])
        tmp = re.split(":", tmp[1], 1)
        iv = tmp[0]
        cipher = AES.new(self.sesskey[skeyid], AES.MODE_CFB, self.ivs[skeyid])
        dec = cipher.decrypt(tmp[0])
        dec = dec
        print dec
        return dec
        
    def encrypt(self, data):
        tmp = re.split(":", data ,1)
        iv = tmp[0]
        skeyid = int(self.header[2])
        cipher = AES.new(self.sesskey[skeyid], AES.MODE_CFB, self.ivs[skeyid])
        data = data
        return cipher.encrypt(data)
        
    def get_hash(self, string):
        self.hashengine.update(string)
        digest = self.hashengine.hexdigest()
        self.hashengine.update("")
        return digest
        
    def recv_msg(self, data):
        sid = int(self.header[2])
        tmp = re.split(":", data, 1)
        if self.uidstrings[sid] == tmp[0]:
            print tmp[1]
        else:
            print "error - wrong uidstring :" + tmp[0]
        return ""
        
    def recv_file(self, data):
        
        return ""
    
    def auth_user(self, data):
        cred = re.split(":", data, 1)
        if self.database.auth_user(cred[0], cred[1]) == True:
            dig = self.get_hash(self.sesskey[int(self.header[2])] + cred[0])
            self.uidstrings[int(self.header[2])] = dig
            return dig
        else:
            return "wrong creditials"
            
        
    
class DatabaseHandler:
    def __init__(self, database):
        self.db = sqlite3.connect(database)
        self.cursor = self.db.cursor()
        self.mid_Pool = Pool(0, self.get_last_mid())
        self.init_db()
    
    def init_db(self):
        self.cursor.execute("CREATE TABLE IF NOT EXISTS user(uid INTEGER, username TEXT, password TEXT)")
        self.cursor.execute("CREATE TABLE IF NOT EXISTS messages(mid INTEGER, uidsender INTEGER, uidreveiver INTEGER, content TEXT)")
        self.db.commit()
        
    def add_user(self, uid, username, pwhash):
        self.cursor.execute("INSERT INTO user VALUES(?, ?, ?)", (uid, username, pwhash))
        self.db.commit()
        
    def auth_user(self, username, pwhash):
        self.cursor.execute("SELECT * FROM user WHERE username=? AND password=?", (username, pwhash))
        if self.cursor.fetchone() != None:
            return True
        return False
        
    def rcv_message(self, uidSender, uidReceiver, data):
        if not isinstance(uidSender, int): return False
        if not isinstance(data, str): return False
        
        if not isinstance(uidReceiver, list):
            if not isinstance(uidReceiver, int):
                return False
            self.cursor.execute("INSERT INTO messages VALUES(?, ?, ?, ?)", (self.midPool.getNext(), uidSender, uidReveiver, data))
            
        else:
            for item in uidReceiver:
                self.cursor.execute("INSERT INTO messages VALUES(?, ?, ?, ?)", (self.midPool.getNext(), uidSender, item, data))
        
        self.db.commit()
    
    
    def get_last_mid(self):
        #self.cursor.execute("SELECT mid FROM messages ORDER BY DSC")
        #return self.cursor.fetchone()
        return 0

# Pool: controls integer id's        
        
class Pool:
    
    ##
    # max_num = highest possible number - 0 for unlimited
    # typ = type - int or char
    ##
    
    def __init__(self, max_num, start = None):
        if (start == None) or not isinstance(start, int):
            self.cur = 0
        else:
            self.cur = start
            
        if (max_num == 0) or not isinstance(max_num, int):
            self.max_num = None
        else:
            self.max_num = max_num
            
        self.free = []
    
    def give_next(self):
        if (self.cur != self.max_num) or (self.max_num == None):
            ret = self.cur
            self.cur += 1
            return ret
        
        if len(self.free) < 0:
            return False
        return self.free.pop()
    
    def remove(self, num):
        if isinstance(num, int):
            self.free.append(num)
       
        
        
conn = ConnectionHandler()
