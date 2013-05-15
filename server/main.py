import socket
import re
from Crypto.Cipher import Blowfish
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto import Random
import random
import sqlite3

class connectionHandler:
    def __init__(self):
        self.sid_pool = pool(0)
        self.sesskey = []
        self.ivs = []
        self.hashengine = SHA256.new()
        
        serv_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serv_soc.bind(("", 32322))
        serv_soc.listen(1)
        
        try:
            while True: 
                komm, addr = serv_soc.accept() 
                while True: 
                    data = komm.recv(1024)

                    if not data: 
                        komm.close() 
                        break
                        
                    if self.is_encrypted(data):
                        body = self.decrypt(data)

                    data = re.split(";", data)
                    header = self.parse_header(data[0])
                    data = data[1]
                    
                    resp = "invalid request"

                    if header[0]== "dhex":
                        resp = self.init_dh(data)                      
                    elif header[0] == "auth":
                        resp = self.auth_user(body)
                    elif header[0] == "mesg":
                        resp = self.recv_msg(body)
                    elif header[0] == "file":
                        resp = self.recv_file(body)
                    elif header[0] == "brdc":
                        resp = self.recv_brdc(body)
                    
                    komm.send(resp)
                    komm.close()
                    break
                    
        finally:
            serv_soc.close()
            
            
    def parse_header(self, data):
        return re.split(":", data)
        
    def is_encrypted(self, data):
        tmp = re.split(":", data)
        if tmp[0] == "dhex":
            return False
        return True
        
    # generates the Blowfish sessionkey based on the algorithm of Diffie-Hellman

    def init_dh(self, data):
        print "a:  " + data
        sessid = self.sid_pool.give_next()
        proot = 3
        #prime = 2959259
        prime = 13
        num = random.randrange(1, prime - 2, 1)
        b = proot**num % prime
        print "b:  " + str(b)
        resp = str(sessid) + ":" + str(b)
        sesskey = int(data)**num % prime
        self.sesskey.append(sesskey)
        print "sesskey:  " + str(sesskey)
        return resp
        
    def decrypt(self, data):
        tmp = re.split(";", data)
        skeyid = re.split(":", tmp[0])
        skeyid = skeyid[3]
        tmp = re.split(":", tmp[1])
        iv = tmp[0]
        cipher = Blowfish.new(str(self.sesskey[int(skeyid)]), Blowfish.MODE_CFB, "asdfasdf")
        return cipher.decrypt(tmp[1])
        
    def encrypt(self, data):
        tmp = re.split(":", data)
        iv = data[1]
        cipher = Blowfish.new(self.sesskey[int(data[0])], Blowfish.MODE_CFB, int(iv))
        return data[0] + ":" + iv + ":" + cipher.encrypt(data[2])
        
    def recv_msg(self, data):
        print data
        return ""
        
    def recv_file(self, data):
        
        return ""
    
    def auth_user(self, data):
        
        return ""
        
    
class databaseHandler:
    def __init__(self, database):
        self.db = sqlite3.connect(database)
        self.cursor = self.db.cursor()
        self.mid_pool = pool(0, self.get_last_mid())
    
    def init_db(self):
        self.cursor.execute("CREATE TABLE user(uid INTEGER, username TEXT, password TEXT)")
        self.cursor.execute("CREATE TABLE messages(mid INTEGER, uidsender INTEGER, uidreveiver INTEGER, content TEXT)")
        
        self.cursor.commit()
        
    def add_user(self, uid, username, pwhash):
        self.cursor.execute("INSERT INTO user VALUES(?, ?, ?)", (uid, username, pwhash))
        self.cursor.commit()
        
    def auth_user(self, username, pwhash):
        self.cursor.execute("SELECT * FROM user WHERE username=? AND password=?", (username, pwhash))
        if self.cursor.rowcount == 1:
            return True
        return False
        
    def rcv_message(self, uidSender, uidReceiver, data):
        if not isinstance(uidSender, int): return False
        if not isinstance(data, str): return False
        
        if not isinstance(uidReceiver, list):
            if not isinstance(uidReceiver, int):
                return False
            self.cursor.execute("INSERT INTO messages VALUES(?, ?, ?, ?)", (self.midpool.getNext(), uidSender, uidReveiver, data))
            
        else:
            for item in uidReceiver:
                self.cursor.execute("INSERT INTO messages VALUES(?, ?, ?, ?)", (self.midpool.getNext(), uidSender, item, data))
        
        self.cursor.commit()
    
    
    def get_last_mid(self):
        self.cursor.execute("SELECT mid FROM messages ORDER BY DSC")
        return self.cursor.fetchone()

# Pool: controls integer id's        
        
class pool:
    
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
       
        
        
conn = connectionHandler()
