import socket
import re
from Crypto.Cipher import Blowfish
from Crypto import Random
import random

class connectionHandler:
    def __init__(self):
        self.sid_pool = 0
        self.sesskey = []
        
        
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

                    print "data:  "+data
                    data = re.split(";", data)
                    print data
                    header = self.parse_header(data[0])
                    data = data[1]

                    if header[0]== "dhex":
                        resp = self.init_dh(data)                      
                    elif header[0] == "auth":
                        resp = self.auth_user(data)
                    elif header[0] == "mesg":
                        resp = self.recv_msg(body)
                    elif header[0] == "file":
                        resp = self.recv_file(data)
                    
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
        
    # generates the AES sessionkey based on the algorithm of Diffie-Hellman

    def init_dh(self, data):
        print "a:  " + data
        sessid = self.sid_pool
        self.sid_pool += 1
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
        
        
        
        
conn = connectionHandler()
