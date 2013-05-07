import socket
import re
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

                    data = re.split(";", data)
                    header = self.parse_header(data[0])
                    data = data[1]

                    if header[0]== "dhex":
                        resp = self.init_dh(data)
                    elif header[0].lowercase() == "auth":
                        resp = self.auth_user(data)
                    elif header[0].lowercase() == "mesg":
                        resp = self.recv_msg(data)
                    elif header[0].lowercase() == "file":
                        resp = self.recv_file(data)
                    
                    komm.send(resp)
                    komm.close()
                    break
                    
        finally:
            serv_soc.close()
            
            
    def parse_header(self, data):
        return re.split(":", data)
        
    # generates the AES sessionkey based on the algorithm of Diffie-Hellman

    def init_dh(self, data):
        sessid = self.sid_pool
        self.sid_pool += 1
        proot = 2
        prime = 2959758 # related 6144-group RFC 3546
        num = random.randrange(1, prime - 2, 1)
        b = proot**num % prime
        resp = str(sessid) + ":" + str(b)
        sesskey = int(data)**proot % prime
        self.sesskey.append(sesskey)
        return resp
        
        
conn = connectionHandler()
