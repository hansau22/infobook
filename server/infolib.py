from Crypto.Cipher import AES as AES
from Crypto.Hash import SHA256 as SHA256
from Crypto.Util import Counter as Counter
from Crypto import Random
import binascii
import sqlite3
import socket
import sys
import os
from re import split
from random import randrange
from re import split


class ConnectionHandler:
    """
    Infolib.ConnectionHandler ist eine Klasse, die die Grundfunktionalitaet des Infoservers bereitstellt.
    Sie bindet einen Port, an dem alle Verbindungen eigehen und verteilt die Pakete nach den entsprechenden Kopfinformationen
    Sie baut auf allen anderen Klassen in der Infolib auf.

    Eine Verwendung ausserhalb des Infobook-Projektes wird nicht empfohlen.

    Eine Dokumentation des Ablaufes finden Sie im GitHub-Wiki unter https://github.org/hansau22/infobook/
    """

    def __init__(self):
        """
        Initialisierung und Binden des Ports.
        Der Port kann via Shell-Argument uebergeben werden, sonst wird versucht, Port 32323 zu binden.

        @return: None
        """


        self.database = DatabaseHandler("gu.db")
        self.crypt = EncryptionHandler()
        self.users = []

        self.ivs = []
        self.ctr = []
        self.sesskey = []
        self.uidstrings = []
        self.sid_Pool = Pool(0)
        
        serv_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if len(sys.argv) < 2:
            serv_soc.bind(("", 32323))
        else:
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

                    data = split(";", data, 1)
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
        """
        Initialisiert den DH-Schluesselaustausch anhand der Informationen aus der Anfrage des Clients.

        @param data: Enthaelt den Oeffentlichen Teil vom Partner
        @type data: str

        @return: str - Sessionkey
        """
        ret = self.crypt.init_dh_b(self.sid_Pool.give_next(),data)
        self.users.append("")
        self.uidstrings.append("")
        self.ivs.append(ret[0])
        self.ctr.append(ret[1])
        self.sesskey.append(ret[2])
        return ret[3]



    def decrypt(self, data):
        """
        Entschluesselt ein Datenpaket mit dem Sessionkey, der zur Session-ID gehoert.

        @param data: Verschluesseltes Paket mit unverschluesselten Kopfinformationen
        @type data: str

        @return: str - Unverschluesseltes Paket ohne Kopfinformationen
        """

        tmp = split(";", data, 1)
        sid = split(":", tmp[0], 2)
        sid = int(sid[2])
        tmp = split(":", tmp[1], 1)
        data = self.crypt.decrypt(self.sesskey[sid], self.ctr[sid], tmp[0])
        return data


            
    def encrypt(self, data):
        """
        Verschluesselt die Daten fuer ein Paket.

        @param data: Daten-String ohne Kopfinformationen
        @type data: str

        @return: Verschluesselt Datenpaket ohne Kopfinformationen
        """
        sid = self.header[2]
        return self.crypt.encrypt(self.sesskey[sid], self.ctr[sid], data)


            
    def parse_header(self, data):
        """
        Verarbeitet Kopfinformationen und wandelt die Informationen in benoetigte Typen

        @param data: Kopfinformationen
        @type data: str

        @return: Array - Kopfinformationen
        """
        header = split(":", data, 2)
        if not header[0] == "dhex":
            header[2] = int(header[2])
        return header
        


    def build_pack(self, msg):
        """
        Erstellt die Kopfinformationen fuer ein Datenpaket und fuegt die Nachricht an.

        @param msg: Nachricht ohne Kopfinformationen
        @type msg: str

        @return: str - Nachrichtenpaket mit Kopfinformationen
        """
        package = "none" + ":" + "12.12.12" + ":" + str(self.header[2]) + ";"
        iv = "asdf"
        package += self.encrypt(msg)
        return package



    def auth_user(self, data):
        """
        Prueft ob eine Nutzer-Passwort Kombination valid ist.

        @param data: Paket des Clients ohne Kopfinformationen
        @type data: str

        @return: str - Digest, der die Nutzer-ID-Strings enthaelt
        """
        cred = split(":", data, 1)
        if self.database.auth_user(cred[0], cred[1]) == True:
            dig = self.crypt.get_hash(self.sesskey[self.header[2]] + cred[0])
            self.uidstrings[self.header[2]] = dig
            self.users[self.header[2]] = self.database.get_user_id(cred[0])
            return dig
        else:
            return "error - wrong-creditials"



    def check_uidstring(self, index, string):
        """
        Vergleicht einen Nutzer-ID-String mit dem, der zu dem Nutzer mit der Session-ID gehoert.

        @param index: Session-ID
        @type index: int

        @param string: Nutzer-ID-String
        @type string: str

        @return: Boolean - Ergebnis
        """
        if self.uidstrings[index] == string:
            return True
        return False


        
    def recv_msg(self, data):
        """
        Traegt eine Nachricht in die Datenbank ein.

        @param data: Datenpaket des Clients ohne Kopfinformationen
        @type data: str

        @return: str - Erfolgs-/Fehlermeldung
        """
        sid = self.header[2]
        tmp = split(":", data, 2)
        if len(tmp) != 3:
            return "error - not-long-enough - MESG"

        if self.check_uidstring(sid, tmp[0]):
            rcv_uid = self.database.get_user_id(tmp[1])
            snd_uid = self.users[self.header[2]]
            print "writing message:" + tmp[2]
            if not self.database.rcv_message(snd_uid, rcv_uid, tmp[2]):
                return "error - server-application-error - MESG"
            return "success - MESG"
        else:
            return "error - wrong-uidstring - MESG"


    def recv_brdc(self, data):
        """
        Traegt eine Broadcast-Nachricht in die Datenbank ein.

        @param data: Datenpaket des Clients ohne Kopfinformationen
        @type data: str

        @return: str - Erfolgs-/Fehlermeldung
        """
        sid = self.header[2]
        tmp = split(":", data, 2)
        if len(tmp) != 3:
            return "Not long enough - BRDC"

        if self.check_uidstring(sid, tmp[0]):
            rcv_gid = self.database.get_group_id(tmp[1])
            snd_uid = self.users[self.header[2]]
            print "writing message:" + tmp[2]
            if not self.database.rcv_brdc_message(snd_uid, rcv_gid, tmp[2]):
                return "error - server-application-error - BRDC"
            return "success - BRDC"
        else:
            return "error - wrong-uidstring - BRDC"

        
    def recv_file(self, data):
        """
        Empfaengt eine Datei. - Noch nicht implementiert
        """
        
        return ""





class DatabaseHandler:
    """
    Infolib.DatabaseHandler ist eine Klasse, die den Datenbankzugriff auf eine sqlite3-Datenbank fuer den Infobook-Server
    regelt.

    Eine Verwendung ausserhalb des Infobook-Projektes wird nicht empfohlen.
    """

    def __init__(self, database):
        """
        Initialisierung

        @param database: Pfad zur Datenbank
        @type database: str

        @return: None
        """
        self.db = sqlite3.connect(database)
        self.cursor = self.db.cursor()
        self.init_db()
        self.mid_Pool = Pool(0, self.get_start_mid())
        self.bid_Pool = Pool(0, self.get_start_brdc_mid())


    
    def init_db(self):
        """
        Initialisert die Datenbank

        @return: None
        """
        self.cursor.execute("CREATE TABLE IF NOT EXISTS user(uid INTEGER, username TEXT, password TEXT)")
        self.cursor.execute("CREATE TABLE IF NOT EXISTS messages(mid INTEGER, uidsender INTEGER, uidreveiver INTEGER, content TEXT)")
        self.cursor.execute("CREATE TABLE IF NOT EXISTS brdc_message(bid INTEGER, uidsender INTEGER, gidreveiver INTEGER, content TEXT)")
        self.cursor.execute("CREATE TABLE IF NOT EXISTS brdc_groups(gid Integer, member Integer, name Text)")

        self.db.commit()


        
    def add_user(self, uid, username, pwhash):
        """
        Fuegt einen Nutzer zur Datenbank hinzu

        @param uid: Nutzer-ID
        @type uid: int

        @param username: Nutzername
        @type username: str

        @param pwhash: SHA256-Verschluesselter Passwort-Hash
        @type pwhash: str

        @return: None
        """
        self.cursor.execute("INSERT INTO user VALUES(?, ?, ?)", (uid, username, pwhash))
        self.db.commit()


        
    def auth_user(self, username, pwhash):
        """
        Prueft Nutzer-Passwort Kombination

        @param username: Nutzername
        @type username: str

        @param pwhash: SHA256-Verschluesselter Passwort-Hash
        @type pwhash: str

        @return: None
        """ 
        self.cursor.execute("SELECT * FROM user WHERE username=? AND password=?", (username, pwhash))
        if self.cursor.fetchone() != None:
            return True
        return False



    def get_user_id(self, username):
        """
        Gibt die Nutzer-ID eines Benutzers zurueck

        @param username: Nutzername
        @type username: str

        @return: str Nutzer-ID, False bei unbekanntem Nutzer
        """
        self.cursor.execute("SELECT * FROM user WHERE username=?", [username])
        result = self.cursor.fetchone()
        if result == None:
            return False
        return result[0]


    def get_group_id(self, name):
        """
        Gibt die Gruppen-ID einer Gruppe zurueck

        @param username: Gruppenname
        @type username: str

        @return: str Gruppen-ID, False bei unbekannter Gruppe
        """
        self.cursor.execute("SELECT * FROM brdc_groups WHERE name=?", [name])
        result = self.cursor.fetchone()
        if result == None:
            return False
        return result[0]

        
    def rcv_message(self, uidSender, uidReceiver, data):
        """
        Traegt eine Nachricht in die Datenbank ein

        @param uidSender: Nutzer-ID des Senders
        @type uidSender: int

        @param uidReceiver: Nutzer-ID des Empfaengers
        @type uidReceiver: int

        @param data: Nachricht
        @type data: Nachricht

        @return: Boolean Erfolg
        """
        if not isinstance(uidSender, int): return False
        if not isinstance(data, str): return False
        
        if not isinstance(uidReceiver, list):
            self.cursor.execute("INSERT INTO messages VALUES(?, ?, ?, ?)", (self.mid_Pool.give_next(), uidSender, uidReceiver, data))
        else:
            for item in uidReceiver:
                self.cursor.execute("INSERT INTO messages VALUES(?, ?, ?, ?)", (self.mid_Pool.give_next(), uidSender, item, data))
        
        self.db.commit()
        return True


    def rcv_brdc_message(self, uidSender, gidReceiver, data):
            """
            Traegt eine Broadcast-Nachricht in die Datenbank ein

            @param uidSender: Nutzer-ID des Senders
            @type uidSender: int

            @param uidReceiver: Gruppen-ID des Empfaengers
            @type uidReceiver: int

            @param data: Nachricht
            @type data: Nachricht

            @return: Boolean Erfolg
            """
            if not isinstance(uidSender, int): return False
            if not isinstance(gidReceiver, int): return False
            if not isinstance(data, str): return False
            
            self.cursor.execute("INSERT INTO brdc_message VALUES(?, ?, ?, ?)", (self.bid_Pool.give_next(), uidSender, gidReceiver, data))
            self.db.commit()
            return True

    
    def get_start_mid(self):
        """
        Gibt die erste freie Nachrichten-ID zurueck

        @return: int ID
        """
        self.cursor.execute("SELECT mid FROM messages ORDER BY mid DESC")
        result = self.cursor.fetchone()
        if result == None:
            return 0
        return (result[0] + 1)



    def get_start_brdc_mid(self):
        """
        Gibt die erste freie Broadcast-Nachrichten-ID zurueck

        @return: int ID
        """
        self.cursor.execute("SELECT bid FROM brdc_message ORDER BY bid DESC")
        result = self.cursor.fetchone()
        if result == None:
            return 0
        return (result[0] + 1)




class EncryptionHandler:
    """ 
    Infolib.EncryptionHandler ist eine Klasse, die Funktionen zur Ver- und Entschluesselung
    von Strings bereithaelt. 

    Eine Verwendung ausserhalb des Infobook-Projektes wird nicht empfohlen.

    Es werden AES mit einem 265-Bit key im CTR-Modus als symmetrische Verschluesselung und
    SHA256 als Hashaglgorithmus verwendet.
    """

    def __init__(self):
        self.hashengine = SHA256.new()
        """Initialisierung der Hashengine""" 



    def is_encrypted(self, data):
        """
        Prueft ob ein Datenpaket verschluesslet ist - Nur fuer Server
        @param data: Datenpaket
        @type data: str
        @return: Boolean Erfolg
        """
        tmp = split(":", data, 2)
        if tmp[0] == "dhex":
            return False
        return True



    def init_dh_b(self, sessid, data):
        """ 
        Initialisierung des DH-Schluesselaustausches von B
        Vorraussetzung ist, dass A bereits in data enthalten ist.
        @param sessid: die neue Session-ID - wird dem Antwortpaket mitgegeben
        @type sessid: int

        @param data: Enthaelt A des Partners
        @type data: str

        @return: Array - [Initialisrungsverktor(str), Counter(counter), Sessionkey(str), Antwortpaket(str)]

        """
        #prime = 2959259
        prime = 13
        proot = 3
        num = randrange(1, prime - 2, 1)
        secret = proot**num % prime
        resp = str(sessid) + ":" + str(secret) + ":"
        sesskey = self.generate_sesskey(num, int(data), prime)

        iv = Random.new().read(AES.block_size)
        resp += binascii.hexlify(iv)
        ctr = Counter.new(128, initial_value=long(iv.encode("hex"), 16))

        ret = []
        ret.append(iv)
        ret.append(ctr)
        ret.append(sesskey)
        ret.append(resp)
        return ret



    def generate_sesskey(self, secret, public, prime):
        """
        Generiert den Sessionkey nach DH

        @param secret: geheime, eigene Nummer
        @type secret: int

        @param public: Ergebnis des Partners
        @type public: int

        @param prime: Primzahl
        @type prime: int

        @return: int - Sessionkey
        """

        sesskey = public**secret % prime
        self.hashengine.update(str(sesskey))
        sesskey = self.hashengine.digest()
        self.hashengine.update("")
        return sesskey


        
    def decrypt(self, sesskey, counter, data):
        """
        Entschluesselt einen String

        @param sesskey: Sessionkey
        @type sesskey: str

        @param counter: Counter
        @type counter: Counter-Objekt

        @param data: Daten-String
        @type data: str

        @return: str - Entschluesselter Daten-String
        """
        cipher = AES.new(sesskey, AES.MODE_CTR, counter=counter)
        dec = cipher.decrypt(data)
        return dec


        
    def encrypt(self, sesskey, counter, data):
        """
        Verschluesselt einen String

        @param sesskey: Sessionkey
        @type sesskey: str

        @param counter: Counter
        @type counter: Counter-Objekt

        @param data: Daten-String
        @type data: str

        @return: str - Verschluesselter Daten-String
        """
        cipher = AES.new(sesskey, AES.MODE_CTR, counter=counter)
        enc = cipher.encrypt(data)
        return enc


        
    def get_hash(self, string):
        """
        Generiert einen SHA256-Hash (Eine Runde)

        @param string: Eingabe-String
        @type string: str

        @return: str - Digest
        """
        self.hashengine.update(string)
        digest = self.hashengine.hexdigest()
        self.hashengine.update("")
        return digest




class Pool:
    """ 
    Infolib.Pool ist eine Klasse, die Indizes verwaltet.

    Eine Verwendung ausserhalb des Infobook-Projektes wird nicht empfohlen, ist aber moeglich.
    """

    def __init__(self, max_num, start = None):
        """
        @param max_num: Maxium, das nicht ueberschritten wird
        @type max_num: int

        @param start: Erste zahl, die vergeben wird
        @type start: int

        @return: None
        """
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
        """
        Gibt den naechsten freien Index
        @return: int Index, False falls max_num ueberschritten werden wuerde
        """
        if (self.cur != self.max_num) or (self.max_num == None):
            ret = self.cur
            self.cur += 1
            return ret
        
        if len(self.free) < 1:
            return False

        return self.free.pop()


    
    def remove(self, num):
        """
        Entfernt ein Index, d.h. er kann wieder vergeben werden
        @param num: nummer, die frei wird
        @type num: int
        @return: None
        """
        if isinstance(num, int):
            self.free.append(num)