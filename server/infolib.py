from Crypto.Cipher import AES as AES
from Crypto.Hash import SHA256 as SHA256
from Crypto.Util import Counter as Counter
import binascii
import sqlite3




class EncryptionHandler:
    """ 
    Infolib.EncryptionHandler ist eine Klasse, die Funktionen zur Ver- und Entschluesselung
    von Strings bereithaelt. Sie ist ausschliesslich zur Verwendung in Programmen, die mit dem Infoserver
    kommunizieren, gedacht.

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
        tmp = re.split(":", data, 2)
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
        num = random.randrange(1, prime - 2, 1)
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


class DatabaseHandler:
    """
    Infolib.DatabaseHandler ist eine Klasse, die den Datenbankzugriff auf eine sqlite3-Datenbank fuer den Infobook-Server
    regelt.

    Eine Verwendung ausserhalb des Infobook-Projektes ist nicht gewaehrleistet.
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
        self.mid_Pool = Pool(0, self.get_start_mid())
        self.init_db()
    
    def init_db(self):
        """
        Initialisert die Datenbank

        @return: None
        """
        self.cursor.execute("CREATE TABLE IF NOT EXISTS user(uid INTEGER, username TEXT, password TEXT)")
        self.cursor.execute("CREATE TABLE IF NOT EXISTS messages(mid INTEGER, uidsender INTEGER, uidreveiver INTEGER, content TEXT)")
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
        self.cursor.execute("SELECT uid FROM user WHERE username=?", [username])
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
    
    def get_start_mid(self):
        """
        Gibt die erste freie Nachrichten-ID zurueck

        @return: int ID
        """
        self.cursor.execute("SELECT mid FROM messages ORDER BY mid DESC")
        result = self.cursor.fetchone()
        return (result[0] + 1)


class Pool:
    """ Infolib.Pool ist eine Klasse, die Indizes verwaltet."""

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
        
        if len(self.free) < 0:
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


