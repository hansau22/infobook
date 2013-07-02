from Crypto.Cipher import AES as AES
from Crypto.Util import Counter as Counter
from hashlib import sha256

import  Crypto.Random as Random
import binascii

from re import split
from random import randrange


class EncryptionHandler:
    """ 
    Infolib.EncryptionHandler ist eine Klasse, die Funktionen zur Ver- und Entschluesselung
    von Strings bereithaelt. 

    Eine Verwendung ausserhalb des Infobook-Projektes wird nicht empfohlen.

    Es werden AES mit einem 256-Bit key im CTR-Modus als symmetrische Verschluesselung und
    SHA256 als Hashaglgorithmus verwendet.
    """

    def __init__(self):
        pass


    def is_encrypted(self, data):
        """
        Prueft ob ein Datenpaket verschluesslet ist - Nur fuer Server
        @param data: Datenpaket
        @type data: str
        @return: Boolean Erfolg
        """
        tmp = split(":", data, 2)
        # Nur DHEX-Pakete sind unverschluesselt
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
        # Eigenes Geheimnis erzeugen
        secret = randrange(1, prime - 2, 1)
        # B erzeugen
        b = proot**secret % prime
        # B uebersenden
        resp = str(sessid) + ":" + str(b) + ":"
        # Sessionkey aus den Uebertragenen Daten (A) generieren
        sesskey = self.generate_sesskey(secret, int(data), prime)

        # Initialisierungsvektor erstellen
        iv = Random.new().read(AES.block_size)
        # Initialisierungsvektor Hex-Encodieren und uebersenden
        resp += binascii.hexlify(iv)
        # Counter erstellen
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


        # Ergebnis Hashen
        sesskey = sha256(str(sesskey)).digest()

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
        return sha256(string).hexdigest()
