from  libinfo.EncryptionHandler import EncryptionHandler
from  libinfo.DatabaseHandler import DatabaseHandler
#from  libinfo import DatabaseHandler
from  libinfo.Pool import Pool

import binascii
import socket
import sys
import os

from re import split


class ConnectionHandler:
    """
    Infolib.ConnectionHandler ist eine Klasse, die die Grundfunktionalitaet des Infoservers bereitstellt.
    Sie bindet einen Port, an dem alle Verbindungen eigehen und verteilt die Pakete nach den entsprechenden Kopfinformationen.
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
        self.sid_Pool = Pool(0)

        self.users = []         # Nutzer, die zum Index Session-ID gehoeren
        self.ivs = []           # Initialiserungsvektoren
        self.ctr = []           # Counter
        self.sesskey = []       # Sessionkeys
        self.uidstrings = []    # User-ID-Strings
        
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

                    # Kopfdaten und Nutzdaten trennen
                    data = split(";", data, 1)
                    self.header = self.parse_header(data[0])
                    data = data[1]
                    
                    resp = "invalid request" # Default-Antwort

                    if self.header[0] == "dhex":
                        resp = self.init_dh(data)                      
                    elif self.header[0] == "auth":
                        resp = self.auth_user(body)
                    elif self.header[0] == "mesg":
                        resp = self.recv_msg(body)
                    elif self.header[0] == "getmesg":
                        resp = self.get_msg(body)
                    elif self.header[0] == "file":
                        resp = self.recv_file(body)
                    elif self.header[0] == "brdc":
                        resp = self.recv_brdc(body)
                    elif self.header[0] == "getbrdc":
                        resp = self.get_brdc(body)
                    

                    # Antwortpaket senden
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

        # DH-Antwort (B) auf die Anfrage (A)
        ret = self.crypt.init_dh_b(self.sid_Pool.give_next(),data)

        # Alle Felder fuer die neu Initialiserte Session reservieren (befuellen)
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

        tmp = split(";", data, 1)       # ";" Seperiert Nutz- und Kopfdaten
        sid = split(":", tmp[0], 2)     # Extrahiere Session-ID
        sid = int(sid[2])
        data = self.crypt.decrypt(self.sesskey[sid], self.ctr[sid], tmp[1])
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

            # User-ID String erzeugen
            dig = self.crypt.get_hash(self.sesskey[self.header[2]] + cred[0])

            self.uidstrings[self.header[2]] = dig
            self.users[self.header[2]] = self.database.get_user_id(cred[0])

            return dig
        else:
            return "error - wrong-credentials"



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

        # Nicht alle Felder gegeben
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



    def get_msg(self, data):
        """
        Gibt dem Client die Nachrichten zurueck. 

        @param data: Letzte MID, die der Client an den Server gibt.
        @type data: str

        @return: Array - Nachrichten
        """

        messages = self.database.get_messages_by_last_mid(self.header[2], data)
        ret_msg = []

        for item in messages:
            username = self.database.get_user_by_id(item[0])

            if username == None:
                username = "Nutzer unbekannt"

            ret_msg.append(username + ":" + item[1])

        ret_msg.append("[FIN]")
        return ret_msg



    def get_brdc(self, data):
        """
        Gibt dem Client die Gruppennachrichten zurueck.

        @param data: Letzte GID, die der Client an den Server gibt.
        @type data: str

        @return: Array - Nachrichten
        """

        messages = self.database.get_messages_by_last_gid(self.header[2], data)
        ret_msg = []

        for item in messages:
            groupname = self.database.get_group_by_id(item[0])

            if groupname == None:
                groupname = "Gruppenname unbekannt"

            ret_msg.append(groupname + ":" + item[1])

        ret_msg.append("[FIN]")
        return ret_msg



    def recv_brdc(self, data):
        """
        Traegt eine Broadcast-Nachricht in die Datenbank ein.

        @param data: Datenpaket des Clients ohne Kopfinformationen
        @type data: str

        @return: str - Erfolgs-/Fehlermeldung
        """
        sid = self.header[2]
        tmp = split(":", data, 2)

        # Nicht alle Felder gegeben
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