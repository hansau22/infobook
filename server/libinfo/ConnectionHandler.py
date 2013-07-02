from  libinfo.EncryptionHandler import EncryptionHandler
from  libinfo.DatabaseHandler import DatabaseHandler
#from  libinfo import DatabaseHandler
from  libinfo.Pool import Pool

import socket
import select
import sys
import os
import string

from re import split
from random import choice


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

        self.file_storage = "./files/"
        self.max_rcv = 4096

        self.users = []         # Nutzer, die zum Index Session-ID gehoeren
        self.ivs = []           # Initialiserungsvektoren
        self.ctr = []           # Counter
        self.sesskey = []       # Sessionkeys
        self.uidstrings = []    # User-ID-Strings
        
        #serv_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #file_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        serv_soc = socket.socket()
        file_soc = socket.socket()

        if len(sys.argv) < 2:
            serv_soc.bind(("", 32323))
            file_soc.bind(("", 32324))
        else:
            serv_soc.bind(("", int(sys.argv[1])))
            file_soc.bind(("", int(sys.argv[1]) + 1))

        serv_soc.listen(1)
        file_soc.listen(1)

        clients = []
        file_sender = []
        
        try:
            while True:

                read, write, oob = select.select([serv_soc, file_soc], [], [])

                for sock in read:

                    # Verbindungsaufbauf fand auf der Server-Socket statt
                    if sock is serv_soc:
                        komm, addr = sock.accept()
                        data = ""
                        data = komm.recv(self.max_rcv)

                        # Leere Verbindung
                        if not data: 
                            komm.close()
                            continue

                        # Datenpaket ist verschluesslt (= Kein DHEX-Paket)    
                        if self.crypt.is_encrypted(data):
                            body = self.decrypt(data)

                        # Kopfdaten und Nutzdaten trennen
                        data = split(";", data, 1)
                        self.header = self.parse_header(data[0])
                        data = data[1]

                        # Datenpaket encoden
                        if self.header[0] != "dhex":
                            self.encode_to_utf8(body)
                        
                        resp = "error - invalid-client-request" # Default-Antwort

                        if self.header[0] == "dhex":
                            resp = self.init_dh(data)                      
                        elif self.header[0] == "auth":
                            resp = self.auth_user(body)
                        elif self.header[0] == "msg":
                            resp = self.recv_msg(body)
                        elif self.header[0] == "getmsg":
                            resp = self.get_msg(body)
                        elif self.header[0] == "gmsg":
                            resp = self.recv_gmsg(body)
                        elif self.header[0] == "getgmsg":
                            resp = self.get_gmsg(body)
                        elif self.header[0] == "regfile":
                            resp = self.register_file(body)


                        if "error" in resp:
                            print "error:  " + resp
                        

                        # Antwortpaket senden
                        if self.header[0] == "dhex":
                            #print "dhex resp" + resp
                            resp = self.encode_to_utf8(resp)
                            komm.send(resp)
                        else:
                            komm.send(self.build_pack(resp))
                            
                        komm.close()

                    # Verbindung wurde ueber Dateisendungs-Socket aufgebaut
                    elif sock is file_soc:
                        komm, addr = sock.accept()

                        filestring = self.generate_file_string()
                        targ_file = self.file_storage + filestring
                        f = open(targ_file, 'wb')

                        data = komm.recv(self.max_rcv)
                        while data and data != "[FIN]":
                            f.write(data)
                            data = komm.recv(self.max_rcv)
                        
                        komm.send(filestring)
                        print filestring
                        komm.close()
                        f.close()

                        self.database.add_file(filestring)
                        
        finally:
            for client in clients: 
                client.close() 
            serv_soc.close()
            file_soc.close()


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

        #print "sesskey :  " + ret[2]

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



    def encode_to_utf8(self, data):
        """
        Dekodiert einen String in UTF-8

        @param data: String
        @type data: str

        @return: str - UTF-8 dekodierter String
        """

        return data.decode("utf-8")

            
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

        @return: str - Digest, der den Nutzer-ID-String enthaelt
        """
        cred = split(":", data, 1)
        if len(cred) < 2:
            return "error - not-enough-arguments - AUTH"

        if self.database.auth_user(cred[0], cred[1]) == True:

            # User-ID String erzeugen
            dig = self.crypt.get_hash(self.sesskey[self.header[2]] + cred[0])

            self.uidstrings[self.header[2]] = dig
            self.users[self.header[2]] = self.database.get_user_id(cred[0])

            return dig
        else:
            return "error - wrong-credentials - AUTH"



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



    def get_gmsg(self, data):
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



    def recv_gmsg(self, data):
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
            return "error - not-enough-arguments - BRDC"

        if self.check_uidstring(sid, tmp[0]):
            rcv_gid = self.database.get_group_id(tmp[1])
            snd_uid = self.users[self.header[2]]
            print "writing message:" + tmp[2]
            if not self.database.rcv_brdc_message(snd_uid, rcv_gid, tmp[2]):
                return "error - server-application-error - BRDC"
            return "success - BRDC"
        else:
            return "error - wrong-uidstring - BRDC"



    def register_file(self, data):
        """
        Registriert eine Datei (Setzt den Besitzer zu einem Upload und gibt Dateinamen an)

        @param data: Datenpaket des Clients ohne Kopfinformationen
        @type data: str

        @return: str - Erfolgs-/Fehlermeldung
        """
        values = split(data, ":", 2)
        if len(values) < 2:
            return "error - file"

        filestring = values[0]
        global_name = values[1]
        del values

        if not self.database.check_filestring(filestring):
            return "error - wrong-filestring"

        if not self.database.register_file(self.users[self.header[2]], global_name, filestring):
            return "error - server-storage-error"
        else:
            return "soccess - FILE"



    def create_file(self, path):
        """
        Erzeugt eine Datei.

        @param path: Dateipfad
        @type pyth: string
        @retun: Boolean Erfolg
        """

        f = open(path, 'w')
        f.write('')
        f.close()

        return True


    def generate_file_string(self):
        """
        Generiert einen Datei-String fuer eine neu empfangene Datei
        Prueft ausserdem, ob eine Datei mit diesem Namen in ./files vorhanden ist

        @return: str - Dateistring
        """
        for i in range(0, 14):
            filestring = ""
            for i in range(0, 10):
                filestring = filestring + choice(string.ascii_letters)

            if os.path.exists(filestring):
                break
            else:
                storage_string = self.file_storage + filestring
                self.create_file(storage_string)
                return filestring

        return None

