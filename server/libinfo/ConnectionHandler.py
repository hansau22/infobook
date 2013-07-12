# -*- coding: utf-8 -*-

from  libinfo.EncryptionHandler import EncryptionHandler
from  libinfo.DatabaseHandler import DatabaseHandler
#from  libinfo import DatabaseHandler
from  libinfo.Pool import Pool

import socket
import select
import sys
import os
import binascii
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

        if len(sys.argv) < 2:
            serv_soc.bind(("", 32323))
        else:
            serv_soc.bind(("", int(sys.argv[1])))

        serv_soc.listen(1)
        
        try:
            while True:

                komm, addr = serv_soc.accept()
                data = ""
                data = komm.recv(self.max_rcv)

                # Default-Antwort
                resp = "error - invalid-client-request"

                # Leere Verbindung
                if not data: 
                    komm.close()
                    continue

                # Datenpaket ist verschluesslt (= Kein DHEX-Paket)    
                if self.crypt.is_encrypted(data):
                    body = self.decrypt(data)

                    # Wenn nicht entschluesselbar -> Fehler
                    if body == None:
                       komm.send(resp)
                       komm.close()
                       continue 

                    body = body.decode("utf-8", "ignore")

                try:
                    # Kopfdaten und Nutzdaten trennen
                    data = split(";", data, 1)
                    self.header = self.parse_header(data[0])
                    data = data[1]
                except IndexError:
                    komm.send(resp)
                    komm.close()
                    continue

                # Datenpaket encoden
                #if self.header[0] != "dhex":

                try:

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
                    elif self.header[0] == "reqfile":
                        resp = self.request_file()
                    elif self.header[0] == "regfile":
                        resp = self.register_file(body)


                    # Antwortpaket senden
                    if self.header[0] == "dhex":
                        komm.send(resp)

                    elif self.is_error(resp):
                        print "error:  " + resp
                        komm.send(resp)

                    else:
                        if isinstance(resp, list):
                            for item in resp:
                                item = item.encode("utf-8", "ignore")
                                komm.send(self.build_pack(item))
                        else:
                            resp = self.crypt.encode_string(resp)
                            komm.send(self.build_pack(resp))
                        
                    komm.close()

                except IndexError:
                    komm.send(resp)
                    komm.close()

                        
        finally:
            #for client in clients: 
            #    client.close() 
            serv_soc.close()



    def is_error(self, data):
        """
        Prueft ob eine Antwort eine Fehlermeldung ist

        @param data: Antwort
        @type data: str

        @return: Boolean Ergebnis
        """

        if not isinstance(data, str):
            raise TypeError("Data must be str")
            return False

        if string.find(data, "error", 0, 4) == -1 :
            return False
        else:
            return True


    def init_dh(self, data):
        """
        Initialisiert den DH-Schluesselaustausch anhand der Informationen aus der Anfrage des Clients.

        @param data: Enthaelt den Oeffentlichen Teil vom Partner
        @type data: str

        @return: str - Sessionkey
        """

        # DH-Antwort (B) auf die Anfrage (A)
        ret = self.crypt.init_dh_b(self.sid_Pool.give_next(),data)

        if ret == False:
            return "error - DH-initiation-error - DHEX"

        try:
            # Alle Felder fuer die neu Initialiserte Session reservieren (befuellen)
            self.users.append("")
            self.uidstrings.append("")
            self.ivs.append(ret[0])
            self.ctr.append(ret[1])
            self.sesskey.append(ret[2])

            #print "sesskey :  " + ret[2]

            return ret[3]
        except IndexError:
            return "error - DH-initiation-server-error - DHEX"
        



    def decrypt(self, data):
        """
        Entschluesselt ein Datenpaket mit dem Sessionkey, der zur Session-ID gehoert.

        @param data: Verschluesseltes Paket mit unverschluesselten Kopfinformationen
        @type data: str

        @return: str - Unverschluesseltes Paket ohne Kopfinformationen
        """

        try:
            tmp = split(";", data, 1)       # ";" Seperiert Nutz- und Kopfdaten
            sid = split(":", tmp[0], 2)     # Extrahiere Session-ID
            sid = int(sid[2])
            data = self.crypt.decrypt(self.sesskey[sid], self.ctr[sid], tmp[1])
            return data
        except IndexError:
            return None



    
    def encrypt(self, data):
        """
        Verschluesselt die Daten fuer ein Paket.

        @param data: Daten-String ohne Kopfinformationen
        @type data: str

        @return: Verschluesselt Datenpaket ohne Kopfinformationen
        """
        try:
            sid = self.header[2]
            return self.crypt.encrypt(self.sesskey[sid], self.ctr[sid], data)
        except IndexError:
            return None

            
    def parse_header(self, data):
        """
        Verarbeitet Kopfinformationen und wandelt die Informationen in benoetigte Typen

        @param data: Kopfinformationen
        @type data: str

        @return: Array - Kopfinformationen
        """

        try:
            header = split(":", data, 2)
            if not header[0] == "dhex":
                header[2] = int(header[2])
            return header
        except IndexError:
            pass
        


    def build_pack(self, msg):
        """
        Erstellt die Kopfinformationen fuer ein Datenpaket und fuegt die Nachricht an.

        @param msg: Nachricht ohne Kopfinformationen
        @type msg: str

        @return: str - Nachrichtenpaket mit Kopfinformationen
        """

        try:
            package = "sresp" + ":" + str(self.header[2]) + ";"
            enc_msg = self.encrypt(msg)
            if enc_msg == None:
                return msg
            package += enc_msg
            return package
        except IndexError:
            return msg



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
        try:
            if self.database.auth_user(cred[0], cred[1]) == True:

                # User-ID String erzeugen
                dig = self.crypt.get_hash(self.sesskey[self.header[2]] + str(cred[0])) 

                self.uidstrings[self.header[2]] = dig
                self.users[self.header[2]] = self.database.get_user_id(cred[0])

                return dig
            else:
                return "error - wrong-credentials - AUTH"
        except IndexError:
            return "error - invalid-header - AUTH"



    def check_uidstring(self, index, string):
        """
        Vergleicht einen Nutzer-ID-String mit dem, der zu dem Nutzer mit der Session-ID gehoert.

        @param index: Session-ID
        @type index: int

        @param string: Nutzer-ID-String
        @type string: str

        @return: Boolean - Ergebnis
        """

        try:
            if self.uidstrings[index] == string:
                return True
            return False
        except IndexError:
            return False


        
    def recv_msg(self, data):
        """
        Traegt eine Nachricht in die Datenbank ein.

        @param data: Datenpaket des Clients ohne Kopfinformationen
        @type data: str

        @return: str - Erfolgs-/Fehlermeldung
        """

        try:
            sid = self.header[2]
            tmp = split(":", data, 2)


            # Nicht alle Felder gegeben
            if len(tmp) != 3:
                return "error - not-long-enough - MSG"

            if self.check_uidstring(sid, tmp[0]):
                rcv_uid = self.database.get_user_id(tmp[1])
                snd_uid = self.users[self.header[2]]
                print "writing message:" + tmp[2]
                if not self.database.rcv_message(snd_uid, rcv_uid, tmp[2]):
                    return "error - server-application-error - MSG"
                return "success - MSG"
            else:
                return "error - wrong-uidstring - MSG"
        except IndexError:
            return "error - invalid-header - MSG"



    def get_msg(self, data):
        """
        Gibt dem Client die Nachrichten zurueck. 

        @param data: Letzte MID, die der Client an den Server gibt.
        @type data: str

        @return: Array - Nachrichten
        """
        try:
            messages = self.database.get_messages_by_last_mid(self.header[2], data)
            ret_msg = []

            for item in messages:
                username = self.database.get_user_by_id(item[0])

                if username == None:
                    username = "Nutzer unbekannt"

                ret_msg.append(username + ":" + item[1])

            ret_msg.append("[FIN]")
            return ret_msg
        except IndexError:
            return "error - internal-database-request-error - MSG"



    def get_gmsg(self, data):
        """
        Gibt dem Client die Gruppennachrichten zurueck.

        @param data: Letzte GID, die der Client an den Server gibt.
        @type data: str

        @return: Array - Nachrichten
        """

        try:
            messages = self.database.get_messages_by_last_gid(self.header[2], data)
            ret_msg = []

            for item in messages:
                groupname = self.database.get_group_by_id(item[0])

                if groupname == None:
                    groupname = "Gruppenname unbekannt"

                ret_msg.append(item[1] + ":" + groupname + ":" + item[2])

            ret_msg.append("[FIN]")
            return ret_msg
        except IndexError:
            return "error - internal-database-request-error - GroupMessage"



    def recv_gmsg(self, data):
        """
        Traegt eine Broadcast-Nachricht in die Datenbank ein.

        @param data: Datenpaket des Clients ohne Kopfinformationen
        @type data: str

        @return: str - Erfolgs-/Fehlermeldung
        """

        try:
            sid = self.header[2]
            tmp = split(":", data, 2)

            # Nicht alle Felder gegeben
            if len(tmp) != 3:
                return "error - not-enough-arguments - GroupMessage"

            if self.check_uidstring(sid, tmp[0]):
                rcv_gid = self.database.get_group_id(tmp[1])
                snd_uid = self.users[self.header[2]]
                print "writing message:" + tmp[2]
                if not self.database.rcv_brdc_message(snd_uid, rcv_gid, tmp[2]):
                    return "error - server-application-error - GroupMessage"
                return "success - GroupMessage"
            else:
                return "error - wrong-uidstring - GroupMessage"
        except IndexError:
            return "error - invalid-header - GroupMessage"


    def request_file(self):
        """
        Gibt einen Dateistring fuer eine neue Datei zurueck, die ueber FTP hochgeladen werden kann

        @return: str - Dateistring
        """

        ret_value = self.generate_file_string()

        if ret_value == None:
            return "error - storage-full - REQFILE"
        else:
            self.database.add_file(ret_value)
            return ret_value



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
        try:
            if not self.database.register_file(self.users[self.header[2]], global_name, filestring):
                return "error - server-storage-error"
            else:
                return "success - FILE"
        except IndexError:
            return "error - invalid-header - FILE"



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

            if os.path.exists(self.storage_string + filestring):
                break
            else:
                return filestring

        return None

