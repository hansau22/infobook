# -*- coding: utf-8 -*-

from libinfo.Pool import Pool

import sqlite3

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
        self.db.text_factory = str
        self.cursor = self.db.cursor()
        self.init_db()
        self.mid_Pool = Pool(0, self.get_start_mid())
        self.bid_Pool = Pool(0, self.get_start_brdc_mid())
        self.fid_Pool = Pool(0, self.get_start_fid())


    
    def init_db(self):
        """
        Initialisert die Datenbank

        @return: None
        """
        self.cursor.execute("CREATE TABLE IF NOT EXISTS users(uid INTEGER, username TEXT, password TEXT)")
        self.cursor.execute("CREATE TABLE IF NOT EXISTS groups(gid Integer, member Integer, name Text)")
        self.cursor.execute("CREATE TABLE IF NOT EXISTS messages(mid INTEGER, uidsender INTEGER, uidreceiver INTEGER, content TEXT)")
        self.cursor.execute("CREATE TABLE IF NOT EXISTS groupmessages(bid INTEGER, uidsender INTEGER, gidreceiver INTEGER, content TEXT)")
        self.cursor.execute("CREATE TABLE IF NOT EXISTS files(fid Integer, localname Text, globalname Text, owner Integer)")
        self.db.commit()

        self.cursor.execute("SELECT uid FROM users WHERE uid = 0")
        if self.cursor.fetchone() == None:
            self.cursor.execute("INSERT INTO users VALUES(0, 'initial', 'nohash')")

        self.cursor.execute("SELECT fid FROM files WHERE fid = 0")
        if self.cursor.fetchone() == None:
            self.cursor.execute("INSERT INTO files VALUES(0, 'initial', 'initial', 0)")

        self.cursor.execute("SELECT mid FROM messages WHERE mid = 0")
        if self.cursor.fetchone() == None:
            self.cursor.execute("INSERT INTO messages VALUES(0, 0, 0, 'initial')")

        self.cursor.execute("SELECT bid FROM groupmessages WHERE bid = 0")
        if self.cursor.fetchone() == None:
            self.cursor.execute("INSERT INTO groupmessages VALUES(0, 0, 0, 'initial')")

        self.cursor.execute("SELECT gid FROM groups WHERE gid = 0")
        if self.cursor.fetchone() == None:
            self.cursor.execute("INSERT INTO groups VALUES(0, 0, 'initial')")

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

        @return: None, False wenn Parameter nicht stimmen
        """

        if not isinstance(uid, int):
            return False
        if not isinstance(username, str):
            return False
        if not isinstance(pwhash, str):
            return False

        self.cursor.execute("INSERT INTO users VALUES(%d, %s, %s)", (uid, username, pwhash))
        self.db.commit()


        
    def auth_user(self, username, pwhash):
        """
        Prueft Nutzer-Passwort Kombination

        @param username: Nutzername
        @type username: str

        @param pwhash: SHA256-Verschluesselter Passwort-Hash
        @type pwhash: str

        @return: True, False wenn Parameter nicht stimmen oder Nutzer-Passwort Kombination falsch
        """ 

        if not isinstance(username, str):
            return False
        if not isinstance(pwhash, str):
            return False

        self.cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, pwhash))
        if self.cursor.fetchone() != None:
            return True
        return False



    def get_user_id(self, username):
        """
        Gibt die Nutzer-ID eines Benutzers zurueck

        @param username: Nutzername
        @type username: str

        @return: int Nutzer-ID, False bei unbekanntem Nutzer
        """

        if not isinstance(username, str):
            return False

        self.cursor.execute("SELECT uid FROM users WHERE username=%s", username)
        result = self.cursor.fetchone()
        if result == None:
            return False
        return int(result)


    def get_group_id(self, name):
        """
        Gibt die Gruppen-ID einer Gruppe zurueck

        @param name: Gruppenname
        @type name: str

        @return: int Gruppen-ID, False bei unbekannter Gruppe
        """

        if not isinstance(name, str):
            return False

        self.cursor.execute("SELECT gid FROM groups WHERE name=%s", name)
        result = self.cursor.fetchone()
        if result == None:
            return False
        return int(result)


    def get_user_by_id(self, id):
        """
        Gibt den Namen des Nutzers anhand der ID zurueck.

        @param id: Nutzer-ID
        @type id: int

        @return: str Name, None falls Name nicht gefunden
        """

        if not isinstance(id, int):
            return False

        self.cursor.execute("SELECT username FROM users WHERE uid=%d", id)
        return self.cursor.fetchone()



    def get_group_by_id(self, gid):
        """
        Gibt den Namen einer Gruppe anhand der ID zurueck.

        @param gid: Gruppen-ID
        @type gid: int

        @return: str Name - None falls Name nicht gefunden
        """

        if not isinstance(gid, int):
            return False

        self.cursor.execute("SELECT name FROM groups WHERE gid=%d", gid)
        return self.cursor.fetchone()

        
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
        
        if not isinstance(uidSender, int):
            return False
        if not isinstance(uidReceiver, int):
            return False
        if not isinstance(data, str):
            return False
        
        # Wiederholen, wenn uidReceiver eine Liste ist
        #data = data.decode('utf-8').encode("utf-8")

        data = data.strip()

        if not isinstance(uidReceiver, list):
            self.cursor.execute("INSERT INTO messages VALUES(%d, %d, %d, %s)", (self.mid_Pool.give_next(), uidSender, uidReceiver, data.encode("utf-8", "ignore")))
        else:
            for item in uidReceiver:
                self.cursor.execute("INSERT INTO messages VALUES(%d, %d, %d, %s)", (self.mid_Pool.give_next(), uidSender, item, data.encode("utf-8", "ignore")))
        
        self.db.commit()
        return True



    def get_messages_by_last_mid(self, uidReceiver, last_mid):
        """
        Sendet dem Client die neuen Nachrichten.
        Alle Nachrichten sind neu, wenn sie eine groessere MID als die uebergebene hat.

        @param uidReceiver: Empfaenger der Nachrichten
        @type uidReceiver: str

        @param last_mid: Letzte bekannte MID
        @type last_mid: int

        @return Array - [Sender(str), Nachrichten(str)]
        """

        if not isinstance(uidReceiver, int):
            return False
        if not isinstance(last_mid, int):
            return False

        self.cursor.execute("SELECT uidSender, content FROM messages WHERE MID > %d", last_mid)
        
        ret_value = []
        result = self.cursor.fetchone()
        while result != None:
            ret_value.append(result)
            result = self.cursor.fetchone()

        return ret_value




    def get_messages_by_last_group_id(self, uidReceiver, last_gid):
        """
        Sendet dem Client die neuen Gruppennachrichten.
        Alle Gruppennachrichten sind neu, wenn sie eine groessere GID als die uebergebene hat.

        @param uidReceiver: Empfaenger der Gruppennachrichten
        @type uidReceiver: str

        @param last_gid: Letzte bekannte GID
        @type last_gid: int

        @return Array - [Sender(str), Gruppennachrichten(str)]
        """

        if not isinstance(uidReceiver, int):
            return False
        if not isinstance(last_gid, int):
            return False

        self.cursor.execute("SELECT gidreceiver, uidsender, content FROM groupmessages WHERE bid > %d", last_gid)

        ret_value = []
        result = self.cursor.fetchone()
        while result != None:
            ret_value.append(result)
            result = self.cursor.fetchone()

        return ret_value



    def rcv_brdc_message(self, uidSender, gidReceiver, data):
            """
            Traegt eine Broadcast-Nachricht in die Datenbank ein

            @param uidSender: Nutzer-ID des Senders
            @type uidSender: int

            @param gidReceiver: Gruppen-ID des Empfaengers
            @type gidReceiver: int

            @param data: Nachricht
            @type data: Nachricht

            @return: Boolean Erfolg
            """

            if not isinstance(uidSender, int):
                return False
            if not isinstance(uidReceiver, int):
                return False
            if not isinstance(data, str):
                return False

            # data = data.encode("utf-8")
            
            self.cursor.execute("INSERT INTO groupmessages VALUES(%d, %d, %d, %s))", (self.bid_Pool.give_next(), uidSender, gidReceiver, data.encode("utf-8", "ignore")))
            self.db.commit()
            return True



    def add_file(self, local_name):
        """
        Erzeugt einen neuen Dateieintrag

        @param local_name: Name der Datei auf dem Server
        @type local_name: str

        @return: Boolean Erfolg
        """

        if not isinstance(local_name, str):
            return False

        self.cursor.execute("INSERT INTO files VALUES(%d, %s, %s, %d)", (self.fid_Pool.give_next(), local_name, "", 0))
        self.db.commit()
        return True



    def register_file(self, owner, globalname, filestring):
        """
        Registriert eine Datei (Setzt Besitzer und Dateinamen)

        @param owner: Nutzer-ID des Besitzers
        @type owner: int

        @param globalname: Dateiname der Datei
        @type globalname: str

        @param filestring: Dateistring der Datei
        @type filestring: str

        @return: Boolean Erfolg
        """

        if not isinstance(owner, int):
            return False
        if not isinstance(globalname, str):
            return False
        if not isinstance(filestring, str):
            return False

        self.cursor.execute("UPDATE files SET owner=%d, globalname=%s WHERE localname=%s", (owner, globalname, filestring))
        self.db.commit()
        return True



    def check_filestring(self, filestring):
        """
        Ueberprueft, ob ein Dateistring existiert

        @param filestring: Dateistring
        @type filestring: str

        @return Boolean Erfolg
        """

        if not isinstance(filestring, str):
            return False

        self.cursor.execute("SELECT localname FROM files WHERE localname = %s", filestring)
        if self.cursor.fetchone() != None:
            return True
        return False


    
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
        self.cursor.execute("SELECT bid FROM groupmessages ORDER BY bid DESC")
        result = self.cursor.fetchone()
        if result == None:
            return 0
        return (result[0] + 1)



    def get_start_fid(self):
        """
        Gibt die erste freie Datei-ID

        @return: int ID
        """
        self.cursor.execute("SELECT fid FROM files ORDER BY fid DESC")
        result = self.cursor.fetchone()
        result = str(result)
        if result == None:
            return 0
        result = int(result[0])
        return (result + 1)   