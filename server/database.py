import sqlite3


class Client:
    def __init__(self, client_id, client_name, public_key, last_seen, AES_key):
        self.ID = client_id
        self.Name = client_name
        self.PublicKey = public_key
        self.LastSeen = last_seen
        self.AESKey = AES_key


class File:
    def __init__(self, client_id, file_name, path_name, verified):
        self.ID = client_id
        self.Name = file_name
        self.PathName = path_name
        self.Verified = verified


class Database:
    CLIENTS = 'clients'
    FILES = 'files'

    def __init__(self, name):
        self.name = name

    def connect(self):
        """ connect to the database """
        conn = sqlite3.connect(self.name)
        return conn

    def executescript(self, script):
        conn = self.connect()
        try:
            conn.executescript(script)
            conn.commit()
        except:
            pass
        conn.close()

    def execute(self, query, args, commit=False, get_last_row=False):
        """ given a query and args, execute query, and return the results. """
        results = None
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(query, args)
            if commit:
                conn.commit()
                results = True
            else:
                results = cur.fetchall()
            if get_last_row:
                results = cur.lastrowid  # special query.
        except Exception as e:
            print(f'database execute: {e}')
        conn.close()  # commit is not required
        return results

    def initialize(self):
        # Try to create Clients table
        self.executescript(f"""
               CREATE TABLE {Database.CLIENTS}(
                 ID CHAR(16) NOT NULL PRIMARY KEY,
                 Name CHAR(255) NOT NULL,
                 PublicKey BLOB(160),
                 LastSeen DATE,
                 AESKey BLOB(16)
               );
               """)

        # Try to create Files table
        self.executescript(f"""
               CREATE TABLE {Database.FILES}(
                 ID CHAR(16) NOT NULL PRIMARY KEY,
                 Name CHAR(255) NOT NULL,
                 PathName CHAR(255) NOT NULL,
                 Verified BIT 
               );
               """)

    def clientUsernameExists(self, user_name):
        """ check if the client name already exists in the database """
        results = self.execute(f"SELECT * FROM {Database.CLIENTS} WHERE Name = ? ", [user_name])
        if not results:
            return False
        return True

    def getClientName(self, client_id):
        """ parse client name """
        results = self.execute(f"SELECT Name FROM {Database.CLIENTS} WHERE ID = ? ", [client_id])
        if not results:
            return None
        return results

    def checkFileExsistence(self, client_id, fileName):
        """ check if there is already in the database file such the current file of the client """
        results = self.execute(f"SELECT * FROM {Database.FILES} WHERE ID = ? AND Name = ?", [client_id, fileName])
        if not results:
            return None
        return results[0][0]

    def clientIdExists(self, client_id):
        """ check if client ID is already exists in the database """
        results = self.execute(f"SELECT * FROM {Database.CLIENTS} WHERE ID = ?", [client_id])
        if not results:
            return False
        return True

    def getClientPublicKey(self, client_id):
        """ parse RSA client public key  """
        results = self.execute(f"SELECT PublicKey FROM {Database.CLIENTS} WHERE ID = ?", [client_id])
        if not results:
            return None
        return results[0][0]

    def getAESSymmetricKey(self, client_id):
        """ parse AES symmetric key """
        results = self.execute(f"SELECT AESKey FROM {Database.CLIENTS} WHERE ID = ?", [client_id])
        if not results:
            return None
        return results[0][0]

    def storeClient(self, client):
        """ set client info """
        results = self.execute(f"INSERT INTO {Database.CLIENTS} (ID, Name, LastSeen) VALUES (?, ?, ?)",
                               [client.ID, client.Name, client.LastSeen], True)
        if not results:
            return False
        return True

    def storeFile(self, file):
        """ set client file """
        results = self.execute(f"INSERT INTO {Database.FILES} (ID, Name, PathName, Verified) VALUES (?, ?, ?, ?)",
                               [file.ID, file.Name, file.PathName, file.Verified], True)
        if not results:
            return False
        return True

    def setPublicAndAESKey(self, client):
        """ set client RSA public key and AES symmetric key"""
        return self.execute(f"UPDATE {Database.CLIENTS} SET PublicKey = ?, AESKey = ?, LastSeen = ? WHERE ID = ?",
                            [client.PublicKey, client.AESKey,  client.LastSeen, client.ID], True)

    def setLastSeen(self, client_id, time):
        """ set last seen given a client_id """
        return self.execute(f"UPDATE {Database.CLIENTS} SET LastSeen = ? WHERE ID = ?",
                            [time, client_id], True)

    def setVerified(self, clientID, verified, fileName):
        """ set last seen given a client_id """
        return self.execute(f"UPDATE {Database.FILES} SET Verified = ? WHERE ID = ? AND Name = ?",
                            [verified, clientID, fileName], True)


    def deleteFile(self, clientID, fileName):
        """ delete file when crc validation failed in the four time """
        return self.execute(f"DELETE FROM {Database.FILES} WHERE ID = ? AND Name = ?",
                            [clientID, fileName], True)
