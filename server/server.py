import os
import uuid
import zlib
import socket
import selectors
import database
import protocol
import datetime
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes


class Server:
    DATABASE = 'server.db'
    PACKET_SIZE = 2048
    MAX_QUEUE_CONNECTIONS = 10
    IS_BLOCKING = False
    CLIENTS_FILES_DIRECTORY = 'clientsFiles'

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.database = database.Database(Server.DATABASE)
        self.sel = selectors.DefaultSelector()
        # client request handle
        self.requestHandle = {
            protocol.ERequestCode.REGISTRATION_REQUEST.value: self.handleRegistrationRequest,
            protocol.ERequestCode.PUBLIC_KEY_REQUEST.value: self.handlePublicKeyRequest,
            protocol.ERequestCode.FILE_SEND_REQUEST.value: self.handleFileSendRequest,
            protocol.ERequestCode.RECONNECT_REQUEST.value: self.handleReconnectRequest,
            protocol.ERequestCode.CRC_CHECKED_OK.value: self.handleCRCOkRequest,
            protocol.ERequestCode.RETRY_CRC_REQUEST.value:  self.handleRetryCRCRequest,
            protocol.ERequestCode.FAILED_CRC_REQUEST.value: self.handleFailedCRCRequest
        }

    def handleFailedCRCRequest(self, conn, data):
        """ indicate that the file was validated in the 4 time was failed - client stop to send, update the database """
        print("server handle client failed crc request")
        currentTime = str(datetime.datetime.now())
        clientRequest = protocol.ValidateCRCRequest()
        serverResponse = protocol.ConfirmedMessageResponse()
        if not clientRequest.unpack(data):
            return False

        # delete non confirmed file from the local server clients folder
        fileName = clientRequest.fileName.decode('utf-8').rstrip('\x00')
        filePath = os.path.join(Server.CLIENTS_FILES_DIRECTORY, fileName)
        filePathLink = Path(filePath)
        try:
            # The client file is not verified - delete him from the database and from the local folder
            filePathLink.unlink()
            if not self.database.deleteFile(clientRequest.header.clientID.hex(), fileName):
                return False
            if not self.database.setLastSeen(clientRequest.header.clientID.hex(), currentTime):
                return False
        except:
            # some problem with the database
            return False
        serverResponse.clientID = clientRequest.header.clientID
        return self.write(conn, serverResponse.pack())

    def handleRetryCRCRequest(self, conn, data):
        """ indicate that the client try to validate his file content another time - update the database  """
        print("server handle client retry crc request")
        currentTime = str(datetime.datetime.now())
        clientRequest = protocol.ValidateCRCRequest()
        if not clientRequest.unpack(data):
            return False
        try:
            # update the time for the last client request
            if not self.database.setLastSeen(clientRequest.header.clientID.hex(), currentTime):
                return False
        except:
            return False
        return True

    def handleCRCOkRequest(self, conn, data):
        """ CKsum was verified. update the database and send thanks response """
        print("server handle client crc request is OK")
        currentTime = str(datetime.datetime.now())
        clientRequest = protocol.ValidateCRCRequest()
        serverResponse = protocol.ConfirmedMessageResponse()
        if not clientRequest.unpack(data):
            return False

        fileName = clientRequest.fileName.decode('utf-8').rstrip('\x00') + '\x00'
        try:
            if not self.database.setVerified(clientRequest.header.clientID.hex(), 1, fileName):
                return False
            if not self.database.setLastSeen(clientRequest.header.clientID.hex(), currentTime):
                return False
        except:
            # some problem with the database
            return False
        serverResponse.clientID = clientRequest.header.clientID
        return self.write(conn, serverResponse.pack())

    def handleReconnectRequest(self, conn, data):
        """ reconnected client, send AES key encrypted with client public key and his client ID """
        print("server handle client reconnect request")
        currentTime = str(datetime.datetime.now())
        clientRequest = protocol.RegistrationRequest()
        serverResponse = protocol.PublicKeyResponse()  # same like public key response
        if not clientRequest.unpack(data):
            return False
        clientID = clientRequest.header.clientID.hex()
        try:
            # validata client details with the database
            clientName = self.database.getClientName(clientID)
            print(f"client name is {clientName[0]}")
            clientPublicKey = self.database.getClientPublicKey(clientID)
        except:
            # some problem with the database
            return False
        if not clientName or not clientPublicKey or len(clientPublicKey) != protocol.EXCPECTED_CLIENT_PK_SIZE:
            # reconnect failed
            serverResponse = protocol.ReconnectFailedResponse()
            return self.write(conn, serverResponse.pack())
        else:
            try:
                # set the current time when client send the request and try parse AES key
                if not self.database.setLastSeen(clientID, currentTime):
                    return False
                AESKey = self.database.getAESSymmetricKey(clientID)
            except:
                # some problem with the database
                return False

            # encrypt the AES key using the client public key
            publicKey = RSA.import_key(clientPublicKey)
            cipher = PKCS1_OAEP.new(publicKey)
            cipherText = cipher.encrypt(AESKey)

            serverResponse.clientID = clientRequest.header.clientID
            serverResponse.AESEncryptedKey = cipherText
            serverResponse.header.code = protocol.EResponseCode.RECONNECT_REQUEST_SUCCESSFUL.value
            return self.write(conn, serverResponse.pack())

    def handleFileSendRequest(self, conn, data):
        print("server handle client send file request")
        currentTime = str(datetime.datetime.now())
        clientRequest = protocol.FileSendRequest()
        serverResponse = protocol.FileSendResponse()
        if not clientRequest.unpack(data):
            return False
        clientID = clientRequest.header.clientID.hex()
        try:
            self.database.setLastSeen(clientID, currentTime)
            AESKey = self.database.getAESSymmetricKey(clientID)
        except:
            # some problem with the database
            return False

        # decrypt the client file content
        IV = b'\x00' * 16
        decryptor = AES.new(AESKey, AES.MODE_CBC, IV)

        content = unpad(decryptor.decrypt(clientRequest.fileContent), 16)
        # calculate CKsum of the file content
        crc32 = self.crcChunksCalculate(content)

        fileName = clientRequest.fileName.decode('utf-8').rstrip('\x00') + '\x00'
        filePath = os.path.join(Server.CLIENTS_FILES_DIRECTORY, fileName) + '\x00'
        try:
            if not self.database.checkFileExsistence(clientID, fileName):
                currentFile = database.File(clientID, fileName, filePath, 0)
                self.database.storeFile(currentFile)
            else:
                self.database.setVerified(clientID, 0, fileName)
                self.database.setLastSeen(clientID, currentTime)
        except:
            # some problem with the database
            return False
        # create new file for the client in local folder
        filePath = filePath.rstrip('\x00')
        with open(filePath, 'wb') as file:
            file.write(content)
            file.close()

        serverResponse.clientID = clientRequest.header.clientID
        serverResponse.contentSize = len(clientRequest.fileContent)
        serverResponse.fileName = clientRequest.fileName
        serverResponse.Checksum = crc32
        serverResponse.header.payloadSize = protocol.PAYLOAD_SIZE_2103R_CODE
        return self.write(conn, serverResponse.pack())

    def crcChunksCalculate(self, fileContent):
        """ calculate CKsum on client file content in chunks of 1MB """
        chunkSize = 1024 * 1024  # 1MB
        checkSum = 0
        for i in range(0, len(fileContent), chunkSize):
            chunk = fileContent[i:i + chunkSize]
            checkSum = zlib.crc32(chunk, checkSum)
        return checkSum & 0xffffffff

    def handlePublicKeyRequest(self, conn, data):
        """ parse client public key and send AES key encrypt with the client public key """
        print("server handle client public key request")
        currentTime = str(datetime.datetime.now())
        clientRequest = protocol.PublicKeyRequest()
        serverResponse = protocol.PublicKeyResponse()
        if not clientRequest.unpack(data):
            print("we can't unpack the client header data")
            return False
        try:
            # here check if the uid that received is the same as this in the database
            if not self.database.clientIdExists(clientRequest.header.clientID.hex()):
                return False
        except:
            # some problem with the database
            return False

        # generate AES key for the server and encrypt it with client public key
        AESKey = get_random_bytes(16)

        # encrypt the server AES key with the client public key
        publicKey = RSA.import_key(clientRequest.publicKey)
        cipher = PKCS1_OAEP.new(publicKey)
        cipherText = cipher.encrypt(AESKey)

        # try to store public key, AES key and update the last seen in the database
        currentClient = database.Client(clientRequest.header.clientID.hex(), clientRequest.name,
                                        clientRequest.publicKey, currentTime, AESKey)
        try:
            if not self.database.setPublicAndAESKey(currentClient):
                return False
            if not self.database.setLastSeen(clientRequest.header.clientID.hex(), currentTime):
                return False
        except:
            # some problem with the database
            return False

        serverResponse.clientID = clientRequest.header.clientID
        serverResponse.AESEncryptedKey = cipherText
        return self.write(conn, serverResponse.pack())

    def handleRegistrationRequest(self, conn, data):
        """ try to register a new user and save to database """
        print("server handle client registration request")
        currentTime = datetime.datetime.now()
        clientRequest = protocol.RegistrationRequest()
        serverResponse = protocol.RegistrationResponse()
        try:
            if not clientRequest.unpack(data) or not clientRequest.name.isalnum():
                return False
            if self.database.clientUsernameExists(clientRequest.name):
                # registration failed! name is already in the database - registration request failed
                serverResponse.registrationUnsuccessful()
                return self.write(conn, serverResponse.pack())
        except:
            # some problem with the database
            return False

        serverResponse.clientID = uuid.uuid4().bytes
        currentClient = database.Client(serverResponse.clientID.hex(), clientRequest.name, 0, currentTime, 0)
        if not self.database.storeClient(currentClient):
            # some error with the database
            return False
        serverResponse.header.payloadSize = protocol.CLIENT_ID_SIZE
        return self.write(conn, serverResponse.pack())

    def read(self, conn, mask):
        """ read client data header anf after it read the payload in chunks of PACKET_SIZE """
        # reading the client header first
        try:
            data = conn.recv(protocol.CLIENT_HEADER_SIZE)
        except ConnectionResetError:
            print("Client closed the connection unexpectedly")
            self.sel.unregister(conn)
            conn.close()
            return
        requestHeader = protocol.RequestHeader()
        if data:
            success = False
            if not requestHeader.unpack(data):
                return False
            else:
                remaining_payload_size = requestHeader.payloadSize
                # reading in chunks of 2048
                while remaining_payload_size > 0:
                    chunk = conn.recv(min(remaining_payload_size, Server.PACKET_SIZE))
                    remaining_payload_size -= len(chunk)
                    data += chunk
                if requestHeader.code in self.requestHandle.keys():
                    success = self.requestHandle[requestHeader.code](conn, data)
            if not success:
                # send to client generic error response with the details of the failure
                serverResponse = protocol.GenericErrorResponse()
                return self.write(conn, serverResponse.pack())
        else:
            self.sel.unregister(conn)
            conn.close()
            print("connection has been closed!")

    def accept(self, sock, mask):
        """ accept connection from client """
        conn, addr = sock.accept()
        print("client has connected!")
        # client socket is'nt blocking
        conn.setblocking(Server.IS_BLOCKING)
        conn.settimeout(25)
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    def write(self, conn, data):
        try:
            # sending the data in chunks of 2048 bytes
            data += b'\x00' * (2048 - len(data))
            conn.sendall(data)
            print("server response send to client")
            return True
        except:
            return False

    def start(self):
        """ start listen for connections. contains the main loop, and the database, client folder initialization """
        try:
            #
            self.database.initialize()
            if not os.path.exists(Server.CLIENTS_FILES_DIRECTORY):
                os.makedirs(Server.CLIENTS_FILES_DIRECTORY)
            sock = socket.socket()
            sock.bind((self.host, self.port))
            sock.listen(Server.MAX_QUEUE_CONNECTIONS)
            # server is'nt blocking
            sock.setblocking(Server.IS_BLOCKING)
            self.sel.register(sock, selectors.EVENT_READ, self.accept)

        except Exception as e:
            print(e)
            return False
        print(f"Server is listening for connections on port {self.port}..")
        while True:
            try:
                events = self.sel.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
            except Exception as e:
                print(f"Server main loop exception: {e}")
