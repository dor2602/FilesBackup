import struct
from enum import Enum

# some important sizes
SERVER_VERSION = 3
DEFAULT_VAL = 0
HEADER_SIZE = 7
CLIENT_HEADER_SIZE = 23
CLIENT_ID_SIZE = 16
CLIENT_NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
AES_KEY_SIZE = 128
FILE_CONTENT_SIZE = 4
FILE_NAME_SIZE = 255
MAX_PAYLOAD_SIZE = 0xFFFFFFFF
EXCPECTED_CLIENT_PK_SIZE = 160
PAYLOAD_SIZE_2103R_CODE = 279


class ERequestCode(Enum):
    REGISTRATION_REQUEST = 1100  # uuid ignored.
    PUBLIC_KEY_REQUEST = 1101
    RECONNECT_REQUEST = 1102
    FILE_SEND_REQUEST = 1103
    CRC_CHECKED_OK = 1104
    RETRY_CRC_REQUEST = 1105
    FAILED_CRC_REQUEST = 1106


class EResponseCode(Enum):
    RESPONSE_REGISTRATION_SUCCESSFUL = 2100
    RESPONSE_REGISTRATION_UNSUCCESSFUL = 2101
    PUBLIC_KEY_REQUEST_SUCCESSFUL = 2102
    FILE_RECVIE_SEND_CRC = 2103
    CONFIRMED_MESSAGE_THANKS = 2104
    RECONNECT_REQUEST_SUCCESSFUL = 2105
    RECONNECT_REQUEST_FAILED = 2106
    GENERIC_ERROR = 2107


class RequestHeader:
    def __init__(self):
        self.clientID = b""
        self.version = DEFAULT_VAL      # 1 byte
        self.code = DEFAULT_VAL         # 2 bytes
        self.payloadSize = DEFAULT_VAL  # 4 bytes
        self.SIZE = CLIENT_ID_SIZE + HEADER_SIZE

    def unpack(self, data):
        """ little endian unpack request Header """
        try:
            self.clientID = struct.unpack(f"<{CLIENT_ID_SIZE}s", data[:CLIENT_ID_SIZE])[0]
            headerData = data[CLIENT_ID_SIZE:CLIENT_ID_SIZE + HEADER_SIZE]
            self.version, self.code, self.payloadSize = struct.unpack("<BHL", headerData)
            return self.validateHeader()
            # return True
        except:
            self.__init__()  # reset values
            return False

    def validateHeader(self):
        if self.version != SERVER_VERSION or self.payloadSize == 0:
            return False
        return True


class ResponseHeader:
    def __init__(self, code):
        self.version = SERVER_VERSION
        self.code = code
        self.payloadSize = DEFAULT_VAL

    def pack(self):
        """ little endian response header pack """
        try:
            return struct.pack("<BHL", self.version, self.code, self.payloadSize)
        except:
            return b""


class GenericErrorResponse:
    def __init__(self):
        self.header = ResponseHeader(EResponseCode.GENERIC_ERROR.value)

    def pack(self):
        """ little endian pack response header with error code"""
        try:
            data = self.header.pack()
            return data
        except:
            return b""

class ReconnectRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""

    def unpack(self, data):
        """ little endian unpack request header and client name """
        if not self.header.unpack(data):
            return False
        try:
            self.name = struct.unpack(f"<{FILE_NAME_SIZE}s", data[23:23 + FILE_NAME_SIZE])[0]
            return True
        except:
            self.__init__()  # reset values
            return False


class CRCFailedRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.fileName = b""

    def unpack(self, data):
        """ little endian unpack request header and client file name """
        if not self.header.unpack(data):
            return False
        try:
            self.fileName = struct.unpack(f"<{FILE_NAME_SIZE}s", data[CLIENT_HEADER_SIZE:
                                                                      CLIENT_HEADER_SIZE + FILE_NAME_SIZE])[0]
            return True
        except:
            return b""


class ValidateCRCRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.fileName = b""

    def unpack(self, data):
        """ little endian unpack request header and client file name """
        if not self.header.unpack(data):
            return False
        try:
            self.header.unpack(data)
            self.fileName = struct.unpack(f"<{FILE_NAME_SIZE}s", data[CLIENT_HEADER_SIZE:
                                                                      CLIENT_HEADER_SIZE + FILE_NAME_SIZE])[0]
            return True
        except:
            return b""


class ConfirmedMessageResponse:
    def __init__(self):
        self.header = ResponseHeader(EResponseCode.CONFIRMED_MESSAGE_THANKS.value)
        self.clientID = b""

    def pack(self):
        """ little endian pack response header and client ID """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            return data
        except:
            return b""


class ReconnectFailedResponse:
    def __init__(self):
        self.header = ResponseHeader(EResponseCode.RECONNECT_REQUEST_FAILED)
        self.clientId = b""

    def pack(self):
        """ little endian pack response header and client ID """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientId)
            return data
        except:
            return b""


class FileSendRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.contentSize = b""
        self.fileName = b""
        self.fileContent = b""

    def unpack(self, data):
        """ little endian unpack request header and client file details """
        if not self.header.unpack(data):
            return False
        try:
            # self.header.unpack(data)
            contentSizeData = data[CLIENT_HEADER_SIZE:CLIENT_HEADER_SIZE + FILE_CONTENT_SIZE]
            self.contentSize = struct.unpack("<L", contentSizeData)[0]
            self.fileName = struct.unpack(f"<{FILE_NAME_SIZE}s", data[27:27 + FILE_NAME_SIZE])[0]
            self.fileContent = struct.unpack(f"<{self.contentSize}s", data[27 + FILE_NAME_SIZE:
                                                                           27 + FILE_NAME_SIZE + self.contentSize])[0]
            return True
        except:
            return False


class FileSendResponse:
    def __init__(self):
        self.header = ResponseHeader(EResponseCode.FILE_RECVIE_SEND_CRC.value)
        self.clientID = b""
        self.contentSize = b""
        self.fileName = b""
        self.Checksum = b""

    def pack(self):
        """ little endian pack response header and client file details """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            data += struct.pack("<L",  self.contentSize)
            data += struct.pack(f"<{FILE_NAME_SIZE}s", self.fileName)
            data += struct.pack("<L",  self.Checksum)
            return data
        except:
            return b""


class PublicKeyRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""
        self.publicKey = b""

    def unpack(self, data):
        """ little endian unpack request header and client name and public key """
        if not self.header.unpack(data):
            return False
        try:
            nameData = data[CLIENT_HEADER_SIZE:CLIENT_HEADER_SIZE + CLIENT_NAME_SIZE]
            self.name = str(struct.unpack(f"<{CLIENT_NAME_SIZE}s", nameData)[0].partition(b'\0')[0].decode('utf-8'))
            publicKeyData = data[
                            CLIENT_HEADER_SIZE + CLIENT_NAME_SIZE:CLIENT_HEADER_SIZE + CLIENT_NAME_SIZE + PUBLIC_KEY_SIZE]
            self.publicKey = struct.unpack(f"<{PUBLIC_KEY_SIZE}s", publicKeyData)[0]
            return True
        except:
            return False


class PublicKeyResponse:
    def __init__(self):
        self.header = ResponseHeader(EResponseCode.PUBLIC_KEY_REQUEST_SUCCESSFUL.value)
        self.clientID = b""
        self.AESEncryptedKey = b""

    def pack(self):
        """ little endian pack response header and client ID and encrypted AES key """
        try:
            self.header.payloadSize = len(self.AESEncryptedKey) + CLIENT_ID_SIZE
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            data += struct.pack(f"<{AES_KEY_SIZE}s", self.AESEncryptedKey)
            return data
        except:
            return b""


class RegistrationRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""

    def unpack(self, data):
        """ little endian unpack request header and client registration data """
        if not self.header.unpack(data):
            return False
        try:

            # trim the byte array after the nul terminating character.
            nameData = data[self.header.SIZE:self.header.SIZE + CLIENT_NAME_SIZE]
            self.name = str(struct.unpack(f"<{CLIENT_NAME_SIZE}s", nameData)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            return False


class RegistrationResponse:
    def __init__(self):
        self.header = ResponseHeader(EResponseCode.RESPONSE_REGISTRATION_SUCCESSFUL.value)
        self.clientID = b""

    def pack(self):
        """ little endian pack response Header and client ID """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            return data
        except:
            return b""

    def registrationUnsuccessful(self):
        """ in case that registration was failed """
        self.header.code = EResponseCode.RESPONSE_REGISTRATION_UNSUCCESSFUL.value
        try:
            data = self.header.pack()
            return data
        except:
            return b""
