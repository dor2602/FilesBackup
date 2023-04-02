#include <string>
#include <fstream>
#include <sstream>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/crc.hpp>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <iomanip>
#include <boost/algorithm/hex.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <limits>
#include "ClientLogic.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Utils.h"
#include "rsa.h"
#include "osrng.h"

using boost::asio::ip::tcp;
using namespace boost::asio;

/* stop client for runing - Fatal Error was made */
void ClientLogic::clientStop(const string& error)
{
	std::cout << "Fatal Error: " << error << std::endl << "Client will stop." << std::endl;
	system("pause");
	exit(1);
}

ClientLogic::ClientLogic() : _fileHandler(nullptr), _socket(nullptr), _RSAPair(nullptr)
{
	_fileHandler = new FileHandler();
	_socket = new SocketHandler();
	_RSAPair = new RSAPrivateWrapper();
	_succseed = false;
	_clientCRC = 0;

}

ClientLogic::~ClientLogic()
{
	delete _fileHandler;
	delete _socket;
	delete _RSAPair;
}

/* unpack server response */
ServerResponse* ClientLogic::unpackResponse(vector<uint8_t> responseBuffer, const uint32_t size)
{
	ServerResponse* res = new ServerResponse;

	/* unpack and copy the server response header */
	res->header.version = responseBuffer[0];
	res->header.code = *reinterpret_cast<uint16_t*>(&responseBuffer[VERSION_SIZE]);
	res->header.payloadSize = *reinterpret_cast<uint32_t*>(&responseBuffer[VERSION_SIZE + CODE_SIZE]);

	/* validate the header */
	if (res->header.version != VERSION)
	{
		return nullptr;
	}

	/* unpack and copy the server response payload */
	uint32_t leftOver = size - HEADER_SIZE;
	if (res->header.payloadSize < leftOver)
		leftOver = res->header.payloadSize;
	res->payload.payload = new uint8_t[leftOver];
	memcpy(res->payload.payload, responseBuffer.data() + HEADER_SIZE, leftOver);

	return res;
}


/* caulcalate CRC In order to verify the sending of the file to the server */
uint32_t ClientLogic::caulcalateCRC(string fileContent)
{
	boost::crc_32_type crc_calculator;
	crc_calculator.process_bytes(fileContent.data(), fileContent.size());
	uint32_t crc = crc_calculator.checksum();
	return crc;
}
string ClientLogic::encryptFileUsingAESKey(string fileContent)
{
	AESWrapper aes((unsigned char*)_AESKey.c_str(), AESWrapper::DEFAULT_KEYLENGTH);

	cout << "content file size " << fileContent.size() << endl;
	std::string ciphertext = aes.encrypt(fileContent.c_str(), fileContent.size());
	return ciphertext;
}

/* extract AES symmetric key using client RSA private key */
string ClientLogic::extractAESKey(uint8_t* payload, uint32_t len)
{
	/* get the client private key from me.info */
	string base64key = _fileHandler->extractBase64privateKey(CLIENT_INFO);

	RSAPrivateWrapper rsapriv_other(Utils::decode(base64key));

	/* get the AES key using client private key */
	_AESKey = rsapriv_other.decrypt(reinterpret_cast<const char*>(&payload[UID_SIZE]), len - UID_SIZE);

	return _AESKey;
}

/* parse transfer info file and initialize the socket info */
bool ClientLogic::parseAndStoreTransferInfo(const string& transferInfoPath)
{
	if (!_fileHandler->openFile(transferInfoPath))
	{
		return false;
	}
	string serverInfo;
	_fileHandler->readLine(serverInfo);
	size_t spos = serverInfo.find(":");
	if (spos == std::string::npos)
	{
		return false;
	}
	string address = serverInfo.substr(0, spos);
	string port = serverInfo.substr(spos + 1);
	port.erase(port.size() - 1);
	/* initialize socket */
	if (!_socket->initializeSocketInfo(address, port))
	{
		clientStop("cannot initialize client socket for communiction");
	}

	_fileHandler->readLine(_userName);
	_userName.erase(_userName.size() - 1);
	if (_userName.size() > MAX_NAME_SIZE)
	{
		return false;
	}
	_fileHandler->readLine(_filePath);
	_fileHandler->closeFile();
	return true;
}

/* parse and store client info details */
bool ClientLogic::parseAndStoreClientInfo()
{
	/* get the RSA public key */
	_publicKey = _RSAPair->getPublicKey();

	/* get the RSA private key decoded as base64 using Base64Wrapper */
	_base64privateKey = Utils::encode(_RSAPair->getPrivateKey());

	if (!_fileHandler->openFile(CLIENT_INFO, false))
	{
		return false;
	}

	/* write the client info into me.info file */
	_fileHandler->writeLine(_userName);
	_fileHandler->writeLine(_clientUID);
	_fileHandler->writeAtOnce(_base64privateKey);
	_fileHandler->closeFile();
	return true;
}

/* prepare the registeration request */
void ClientLogic::createRegisterationRequest(vector<uint8_t>& requestBuffer, bool reconnect)
{
	/* create new registeration request */
	RegisterationRequest request(REGISTRATION_REQUEST, NAME_SIZE);
	if (reconnect)
	{
		/* client already before was registerd  */

		/* prepare the header */
		request.header.code = LOGIN_REQUEST;
		std::string unhexUID = Utils::reverse_hexi(_clientUID);
		unhexUID.copy(reinterpret_cast<char*>(request.header.uid), sizeof(request.header.uid));
	}

	/* pack the header */
	memcpy(requestBuffer.data(), &request, REQUEST_HEADER_SIZE);

	/* pack the payload */
	memcpy(requestBuffer.data() + REQUEST_HEADER_SIZE, _userName.c_str(), _userName.length());//23 is where payload starts
	memset(requestBuffer.data() + REQUEST_HEADER_SIZE + _userName.length(), '\0', FILE_NAME_SIZE - _userName.length());
	memcpy(requestBuffer.data() + REQUEST_HEADER_SIZE + _userName.length(), "\0", 1);//add null ptr for name
}

/* handle client register in the first time  */
uint8_t* ClientLogic::handleRegisterationRequest(vector<uint8_t>& requestBuffer, vector<uint8_t>& responseBuffer)
{
	ServerResponse* response = nullptr;
	bool _connected = false;
	for (int i = 0; i < MAX_SENDS; i++)
	{
		createRegisterationRequest(requestBuffer);
		if (!_socket->write(requestBuffer))
		{
			clientStop("socket failure, The data cannot be write");
		}
		responseBuffer.clear();
		responseBuffer.resize(PACKET_SIZE);
		responseBuffer = _socket->read();
		if (responseBuffer.empty())
		{
			clientStop("socket failure, The data cannot be read");
		}
		response = unpackResponse(responseBuffer, PACKET_SIZE);

		if (response == nullptr)
		{
			clientStop("response header is not appropriate to the protocol");
		}
		if (response->header.code == ServerResponse::SResponseCode::REGISTRATION_REQUEST_FAILED)
		{
			clientStop("name is already seen in the database");
		}

		if (response->header.code == ServerResponse::SResponseCode::GENERAL_ERR)
		{
			continue;
		}
		if (response->header.code == ServerResponse::SResponseCode::REGISTRATION_REQUEST_SUCCESS)
		{
			_succseed = true;
			break;
		}

	}
	if (!_succseed)
	{
		clientStop("registration request failed");
	}

	/* parse the client UID from server response and return her */
	response->payload.payload[UID_SIZE] = '\0';
	return response->payload.payload;
}

/* after the client registers for the first time or when the reconnection fails -
the client exchanges encryption keys with the server so that it can send the file to backup on the server encrypted */
void ClientLogic::handlePublicKeyRequest(vector<uint8_t>& requestBuffer, vector<uint8_t>& responseBuffer)
{
	ServerResponse* response = nullptr;
	for (int i = 0; i < MAX_SENDS; i++)
	{
		createPublicKeyRequest(requestBuffer);
		if (!_socket->write(requestBuffer))
		{
			clientStop("socket failure, The data cannot be write");
		}
		responseBuffer.clear();
		responseBuffer.resize(PACKET_SIZE);
		responseBuffer = _socket->read();
		if (responseBuffer.empty())
		{
			clientStop("socket failure, The data cannot be read");
		}

		response = unpackResponse(responseBuffer, PACKET_SIZE);

		if (response == nullptr)
		{
			clientStop("response header is not appropriate to the protocol");
		}

		if (response->header.code == ServerResponse::SResponseCode::GOT_PC_SEND_AES)
		{
			_succseed = true;
			_AESKey = extractAESKey(response->payload.payload, response->header.payloadSize);
			break;
		}
	}
	if (!_succseed)
	{
		clientStop("registration request failed");
	}

}
void ClientLogic::createPublicKeyRequest(vector<uint8_t>& requestBuffer)
{
	requestBuffer.clear();
	requestBuffer.resize(PACKET_SIZE);
	PublicKeyRequest request(PUBLIC_KEY_REQUEST, NAME_SIZE + PUBLIC_KEY_SIZE);

	/* pack the header */
	std::string unhexUID = Utils::reverse_hexi(_clientUID);
	unhexUID.copy(reinterpret_cast<char*>(request.header.uid), sizeof(request.header.uid));
	memcpy(requestBuffer.data(), &request, REQUEST_HEADER_SIZE);

	/* pack the payload */
	memcpy(requestBuffer.data() + CLIENT_HEADER_SIZE, _userName.c_str(), NAME_SIZE);
	memcpy(requestBuffer.data() + REQUEST_HEADER_SIZE + NAME_SIZE, "\0", 1);//add null ptr for name
	memcpy(requestBuffer.data() + CLIENT_HEADER_SIZE + NAME_SIZE, _publicKey.c_str(), PUBLIC_KEY_SIZE);
}

/* prepare the file storage request for backup */
bool ClientLogic::createFileStorageRequest(vector<std::uint8_t>& requestBuffer)
{
	/* check if the payload size is smaller then the max excpected payload size  */
	if (CONTENT_SIZE + FILE_NAME_SIZE + _encryptedContent.size() > std::numeric_limits<unsigned int>::max())
	{
		return false;
	}

	fileSendRequest request(FILE_SEND_REQUEST, CONTENT_SIZE + FILE_NAME_SIZE + _encryptedContent.size());
	requestBuffer.clear();
	requestBuffer.resize(request.header.payloadSize);

	/* pack the header */
	std::string unhexUID = Utils::reverse_hexi(_clientUID);
	unhexUID.copy(reinterpret_cast<char*>(request.header.uid), sizeof(request.header.uid));
	memcpy(requestBuffer.data(), &request, REQUEST_HEADER_SIZE);

	uint32_t contentSize = _encryptedContent.size();

	/* extract file name for the client file path */
	string fileName1 = _filePath.substr(_filePath.find_last_of("/\\") + 1);

	/* pack the payload */
	memcpy(requestBuffer.data() + REQUEST_HEADER_SIZE, &contentSize, CONTENT_SIZE);
	memcpy(requestBuffer.data() + REQUEST_HEADER_SIZE + CONTENT_SIZE, fileName1.c_str(), FILE_NAME_SIZE);//check why FILE_NAME_SIZE
	memset(requestBuffer.data() + REQUEST_HEADER_SIZE + CONTENT_SIZE + fileName1.length(), '\0', FILE_NAME_SIZE - fileName1.length());
	memcpy(requestBuffer.data() + REQUEST_HEADER_SIZE + CONTENT_SIZE + FILE_NAME_SIZE, _encryptedContent.c_str(), contentSize);

	return true;
}

/* handle send client file for backup request */
uint32_t ClientLogic::handleFileStorageRequest(vector<uint8_t>& requestBuffer, vector<uint8_t>& responseBuffer)
{
	ServerResponse* response = nullptr;

	for (int i = 0; i < MAX_SENDS; i++)
	{
		if (!createFileStorageRequest(requestBuffer))
		{
			clientStop("request payload size is greater then the expected in the protocol");
		}

		uint32_t payloadSize;
		memcpy(&payloadSize, requestBuffer.data() + 19, CRC_SIZE); //19 is where the payload size gonna start
		if (!_socket->writeChuncks(requestBuffer, payloadSize))
		{
			clientStop("socket failure, The data cannot be write");
		}
		responseBuffer.clear();
		responseBuffer.resize(PACKET_SIZE);
		responseBuffer = _socket->read();
		if (responseBuffer.empty())
		{
			clientStop("socket failure, The data cannot be read");
		}

		response = unpackResponse(responseBuffer, PACKET_SIZE);

		if (response == nullptr)
		{
			clientStop("response header is not appropriate to the protocol");
		}
		if (response->header.code == ServerResponse::SResponseCode::GENERAL_ERR)
		{
			continue;
		}

		if (response->header.code == ServerResponse::SResponseCode::GOT_FILE_SEND_CRC)
		{
			_succseed = true;
			break;
		}
	}
	if (!_succseed)
	{
		clientStop("file send request failed");
	}
	uint32_t serverCRC;
	memcpy(&serverCRC, &(response->payload.payload)[FILE_NAME_SIZE + UID_SIZE + CONTENT_SIZE], CRC_SIZE);
	return serverCRC;
}

/* handle crc ok, crc failed and retry crc requests */
void ClientLogic::handleSendFileAndCRCRequest(vector<uint8_t>& requestBuffer, vector<uint8_t>& responseBuffer)
{
	int i = 0;
	ServerResponse* response = nullptr;
	while (true)
	{
		uint32_t serverCRC = handleFileStorageRequest(requestBuffer, responseBuffer);
		_succseed = false;
		if (_clientCRC == serverCRC)
		{
			handleCRCIsOkREQUEST(requestBuffer, responseBuffer);
			break;
		}
		else if (i + 1 != MAX_CRC_SEND)
		{
			handleRetryCRCRequest(requestBuffer);
		}
		else
		{
			handleFailedCRCRequest(requestBuffer, responseBuffer);
			_socket->write(requestBuffer);
			break;
		}
		i++;
	}
}

/* prepare appropriate crc request */
bool ClientLogic::createCRCValidateRequest(vector<uint8_t>& requestBuffer, bool validate)
{
	requestBuffer.clear();
	requestBuffer.resize(PACKET_SIZE);
	CRCValidateRequest request(CRC_VALID_REQUEST, FILE_NAME_SIZE);

	if (!validate)
	{
		request.header.code = CRC_FAILED_REQUEST;
	}

	/* pack the header */
	std::string unhexUID = Utils::reverse_hexi(uid);
	unhexUID.copy(reinterpret_cast<char*>(request.header.uid), sizeof(request.header.uid));
	memcpy(requestBuffer.data(), &request, REQUEST_HEADER_SIZE);

	/* extract file name for the client file path */
	string fileName = _filePath.substr(_filePath.find_last_of("/\\") + 1);

	/* pack the payload */
	memcpy(requestBuffer.data() + REQUEST_HEADER_SIZE, fileName.c_str(), FILE_NAME_SIZE);//check why FILE_NAME_SIZE
	memset(requestBuffer.data() + REQUEST_HEADER_SIZE + fileName.length(), '\0', FILE_NAME_SIZE - fileName.length());

	return true;
}

/* when the check sum of the file are equel in both client-server side - handle crc ok request  */
void ClientLogic::handleCRCIsOkREQUEST(vector<uint8_t>& requestBuffer, vector<uint8_t>& responseBuffer)
{
	ServerResponse* response = nullptr;

	for (int i = 0; i < MAX_SENDS; i++)
	{
		createCRCValidateRequest(requestBuffer);
		if (!_socket->write(requestBuffer))
		{
			clientStop("socket failure, The data cannot be write");
		}
		responseBuffer.clear();
		responseBuffer.resize(PACKET_SIZE);
		responseBuffer = _socket->read();

		if (responseBuffer.empty())
		{
			clientStop("socket failure, The data cannot be read");
		}
		response = unpackResponse(responseBuffer, PACKET_SIZE);

		if (response == nullptr)
		{
			clientStop("response header is not appropriate to the protocol");
		}
		if (response->header.code == ServerResponse::SResponseCode::GENERAL_ERR)
		{
			continue;
		}

		if (response->header.code == ServerResponse::SResponseCode::GOT_REQ_TNX)
		{
			_succseed = true;
			break;
		}

	}
	if (!_succseed)
	{
		clientStop("CRC ok request failed");
	}
}

/* when the check sum response to the client request
doesnt varified in the client side - send again the file for validation */
void ClientLogic::handleRetryCRCRequest(vector<uint8_t>& requestBuffer)
{
	createCRCValidateRequest(requestBuffer, false);
	if (!_socket->write(requestBuffer))
	{
		clientStop("socket failure, The data cannot be write");
	}
}

bool ClientLogic::createCRCFailedRequest(vector<uint8_t>& requestBuffer)
{
	requestBuffer.clear();
	CRCFailedRequest request(FOUR_FAILED_CRC_REQUEST, FILE_NAME_SIZE);

	/* pack the header */
	std::string unhexUID = Utils::reverse_hexi(uid);
	unhexUID.copy(reinterpret_cast<char*>(request.header.uid), sizeof(request.header.uid));
	memcpy(requestBuffer.data(), &request, REQUEST_HEADER_SIZE);

	/* extract file name for the client file path */
	string fileName = _filePath.substr(_filePath.find_last_of("/\\") + 1);

	/* pack the payload */
	memcpy(requestBuffer.data() + REQUEST_HEADER_SIZE, fileName.c_str(), FILE_NAME_SIZE);//check why FILE_NAME_SIZE
	memset(requestBuffer.data() + REQUEST_HEADER_SIZE + fileName.length(), '\0', FILE_NAME_SIZE - fileName.length());
	return true;
}

/* crc request failed in the four time - stop sending and inform the server about it  */
void ClientLogic::handleFailedCRCRequest(vector<uint8_t>& requestBuffer, vector<uint8_t>& responseBuffer)
{
	ServerResponse* response = nullptr;
	for (int i = 0; i < MAX_SENDS; i++)
	{

		createCRCFailedRequest(requestBuffer);
		if (!_socket->write(requestBuffer))
		{
			clientStop("socket failure, The data cannot be write");
		}
		responseBuffer.clear();
		responseBuffer.resize(PACKET_SIZE);
		responseBuffer = _socket->read();

		if (responseBuffer.empty())
		{
			clientStop("socket failure, The data cannot be read");
		}
		response = unpackResponse(responseBuffer, PACKET_SIZE);

		if (response == nullptr)
		{
			clientStop("response header is not appropriate to the protocol");
		}

		if (response->header.code == ServerResponse::SResponseCode::GENERAL_ERR)
		{
			continue;
		}

		if (response->header.code == ServerResponse::SResponseCode::GOT_REQ_TNX)
		{
			_succseed = true;
			break;
		}
	}
	if (!_succseed)
	{
		clientStop("failed CRC request failed");
	}
}

/* client already sign in before to the server services -
send recconect request then after it client will can send the file for backup */
void ClientLogic::handleReconnectRequest(vector<uint8_t>& requestBuffer, vector<uint8_t>& responseBuffer)
{
	ServerResponse* response = nullptr;
	for (int i = 0; i < MAX_SENDS; i++)
	{
		createRegisterationRequest(requestBuffer, true);
		if (!_socket->write(requestBuffer))
		{
			clientStop("socket failure, The data cannot be write");
		}
		responseBuffer.clear();
		responseBuffer.resize(PACKET_SIZE);
		responseBuffer = _socket->read();
		if (responseBuffer.empty())
		{
			clientStop("socket failure, The data cannot be read");
		}

		response = unpackResponse(responseBuffer, PACKET_SIZE);

		if (response == nullptr)
		{
			clientStop("response header is not appropriate to the protocol");
		}
		if (response->header.code == ServerResponse::SResponseCode::GENERAL_ERR)
		{
			continue;
		}
		if (response->header.code == ServerResponse::SResponseCode::RECONNECT_FAILED)
		{
			/* reconnect failed: user name already exists on server database -
			The client is re-registered as a new client and replaces with the server encryption keys */

			_clientUID = Utils::hexi(handleRegisterationRequest(requestBuffer, responseBuffer), UID_SIZE);
			handlePublicKeyRequest(requestBuffer, responseBuffer);
			_succseed = true;
			break;
		}

		if (response->header.code == ServerResponse::SResponseCode::LOGIN_SUCCESS_SEND_AES)
		{
			_succseed = true;
			_AESKey = extractAESKey(response->payload.payload, response->header.payloadSize);
			break;
		}
	}
	if (!_succseed)
	{
		clientStop("registration request failed");
	}
}

/* run the client in batch mode */
void ClientLogic::clientMain()
{
	try 
	{
		vector<uint8_t> responseBuffer(PACKET_SIZE);
		vector<uint8_t> requestBuffer(PACKET_SIZE);
		if (!parseAndStoreTransferInfo(TRANSFER_INFO))
		{
			clientStop("couldn't parse file transfer details");
		}

		if (!_socket->connectToServer())
		{
			clientStop("failed to connect server");
		}

		if (!_fileHandler->checkFileExsistance(CLIENT_INFO))
		{
			/* the file me.info did not exist - the client registered for the first time */

			_clientUID = Utils::hexi(handleRegisterationRequest(requestBuffer, responseBuffer), UID_SIZE);

			_succseed = false;
			responseBuffer.clear();
			responseBuffer.resize(PACKET_SIZE);
			if (!parseAndStoreClientInfo())
			{
				clientStop("failed create and store me info for client");
			}
			handlePublicKeyRequest(requestBuffer, responseBuffer);
		}

		else
		{
			/* The client has already registered before - the me.info file is found */

			if (!_fileHandler->openFile(CLIENT_INFO))
			{
				clientStop("couldn't open me.info file");
			}

			/* parse client info and store them localy */
			_fileHandler->readLine(_userName);
			_userName.erase(_userName.size() - 1);
			_fileHandler->readLine(_clientUID);
			_clientUID.erase(_clientUID.size() - 1);
			_fileHandler->closeFile();

			_succseed = false;

			handleReconnectRequest(requestBuffer, responseBuffer);
		}

		/* there is no such file in the client path */
		if (!_fileHandler->checkFileExsistance(_filePath))
		{
			clientStop("wrong path to client file");
		}

		/* parse file content and send it to the server for backup */
		string fileContent = _fileHandler->extractFileContent(_filePath);

		/* caulcalate the client file CKsum */
		_clientCRC = caulcalateCRC(fileContent);

		_encryptedContent = encryptFileUsingAESKey(fileContent);//here is the problen the buffer is change in this function

		handleSendFileAndCRCRequest(requestBuffer, responseBuffer);
	}
	catch (const std::exception& e)
	{
		throw e;
	}

}

