#pragma once
#include <boost/asio.hpp>
#include "protocol.h"
#include "SocketHandler.h"
#include "FileHandler.h"
#include "Utils.h"

constexpr auto CLIENT_INFO = "../Debug/me.info"; // Should be located near exe file.
constexpr auto TRANSFER_INFO = "../Debug/transfer.info"; // Should be located near exe file.

using namespace std;
using boost::asio::ip::tcp;

class FileHandler;
class SocketHandler;
class RSAPrivateWrapper;

class ClientLogic
{
public:
	ClientLogic();
	~ClientLogic();
	void clientStop(const string& error);
	ServerResponse* unpackResponse(vector<uint8_t> responseBuffer, const uint32_t size);
	bool parseAndStoreTransferInfo(const string& path);
	string extractAESKey(uint8_t* payload, uint32_t len);
	uint32_t caulcalateCRC(string fileContent);
	string encryptFileUsingAESKey(string fileContent);
	void clientMain();
	bool parseAndStoreClientInfo();
	void createRegisterationRequest(vector<uint8_t>& requestBuffer, bool reconnect = false);  //reconnect initialize to false - if client want to reconnect then we pass true as the senocd argument
	void createPublicKeyRequest(vector<uint8_t>& requestBuffer);
	bool createFileStorageRequest(vector<std::uint8_t>& requestBuffer);
	bool createCRCFailedRequest(vector<uint8_t>& requestBuffer);
	bool createCRCValidateRequest(vector<uint8_t>& requestBuffer, bool validate = true);  // validate true indicate the the crc check was succeeded
	void handleRetryCRCRequest(vector<uint8_t>& requestBuffer);
	void handleFailedCRCRequest(vector<uint8_t>& requestBuffer, vector<uint8_t>& responseBuffer);
	void handleReconnectRequest(vector<uint8_t>& requestBuffer, vector<uint8_t>& responseBuffer);
	void handleSendFileAndCRCRequest(vector<uint8_t>& requestBuffer, vector<uint8_t>& responseBuffer);
	void handleCRCIsOkREQUEST(vector<uint8_t>& requestBuffer, vector<uint8_t>& responseBuffer);
	void handlePublicKeyRequest(vector<uint8_t>& requestBuffer, vector<uint8_t>& responseBuffer);
	uint8_t* handleRegisterationRequest(vector<uint8_t>& requestBuffer, vector<uint8_t>& responseBuffer); // returning the client ID
	uint32_t handleFileStorageRequest(vector<uint8_t>& requestBuffer, vector<uint8_t>& responseBuffer);  // returning the culcaulate CKsum
private:
	string _userName;
	string _filePath;
	string address;
	string port;
	string _publicKey;
	string _base64privateKey;
	string _AESKey;
	string uid;
	string _encryptedContent;
	FileHandler* _fileHandler;
	SocketHandler* _socket;
	RSAPrivateWrapper* _RSAPair;
	string _clientUID;
	bool _succseed;
	uint32_t _clientCRC;
};