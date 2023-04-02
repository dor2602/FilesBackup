#pragma once

constexpr auto VERSION = 3;
constexpr auto PACKET_SIZE = 2048;
constexpr auto UID_SIZE = 16;
constexpr auto VERSION_SIZE = 1;
constexpr auto CODE_SIZE = 2;
constexpr auto PAYLOAD_SIZE = 4;
constexpr auto REQUEST_HEADER_SIZE = 23;
constexpr auto HEADER_SIZE = 7;
constexpr auto NAME_SIZE = 255;
constexpr auto PUBLIC_KEY_SIZE = 160;
constexpr auto CLIENT_HEADER_SIZE = 23;
constexpr auto CONTENT_SIZE = 4;
constexpr auto CRC_SIZE = 4;
constexpr auto FILE_NAME_SIZE = 255;
constexpr auto MAX_CRC_SEND = 4;
constexpr auto MAX_NAME_SIZE = 100;
constexpr auto MAX_SENDS = 4;

enum { DEF_VAL = 0 };  // default value used to initialize protocol structures.

typedef uint16_t code_t;
typedef uint32_t payload_t;

enum CRequestCode
{
	REGISTRATION_REQUEST = 1100,   // uuid ignored.
	PUBLIC_KEY_REQUEST = 1101,
	LOGIN_REQUEST = 1102,
	FILE_SEND_REQUEST = 1103,
	CRC_VALID_REQUEST = 1104,
	CRC_FAILED_REQUEST = 1105,
	FOUR_FAILED_CRC_REQUEST = 1106
};

#pragma pack(push, 1) // with this we can pack all the struct in once
struct ClientRequestHeader
{
	uint8_t uid[16]; //16 bytes
	uint8_t  version; //one byte
	uint16_t  code;   // the request code to execute  , 2 byets
	uint32_t payloadSize; //4 byets  payload size
	ClientRequestHeader(code_t requestCode, payload_t payloadSize) : uid{ '\0' }, version(VERSION), code(requestCode), payloadSize(payloadSize) {}
};
#pragma pack(pop)


struct PublicKeyRequest
{
	ClientRequestHeader header;
	PublicKeyRequest(code_t requestCode, payload_t payloadSize) : header(requestCode, payloadSize) {}

};

struct RegisterationRequest
{
	ClientRequestHeader header;
	RegisterationRequest(code_t requestCode, payload_t payloadSize) : header(requestCode, payloadSize) {}
};

struct ReconnectionRequest
{
	ClientRequestHeader header;
	ReconnectionRequest(code_t requestCode, payload_t payloadSize) : header(requestCode, payloadSize) {}
};

struct fileSendRequest
{
	ClientRequestHeader header;
	fileSendRequest(code_t requestCode, payload_t payloadSize) : header(requestCode, payloadSize) {}
};

struct CRCValidateRequest
{
	ClientRequestHeader header;
	CRCValidateRequest(code_t requestCode, payload_t payloadSize) : header(requestCode, payloadSize) {}
};

struct CRCFailedRequest
{
	ClientRequestHeader header;
	CRCFailedRequest(code_t requestCode, payload_t payloadSize) : header(requestCode, payloadSize) {}
};

struct retryFileSendRequest
{
	ClientRequestHeader header;
	retryFileSendRequest(code_t requestCode, payload_t payloadSize) : header(requestCode, payloadSize) {}
};

struct ServerResponse
{

	struct SResponseHeader
	{
		uint8_t  version; //one byte
		uint16_t  code;   // the request code to execute  , 2 byets
		uint32_t payloadSize; //4 byets  payload size
		SResponseHeader() : version(VERSION), code(DEF_VAL), payloadSize(DEF_VAL) {}

	};
	enum SResponseCode
	{
		REGISTRATION_REQUEST_SUCCESS = 2100,   // uuid ignored.
		REGISTRATION_REQUEST_FAILED = 2101,
		GOT_PC_SEND_AES = 2102,
		GOT_FILE_SEND_CRC = 2103,
		GOT_REQ_TNX = 2104,
		LOGIN_SUCCESS_SEND_AES = 2105,
		RECONNECT_FAILED = 2106,
		GENERAL_ERR = 2107
	};

	struct Payload
	{
		uint8_t* payload;
		Payload() : payload(nullptr) {}
	};

	SResponseHeader header;  // request header
	Payload payload;
};
