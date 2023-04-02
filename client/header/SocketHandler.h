#pragma once
#include <string>
#include <cstdint>
#include <ostream>
#include <boost/asio/ip/tcp.hpp>

using boost::asio::ip::tcp;
using boost::asio::io_context;
using namespace std;

class SocketHandler
{
public:
	SocketHandler();
	~SocketHandler();
	static bool addressValidation(const string& address);
	static bool portValidation(const string& port);
	bool connectToServer();
	bool initializeSocketInfo(const string& address, const string& port);
	vector<uint8_t> read();

	bool writeChuncks(vector<uint8_t>& requestBuffer, uint32_t payload_size);
	bool write(vector<uint8_t>& requestBuffer);
private:
	std::string    _address;
	std::string    _port;
	io_context* _ioContext;
	tcp::resolver* _resolver;
	tcp::socket* _socket;
};