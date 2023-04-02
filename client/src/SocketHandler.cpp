#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <iostream>
#include "protocol.h"
#include "SocketHandler.h"


using boost::asio::ip::tcp;
using boost::asio::io_context;

SocketHandler::SocketHandler() : _ioContext(nullptr), _resolver(nullptr), _socket(nullptr)
{
	_ioContext = new io_context();
	_socket = new tcp::socket(*_ioContext);
	_resolver = new tcp::resolver(*_ioContext);
}

/* initalize socket info */
bool SocketHandler::initializeSocketInfo(const string& address, const string& port)
{
	if (!addressValidation(address) || !portValidation(port))
	{
		return false;
	}
	_address = address;
	_port = port;

	return true;
}

/* make connection to the server */
bool SocketHandler::connectToServer()
{
	try
	{
		auto endpoint = _resolver->resolve(_address, _port);
		boost::asio::connect(*_socket, endpoint);
		_socket->non_blocking(false);
	}
	catch (...)
	{
		return false;
	}
	return true;
}

/* write the request in one chunk of 2048 bytes */
bool SocketHandler::write(vector<uint8_t>& requestBuffer)
{
	boost::system::error_code error;
	const size_t len = boost::asio::write(*_socket, boost::asio::buffer(requestBuffer.data(), PACKET_SIZE), error);
	if (len == 0)
	{
		cout << "message was not sent!" << endl;

		/* error. Failed sending and shouldn't use buffer.*/
		return false;
	}

	if (error)
	{

		return false;
	}
	cout << "message sent!" << endl;
	return true;
}


/* read server resonse in one chunk of 2048 bytes  */
std::vector<uint8_t> SocketHandler::read()
{
	boost::system::error_code error;
	
	boost::asio::deadline_timer timer(*_ioContext);
	timer.expires_from_now(boost::posix_time::seconds(25));

	/* set up a deadline timer to cancel the blocking read operation if it takes too long */ 
	timer.async_wait([&error](const boost::system::error_code& ec) {
		if (ec != boost::asio::error::operation_aborted) {
			error = boost::asio::error::timed_out;
		}
		});

	auto data = make_unique<vector<uint8_t>>(PACKET_SIZE);
	size_t len = boost::asio::read(*_socket, boost::asio::buffer(*data), error);

	/* cancel the timer now that the blocking read operation has completed */ 
	timer.cancel();

	if (len == 0) 
	{
		std::cout << "response message failed!" << std::endl;
		/* error. Failed receiving and shouldn't use buffer.*/
		return vector<uint8_t>();
	}

	if (error && error != boost::asio::error::eof) {
		std::cout << "read failed: " << error.message() << std::endl;
		return vector<uint8_t>(); // Some other error.
	}

	std::cout << "response message was read!" << std::endl;
	return std::move(*data);
}




/* sending file in chunks, first send the header and after that send the data in 2048 bytes size chuck */
bool SocketHandler::writeChuncks(vector<uint8_t>& requestBuffer, uint32_t payload_size)
{
	boost::system::error_code error;
	const size_t len = boost::asio::write(*_socket, boost::asio::buffer(requestBuffer, CLIENT_HEADER_SIZE), error);

	if (len == 0 || error)
	{
		/* error. Failed sending and shouldn't use buffer.*/
		return false;
	}

	for (uint32_t i = 0; i < payload_size; i += PACKET_SIZE)
	{
		size_t bytes_written = _socket->write_some(boost::asio::buffer(requestBuffer.data() + i + CLIENT_HEADER_SIZE, std::min<uint32_t>(PACKET_SIZE, payload_size - i)), error);
		if (bytes_written == 0 || error)
		{
			/* error. Failed sending and shouldn't use buffer.*/
			return false;
		}

	}
	requestBuffer.clear();
	requestBuffer.resize(PACKET_SIZE);
	
	return true;
}
/* address validation */
bool SocketHandler::addressValidation(const string& address)
{
	if ((address == "localhost") || (address == "LOCALHOST"))
		return true;
	try
	{
		(void)boost::asio::ip::address_v4::from_string(address);
	}
	catch (...)
	{
		return false;
	}
	return true;
}


/* port validation */
bool SocketHandler::portValidation(const string& port)
{
	try
	{
		const int p = std::stoi(port);
		return (p != 0);  // port 0 is invalid..
	}
	catch (...)
	{
		return false;
	}
}

SocketHandler::~SocketHandler()
{
	delete _ioContext;
	delete _socket;
	delete _resolver;
}

