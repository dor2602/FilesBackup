#include "Utils.h"
#include <boost/algorithm/hex.hpp>

/*  convert to unhex representation */
string Utils::reverse_hexi(const string& hexString)
{
	try
	{
		std::string byteString;
		boost::algorithm::unhex(hexString, std::back_inserter(byteString));
		return byteString;
	}
	catch (...)
	{
		return "";
	}
}

/*  convert to hexedecimal representation */
string Utils::hexi(const uint8_t* buffer, const size_t size)
{
	if (size == 0 || buffer == nullptr)
		return "";
	const std::string byteString(buffer, buffer + size);
	if (byteString.empty())
		return "";
	try
	{
		return boost::algorithm::hex(byteString);
	}
	catch (...)
	{
		return "";
	}
}

/* base64 encoder */
std::string Utils::encode(const std::string& str)
{
	std::string encoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded)
		) // Base64Encoder
	); // StringSource

	return encoded;
}

/* base64 decoder */
std::string Utils::decode(const std::string& str)
{
	std::string decoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decoded)
		) // Base64Decoder
	); // StringSource

	return decoded;
}
