#pragma once
#include <iostream>
#include <base64.h>

using namespace std;

class Utils
{
public:
	static string reverse_hexi(const string& hexString);
	static string hexi(const uint8_t* buffer, const size_t size);
	static string encode(const string& str);
	static string decode(const std::string& str);
};