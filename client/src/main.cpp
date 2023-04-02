#include "ClientLogic.h"
#include <iostream>
//
int main()
{
	try
	{
		ClientLogic client;
		client.clientMain();
		cout << "Communication with the server was successful. The file has been transferred to the server for backup." << endl;
		return 0;
	}
	catch (const std::exception& e)
	{
		cout << e.what() << endl;
		exit(1);
	}
}


