#include "FileHandler.h"
#include <iostream>
#include <sstream>
#include "ClientLogic.h"

FileHandler::FileHandler()
{
    ioFile = nullptr;
}

bool FileHandler::openFile(const string& filepath, bool read)
{
    if (read)
    {
        ioFile = new std::fstream(filepath, std::ios::in | std::ios::binary);
    }
    else
    {
        ioFile = new std::fstream(filepath, std::ios::out);

    }

    if (!ioFile->is_open())
    {

        delete ioFile;
        ioFile = nullptr;
        return false;
    }
    return true;
}

/* check if client info file was created already before */
bool FileHandler::checkFileExsistance(string info)
{
    std::ifstream meFile(info);
    if (!meFile)
    {
        return false;
    }

    return true;
}

void FileHandler::readLine(string& line)
{
    if (ioFile == nullptr || !ioFile->is_open())
    {
        std::cout << "Error: file is not open." << std::endl;
        return;
    }

    if (std::getline(*ioFile, line))
    {

    }
    else
    {
        std::cout << "Error reading line." << std::endl;
    }
}

void FileHandler::closeFile()
{
    if (ioFile != nullptr)
    {
        ioFile->close();
        delete ioFile;
        ioFile = nullptr;
    }
}

void FileHandler::writeAtOnce(const string& line)
{
    if (ioFile->is_open())
    {
        *ioFile << line;
    }
}

/* extract base64 private key from client info file */
std::string FileHandler::extractBase64privateKey(const string& path)
{
    ifstream infile(path);
    std::string line;
    std::string base64;

    /* base64 private key starts in the third line in the client info file */
    std::getline(infile, line);
    std::getline(infile, line);
    while (std::getline(infile, line))
    {
        base64 += line;
    }

    infile.close();
    return base64;
}

/* extract file content in binary mode */
std::string FileHandler::extractFileContent(string& path)
{
    std::ifstream infile(path, std::ios::binary);

    /* failed to open client file */
    if (!infile)
    {
        return "";
    }

    /* Read the contents of the file into a stringstream */
    std::stringstream buffer;
    buffer << infile.rdbuf();

    /* Convert the stringstream to a string */
    std::string fileContent = buffer.str();

    infile.close();
    return fileContent;
}


void FileHandler::writeLine(const string& line) 
{
    if (ioFile->is_open())
    {
        *ioFile << line << std::endl;
    }
}

FileHandler::~FileHandler()
{
    closeFile();
}
