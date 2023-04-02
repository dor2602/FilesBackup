#pragma once
#include <fstream>
#include <string>

using namespace std;

class FileHandler
{
public:
    FileHandler();
    bool openFile(const string& filepath, bool read = true);
    void closeFile();
    void readLine(string& line);
    void writeLine(const string& line);
    bool checkFileExsistance(string info);
    std::string extractFileContent(string& path);
    std::string extractBase64privateKey(const string& path);
    void writeAtOnce(const string& line);
    ~FileHandler();
private:
    std::fstream* ioFile;
};
