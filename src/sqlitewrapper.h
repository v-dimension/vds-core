#ifndef SQLITEWRAPPER_H
#define SQLITEWRAPPER_H

#include "clientversion.h"
#include "serialize.h"
#include "streams.h"
#include "util.h"
#include "version.h"
#include "utilstrencodings.h"

#include <boost/filesystem/path.hpp>
#include "sqlite3.h"

class uint256;
using namespace std;


class sqlite_error : public std::runtime_error
{
public:
    sqlite_error(const std::string& msg) : std::runtime_error(msg)
    {
    }
};

class ImFriendStruct
{
public:
    explicit ImFriendStruct()
    {
        vaddr = "";
        friendAddr = "";
        friendName = "";
        headPix.clear();
        remarks = "";
        blackList = 0;
    }
    void insertHeadPix(char* _headPix, int _size)
    {
        headPix.insert(headPix.begin(), _headPix, _headPix + _size);
    }
    string vaddr;
    string friendAddr;
    string friendName;
    std::vector<char> headPix;
    string remarks;
    int blackList;
};


class CSqliteWrapper
{
private:
    sqlite3* pdb;
    explicit CSqliteWrapper(const boost::filesystem::path& path);
    ~CSqliteWrapper();
    void HandleError(const int& status);
    static CSqliteWrapper* p;
    void createFriendTable();
    int stringToInt(const string str);
public:
    static CSqliteWrapper* getInstance();
    void createTables();

    //friend
    bool insertFriend(ImFriendStruct _friendStruct);
    bool deleteFriend(string vaddr, string friendAddr);
    bool getAllFriend(string vaddr, std::list<ImFriendStruct>& Friends);
    bool findFriend(string vaddr);
    //black
    bool insertBlack(string vaddr, string name);
    bool deleteBlack(string vaddr);
    bool getAllBlack(std::map<string, string>& mapBlack);


};

#endif // SQLITEWRAPPER_H
