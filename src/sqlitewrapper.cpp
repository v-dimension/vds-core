#include "sqlitewrapper.h"
#include "util.h"
#include "timedata.h"
#include <boost/filesystem.hpp>
#include <stdio.h>
#include <inttypes.h>

CSqliteWrapper* CSqliteWrapper::p = NULL;

CSqliteWrapper::CSqliteWrapper(const boost::filesystem::path& path)
{
    TryCreateDirectory(path);
    LogPrintf("Opening sqliteDB in %s\n", path.string());

    boost::filesystem::path unencryptedPath = path / "sqlite.db";

    pdb = NULL;
    LogPrintf("SQLITE_THREADSAFE: %d\n", sqlite3_threadsafe());
    int ret = sqlite3_config(SQLITE_CONFIG_SERIALIZED);
    if (ret != SQLITE_OK) {
        LogPrintf("filed to config slqite3, %d\n", ret);
    }

    int status = sqlite3_open(unencryptedPath.string().c_str(), &pdb);
    HandleError(status);
    createTables();
    LogPrintf("Open sqliteDB successfully\n");
}
CSqliteWrapper* CSqliteWrapper::getInstance()
{
    if (p == NULL) {
        p = new CSqliteWrapper(GetDataDir());
    }
    return p;
}
void CSqliteWrapper::HandleError(const int& status)
{
    if (!status) {
        return;
    }
    sqlite3_close(pdb);
    LogPrintf( "%s\n", sqlite3_errmsg(pdb));
    throw sqlite_error(sqlite3_errmsg(pdb));
}
CSqliteWrapper::~CSqliteWrapper()
{
    sqlite3_close(pdb);
}
void CSqliteWrapper::createTables()
{
    createFriendTable();
//    std::map<ImFriendStruct> tmpMap;
//    getAllFriend(tmpMap );
//    std::map<string, string>::iterator it;
//    for (it =  tmpMap.begin(); it != tmpMap.end(); it++) {
//        LogPrintf("qweqwe---%s---%s\n", (*it).first, (*it).second);
//    }
}
void CSqliteWrapper::createFriendTable()
{
    char* errMsg = 0;
    string tableName = "friendtable";
    char sql[2000] = {0};
    sprintf(sql, "CREATE TABLE IF NOT EXISTS %s(vaddr CHAR(60) ,friendAddr CHAR(60), friendName CHAR(60), headPix BLOB ,remarks CHAR(100), blacklist INT);", tableName.c_str());
    sqlite3_exec(pdb, sql, 0, 0, &errMsg);
    return;
}
int CSqliteWrapper::stringToInt(const string str)
{
    return atoi(str.c_str());
}
bool CSqliteWrapper::insertFriend(ImFriendStruct _friendStructt)
{
    char* errMsg = 0;
    char sql[2000] = {0};
    sprintf(sql, "REPLACE INTO friendtable (vaddr, friendAddr, friendName, headPix, remarks, blackList) VALUES (\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%d\");", _friendStructt.vaddr.c_str(), _friendStructt.friendAddr.c_str(), _friendStructt.friendName.c_str(), _friendStructt.headPix.data(), _friendStructt.remarks.c_str(), _friendStructt.blackList);
    //LogPrintf("%s\n", sql);
    sqlite3_exec(pdb, sql, 0, 0, &errMsg);
    return true;
}
bool CSqliteWrapper::deleteFriend(string vaddr, string friendAddr)
{
    char* errMsg = 0;
    char sql[2000] = {0};
    sprintf(sql, "DELETE FROM friendtable WHERE vaddr=\"%s\" and friendAddr=\"%s\";", vaddr.c_str(), friendAddr.c_str());
    //LogPrintf("%s\n", sql);
    sqlite3_exec(pdb, sql, 0, 0, &errMsg);
    return true;
}
bool CSqliteWrapper::getAllFriend(std::string vaddr, std::list<ImFriendStruct>& Friends)
{
    //addr ,name
    char* errMsg = 0;
    char sql[2000] = {0};
    sprintf(sql, "SELECT vaddr, friendAddr, friendName, headPix, remarks, blackList from friendtable WHERE vaddr = \"%s=\";", vaddr.c_str());
    //LogPrintf("%s\n", sql);
    sqlite3_stmt* sqlStateMent = NULL;
    int rc = sqlite3_prepare_v2(pdb, sql, -1, &sqlStateMent, NULL);
    if (rc != SQLITE_OK) {
        LogPrintf("%s getAllfriend----error number:%d\n ", sql, rc);
        return false;
    }
    while (sqlite3_step(sqlStateMent) == SQLITE_ROW) {
        ImFriendStruct friendStruct;
        const unsigned char* oneVaddr = sqlite3_column_text(sqlStateMent, 0);
        std::string strVaddr((char*)oneVaddr);
        friendStruct.vaddr = strVaddr;
        const unsigned char* oneFriendAddr = sqlite3_column_text(sqlStateMent, 1);
        std::string strFriendAddr((char*)oneFriendAddr);
        friendStruct.friendAddr = strFriendAddr;
        const unsigned char* oneFriendName = sqlite3_column_text(sqlStateMent, 2);
        std::string strFriendName((char*)oneFriendName);
        friendStruct.friendName = strFriendName;
        const void* headPix = sqlite3_column_blob(sqlStateMent, 3);
        int len = sqlite3_column_bytes(sqlStateMent, 3);
        friendStruct.insertHeadPix((char*)headPix, len);
        const unsigned char* remarks = sqlite3_column_text(sqlStateMent, 4);
        std::string strRemarks((char*)remarks);
        friendStruct.remarks = strRemarks;
        const int blackList = sqlite3_column_int(sqlStateMent, 5);
        friendStruct.blackList = blackList;
        //LogPrintf("getAllFriend----%s---%s\n",oneVaddr, oneName);
        Friends.push_back(friendStruct);
    }
    return true;
}

bool CSqliteWrapper::findFriend(string vaddr)
{
    char* errMsg = 0;
    char sql[2000] = {0};
    sprintf(sql, "SELECT COUNT() from friendtable WHERE vaddr=\"%s\";", vaddr.c_str());
    //LogPrintf("%s\n", sql);
    sqlite3_stmt* sqlStateMent = NULL;
    int rc = sqlite3_prepare_v2(pdb, sql, -1, &sqlStateMent, NULL);
    if (rc != SQLITE_OK) {
        LogPrintf("%s findFriend----error number:%d\n ", sql, rc);
        return false;
    }
    if (sqlite3_step(sqlStateMent) == SQLITE_ROW) {
        const unsigned char* oneVaddr = sqlite3_column_text(sqlStateMent, 0);
        std::string strVaddr((char*)oneVaddr);
        int k = stringToInt(strVaddr);
        if (k > 0)
            return true;
    }
    return false;
}

bool CSqliteWrapper::insertBlack(string vaddr, string name)
{
    char* errMsg = 0;
    char sql[2000] = {0};
    sprintf(sql, "REPLACE INTO blacktable (vaddr, name) VALUES (\"%s\", \"%s\");", vaddr.c_str(), name.c_str());
    sqlite3_exec(pdb, sql, 0, 0, &errMsg);
    return true;
}
bool CSqliteWrapper::deleteBlack(string vaddr)
{
    char* errMsg = 0;
    char sql[2000] = {0};
    sprintf(sql, "DELETE FROM blacktable WHERE vaddr=\"%s\";", vaddr.c_str());
    sqlite3_exec(pdb, sql, 0, 0, &errMsg);
    return true;
}
bool CSqliteWrapper::getAllBlack(std::map<string, string>& mapBlack)
{
    char* errMsg = 0;
    char sql[2000] = {0};
    sprintf(sql, "SELECT vaddr,name from blacktable;");
    //LogPrintf("%s\n", sql);
    sqlite3_stmt* sqlStateMent = NULL;
    int rc = sqlite3_prepare_v2(pdb, sql, -1, &sqlStateMent, NULL);
    if (rc != SQLITE_OK) {
        LogPrintf("%s getAllBlack----error number:%d\n ", sql, rc);
        return false;
    }
    while (sqlite3_step(sqlStateMent) == SQLITE_ROW) {
        const unsigned char* oneVaddr = sqlite3_column_text(sqlStateMent, 0);
        std::string strVaddr((char*)oneVaddr);
        const unsigned char* oneName = sqlite3_column_text(sqlStateMent, 1);
        std::string strName((char*)oneName);
        //LogPrintf("getAllBlack----%s---%s\n",oneVaddr, oneName);
        mapBlack.insert(pair<string, string>(strVaddr, strName));
    }
    return true;
}
