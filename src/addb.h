// Copyright (c) 2017-2020 The Vds Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VDS_CADDB_H
#define VDS_CADDB_H

#include "dbwrapper.h"
#include "base58.h"
#include "uint256.h"
#include <boost/multiprecision/cpp_int.hpp>
#include "sync.h"
struct CAd;
extern CAd g_AdKing;
struct CAd {
    uint256 txid;
    int blockHeight;
    CTxDestination address;
    std::string admsg;
    CAmount adValue;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(txid);
        READWRITE(blockHeight);
        READWRITE(address);
        READWRITE(admsg);
        READWRITE(adValue);
    }

    CAd(uint256 txidIn, int blockHeightIn, CTxDestination addressIn, std::string admsgIn, CAmount adValueIn);

    CAd()
    {
        SetNull();
    }

    void SetNull()
    {
        txid = uint256();
        blockHeight = -1;
        address = CNoDestination();
        admsg = "";
        adValue = 0;
    }
};

class CAdCache
{
public:
    CAdCache();
public:
    bool WriteAd(const CAd& ad);
    bool ReadAd(const uint256& txid, CAd& ad);
    bool ReadAd(const int& blockHeight, CAd& ad);
    bool HaveAd(const uint256& txid);
    bool HaveAd(const int& blockHeight);
    bool GetAdID(const int& blockHeight, uint256& txid);
    bool WriteAdMsg(const uint256& hash, const std::string& msg);
    bool HaveAdMsg(const uint256& hash);
    bool ReadAdMsg(const uint256& hash, std::string& msg);
    bool WriteAdKing(const uint256& adkingid);
    bool GetAdKing(CAd& ad);
    bool GetAdKingLast(CAd& ad);
    bool GetAdKingID(uint256& txid);
    bool EraseAd(const uint256& txid);
private:
    std::map<uint256, CAd> m_MapAdCacheHash;
    std::map<int, CAd> m_MapAdCacheHeight;
    std::map<uint256, std::string> m_MapAdMsgCache;
    uint256 m_HashAdKing;
    uint256 m_HashAdKingLast;
    CCriticalSection cs_cache;
};

class CAdDB : public CDBWrapper
{
public:
    CAdDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

private:
    CAdDB(const CAdDB&);
    CCriticalSection cs_ad;

public:
    bool WriteAd(const CAd& ad);
    bool ReadAd(const uint256& txid, CAd& ad);
    bool ReadAd(const int& blockHeight, CAd& ad);
    bool HaveAd(const uint256& txid);
    bool HaveAd(const int& blockHeight);
    bool GetAdID(const int& blockHeight, uint256& txid);
    bool WriteAdMsg(const uint256& hash, const std::string& msg);
    bool HaveAdMsg(const uint256& hash);
    bool ReadAdMsg(const uint256& hash, std::string& msg);
    bool WriteAdKing(const uint256& adkingid);
    bool GetAdKing(CAd& ad);
    bool GetAdKingLast(CAd& ad);
    bool GetAdKingID(uint256& txid);
    bool EraseAdKing();
    bool EraseAdKingLast();
private:
    CAdCache m_AdCache;
};



#endif // VDS_CADDB_H
