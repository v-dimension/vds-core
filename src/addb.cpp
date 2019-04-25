// Copyright (c) 2017-2020 The Vds Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "addb.h"
#include "serialize.h"
#include "validation.h"
#include <boost/concept_check.hpp>

static const char AD_KING = 'K';
static const char AD_MSG = 'M';
static const char AD_KING_LAST = 'L';

using namespace std;
CAd g_AdKing;
CAd::CAd(uint256 txidIn, int blockHeightIn, CTxDestination addressIn, string admsgIn, CAmount adValueIn)
{
    txid = txidIn;
    blockHeight = blockHeightIn;
    address = addressIn;
    admsg = admsgIn;
    adValue = adValueIn;
}

CAdDB::CAdDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "ads", nCacheSize, fMemory, false /* Caution!!! here should not delete ad data*/)
{
    if (fWipe) {
        EraseAdKing();
        EraseAdKingLast();
    } else {
        if (Exists(AD_KING)) {
            uint256 txid;
            if (!Read(AD_KING, txid))
                g_AdKing.SetNull();
            if (!ReadAd(txid, g_AdKing))
                g_AdKing.SetNull();
        }
    }
}


bool CAdDB::WriteAd(const CAd& ad)
{
    LOCK(cs_ad);
    if (!Write(ad.txid, ad))
        return false;
    if (!Write(ad.blockHeight, ad))
        return false;
    if (ad.admsg != "")
        if (!WriteAdMsg(ad.txid, ad.admsg))
            return false;

    m_AdCache.WriteAd(ad);
    return true;
}

bool CAdDB::EraseAdKing()
{
    LOCK(cs_ad);
    if (!Exists(AD_KING)) {
        return false;
    } else {
        return Erase(AD_KING);
    }
    return true;
}

bool CAdDB::EraseAdKingLast()
{
    LOCK(cs_ad);
    if (!Exists(AD_KING_LAST)) {
        return false;
    } else {
        return Erase(AD_KING_LAST);
    }
    return true;
}

bool CAdDB::WriteAdKing(const uint256& adkingid)
{
    LOCK(cs_ad);
    if (!Exists(AD_KING)) {
        return Write(AD_KING, adkingid);
    } else {
        uint256 txidKingLast;
        if (!Read(AD_KING, txidKingLast))
            return false;

        CAd adKingLast;
        if (!Read(txidKingLast, adKingLast))
            return false;

        if (!Write(AD_KING, adkingid))
            return false;

        if (!Write(AD_KING_LAST, adKingLast.txid))
            return false;
    }

    m_AdCache.WriteAdKing(adkingid);
    return true;
}

bool CAdDB::ReadAd(const uint256& txid, CAd& ad)
{
    if (m_AdCache.ReadAd(txid, ad)) {
        return true;
    }

    LOCK(cs_ad);
    //db operate
    if (!Read(txid, ad))
        return false;
    if (ad.admsg == "")
        if (!ReadAdMsg(ad.txid, ad.admsg))
            return false;

    m_AdCache.WriteAd(ad);
    return true;
}

bool CAdDB::ReadAd(const int& blockHeight, CAd& ad)
{
    if (m_AdCache.ReadAd(blockHeight, ad)) {
        return true;
    }

    LOCK(cs_ad);
    //db operate
    if (!Read(blockHeight, ad))
        return false;

    if (ad.admsg == "")
        if (!ReadAdMsg(ad.txid, ad.admsg))
            return false;

    m_AdCache.WriteAd(ad);
    return true;
}


bool CAdDB::HaveAd(const uint256& txid)
{
    if (m_AdCache.HaveAd(txid)) {
        return true;
    }
    LOCK(cs_ad);

    return Exists(txid);
}

bool CAdDB::HaveAd(const int& blockHeight)
{
    if (m_AdCache.HaveAd(blockHeight)) {
        return true;
    }
    LOCK(cs_ad);
    return Exists(blockHeight);
}

bool CAdDB::GetAdID(const int& blockHeight, uint256& txid)
{
    if (m_AdCache.GetAdID(blockHeight, txid)) {
        return true;
    }

    LOCK(cs_ad);
    if (!HaveAd(blockHeight))
        return false;
    CAd ad;
    if (!Read(blockHeight, ad))
        return false;
    txid = ad.txid;
    return true;
}

bool CAdDB::WriteAdMsg(const uint256& hash, const string& msg)
{
    LOCK(cs_ad);
    m_AdCache.WriteAdMsg(hash, msg);
    return Write(std::make_pair(AD_MSG, hash), msg);
}

bool CAdDB::HaveAdMsg(const uint256& hash)
{
    if (m_AdCache.HaveAdMsg(hash)) {
        return true;
    }
    LOCK(cs_ad);
    return Exists(std::make_pair(AD_MSG, hash));
}

bool CAdDB::ReadAdMsg(const uint256& hash, string& msg)
{
    if (m_AdCache.ReadAdMsg(hash, msg)) {
        return true;
    }
    LOCK(cs_ad);
    return Read(std::make_pair(AD_MSG, hash), msg);
}

bool CAdDB::GetAdKing(CAd& ad)
{
    if (m_AdCache.GetAdKing(ad)) {
        return true;
    }

    LOCK(cs_ad);
    if (Exists(AD_KING)) {
        uint256 txid;
        if (!Read(AD_KING, txid))
            return false;
        return Read(txid, ad);
    } else {
        ad.SetNull();
        return false;
    }
    return false;
}

bool CAdDB::GetAdKingLast(CAd& ad)
{
    if (m_AdCache.GetAdKingLast(ad)) {
        return true;
    }

    LOCK(cs_ad);
    if (Exists(AD_KING_LAST)) {
        uint256 txid;
        if (!Read(AD_KING_LAST, txid))
            return false;
        return Read(txid, ad);
    } else {
        ad.SetNull();
        return false;
    }
    return false;
}

bool CAdDB::GetAdKingID(uint256& txid)
{
    if (m_AdCache.GetAdKingID(txid)) {
        return true;
    }
    LOCK(cs_ad);
    return Read(AD_KING, txid);
}

CAdCache::CAdCache()
{
    m_MapAdCacheHash.clear();
    m_MapAdCacheHeight.clear();
    m_MapAdMsgCache.clear();
    m_HashAdKing = uint256();
    m_HashAdKingLast = uint256();
}

bool CAdCache::WriteAd(const CAd& ad)
{
    LOCK(cs_cache);
    m_MapAdCacheHeight[ad.blockHeight] = ad;
    m_MapAdCacheHash[ad.txid] = ad;
    if (ad.admsg != "")
        m_MapAdMsgCache[ad.txid] = ad.admsg;
    return true;
}

bool CAdCache::ReadAd(const uint256& txid, CAd& ad)
{
    LOCK(cs_cache);
    if (!HaveAd(txid)) {
        return false;
    }
    ad = m_MapAdCacheHash[txid];

    if (ad.admsg == "") {
        if (!HaveAdMsg(txid)) {
            return false;
        }
        ad.admsg = m_MapAdMsgCache[txid];
    }
    return true;
}

bool CAdCache::ReadAd(const int& blockHeight, CAd& ad)
{
    LOCK(cs_cache);
    if (!HaveAd(blockHeight)) {
        return false;
    }
    ad = m_MapAdCacheHeight[blockHeight];

    if (ad.admsg == "") {
        if (!HaveAdMsg(ad.txid)) {
            return false;
        }
        ad.admsg = m_MapAdMsgCache[ad.txid];
    }
    return true;
}

bool CAdCache::HaveAd(const uint256& txid)
{
    LOCK(cs_cache);
    std::map<uint256, CAd>::const_iterator itorHash = m_MapAdCacheHash.find(txid);
    if (itorHash == m_MapAdCacheHash.end()) {
        return false;
    } else {
        CAd adCache = m_MapAdCacheHash[txid];
        if (adCache.admsg == "") {
            return false;
        }
    }
    return true;
}

bool CAdCache::HaveAd(const int& blockHeight)
{
    LOCK(cs_cache);
    std::map<int, CAd>::const_iterator itorHeight = m_MapAdCacheHeight.find(blockHeight);
    if (itorHeight == m_MapAdCacheHeight.end()) {
        return false;
    } else {
        CAd adCache = m_MapAdCacheHeight[blockHeight];
        if (adCache.admsg == "") {
            return false;
        }
    }
    return true;
}

bool CAdCache::GetAdID(const int& blockHeight, uint256& txid)
{
    LOCK(cs_cache);
    if (!HaveAd(blockHeight))
        return false;
    CAd ad;
    if (!ReadAd(blockHeight, ad))
        return false;
    txid = ad.txid;
    return true;
}

bool CAdCache::WriteAdMsg(const uint256& hash, const string& msg)
{
    LOCK(cs_cache);
    m_MapAdMsgCache[hash] = msg;
    return true;
}

bool CAdCache::HaveAdMsg(const uint256& hash)
{
    LOCK(cs_cache);
    std::map<uint256, std::string>::const_iterator itorMsg = m_MapAdMsgCache.find(hash);
    if (itorMsg == m_MapAdMsgCache.end()) {
        return false;
    }
    return true;
}

bool CAdCache::ReadAdMsg(const uint256& hash, string& msg)
{
    LOCK(cs_cache);
    if (!HaveAdMsg(hash)) {
        return false;
    }
    msg = m_MapAdMsgCache[hash];
    return true;
}

bool CAdCache::WriteAdKing(const uint256& adkingid)
{
    m_HashAdKingLast = m_HashAdKing;
    m_HashAdKing = adkingid;
    return true;
}

bool CAdCache::GetAdKing(CAd& ad)
{
    return ReadAd(m_HashAdKing, ad);
}

bool CAdCache::GetAdKingLast(CAd& ad)
{
    return ReadAd(m_HashAdKingLast, ad);
}

bool CAdCache::GetAdKingID(uint256& txid)
{
    if (uint256() == m_HashAdKing) {
        return false;
    }
    txid = m_HashAdKing;
    return true;
}

bool CAdCache::EraseAd(const uint256& txid)
{
    LOCK(cs_cache);
    std::map<uint256, CAd>::const_iterator itorHash = m_MapAdCacheHash.find(txid);
    if (itorHash != m_MapAdCacheHash.end()) {
        m_MapAdCacheHash.erase(itorHash);
    }
}
