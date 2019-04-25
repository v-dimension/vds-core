// Copyright (c) 2014-2019 The vds Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MASTERNODESTATISTIC_H
#define MASTERNODESTATISTIC_H
#include "dbwrapper.h"
#include "primitives/block.h"
#include "chain.h"
#include "sync.h"
struct tagMyMasternodeStatistic {
    CAmount nValueReward;
    CAmount nValueIssue;
    CAmount nValueAd;
    CAmount nValueFee;
    CAmount nValueCommunity;
    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nValueReward);
        READWRITE(nValueIssue);
        READWRITE(nValueAd);
        READWRITE(nValueFee);
        READWRITE(nValueCommunity);
    }
};

class CMasternodeStatisticDB : public CDBWrapper
{
public:
    CMasternodeStatisticDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
    bool connectBlock(const CBlock& block, const CBlockIndex* pindex);
    bool disconnectBlock(const CBlock& block, const CBlockIndex* pindex);
    bool getAmountMean(CAmount& nAmountMean);
    bool getAmountMeanDaily(CAmount& nAmountMean);
    bool getMyMasternodeStatistic(CAmount& nValueReward, CAmount& nValueIssue, CAmount& nValueAd, CAmount& nValueFee, CAmount& nValueCommunity);
public:
    bool WriteMasternodeStatistic(const uint256& blockhash, const CAmount& nValueToMasternode);
    bool EraseMasternodeStatistic(const uint256& blockhash);
    bool HaveMasternodeStatistic(const uint256& blockhash);
    bool ReadMasternodeStatistic(const uint256& blockhash, CAmount& nValueToMasternode);
    bool WriteMasternodeTotalReward(const CAmount& nAmountTotal);
    bool ReadMasternodeTotalReward(CAmount& nAmountTotal);
    bool WriteNumMasternodeGetReward(const int& nNum);
    bool ReadNumMasternodeGetReward(int& nNum);

    bool WriteMyMasternodeStatistic(const tagMyMasternodeStatistic& _MyMasternodeStatistic);
    bool ReadMyMasternodeStatistic(tagMyMasternodeStatistic& _MyMasternodeStatistic);
    boost::signals2::signal<void ()> NotifyMasternodeStatisticChange;
    boost::signals2::signal<void ()> NotifyMasternodeNetworkWideChange;
private:
    bool getBlockMasternodePaid(const CBlock& block, CAmount& nMasternodePaid);
    bool classifyMasternodeReward(const CBlock& block, const CBlockIndex* pindex, const CScript& payeeMasternode, CAmount& nValueMasternodeAll, CAmount& nValueIssue, CAmount& nValueAd, CAmount& nValueFee, CAmount& nValueCommunity);
    bool isMineBlockMasternode(const CBlock& block, const CBlockIndex* pindex, CScript& mnpayee);
    bool getMasterNodePayee(CScript& masternodePayee);
private:
    CCriticalSection cs_db;
};

extern CMasternodeStatisticDB* pMasternodeStatisticDb;

#endif // MASTERNODESTATISTIC_H
