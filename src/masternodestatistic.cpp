// Copyright (c) 2014-2019 The vds Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "masternodestatistic.h"
#include "primitives/transaction.h"
#include "chain.h"
#include "masternode-payments.h"
#include "masternodeconfig.h"
#include "masternodeman.h"
#include "primitives/transaction.h"

const unsigned char DB_MASTERNODE_STATISTIC = 'm';

CMasternodeStatisticDB* pMasternodeStatisticDb = NULL;
CMasternodeStatisticDB::CMasternodeStatisticDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "masternodestatistic", nCacheSize, fMemory, fWipe)
{

}


bool CMasternodeStatisticDB::connectBlock(const CBlock& block, const CBlockIndex* pindex)
{
    assert(pindex != nullptr);
    //Network Wide Statistic
    CDBBatch batch(*this);
    uint256 blockHash = block.GetHash();
    if (HaveMasternodeStatistic(blockHash)) {
        return false;
    }
    CAmount nMasternodePaid = 0;
    if (!getBlockMasternodePaid(block, nMasternodePaid))
        return true;

    batch.Write(blockHash, nMasternodePaid);
    CAmount nAmountTotal = 0;
    this->ReadMasternodeTotalReward(nAmountTotal);
    {
        nAmountTotal += nMasternodePaid;
        std::string strTotalAmount = "totalamount";
        batch.Write(strTotalAmount, nAmountTotal);
    }

    int nNumTotal = 0;
    this->ReadNumMasternodeGetReward(nNumTotal);
    {
        nNumTotal += 1;
        std::string strTotalNumber = "totalnumber";
        batch.Write(strTotalNumber, nNumTotal);
    }


    //Mine Statistic
    CScript mnpayee;
    if (!isMineBlockMasternode(block, pindex, mnpayee)) {
        LOCK(cs_db);
        if (!WriteBatch(batch)) {
            return false;
        }
        NotifyMasternodeNetworkWideChange();
        NotifyMasternodeStatisticChange();
        return true;
    } else {
        CAmount nValueReward = 0;
        CAmount nValueIssue = 0;
        CAmount nValueAd = 0;
        CAmount nValueFee = 0;
        CAmount nValueCommunity = 0;
        if (!classifyMasternodeReward(block, pindex, mnpayee, nValueReward, nValueIssue, nValueAd, nValueFee, nValueCommunity)) {
            LOCK(cs_db);
            if (!WriteBatch(batch)) {
                return false;
            }
            NotifyMasternodeNetworkWideChange();
            NotifyMasternodeStatisticChange();
            return true;
        }
        tagMyMasternodeStatistic myMasternodeStatistic;
        if (!ReadMyMasternodeStatistic(myMasternodeStatistic)) {
            myMasternodeStatistic.nValueReward = nValueReward;
            myMasternodeStatistic.nValueIssue = nValueIssue;
            myMasternodeStatistic.nValueAd = nValueAd;
            myMasternodeStatistic.nValueFee = nValueFee;
            myMasternodeStatistic.nValueCommunity = nValueCommunity;
            std::string strMyMasternodeStatistic = "mymasternodestatistic";
            batch.Write(strMyMasternodeStatistic, myMasternodeStatistic);
        } else {
            myMasternodeStatistic.nValueReward += nValueReward;
            myMasternodeStatistic.nValueIssue += nValueIssue;
            myMasternodeStatistic.nValueAd += nValueAd;
            myMasternodeStatistic.nValueFee += nValueFee;
            myMasternodeStatistic.nValueCommunity += nValueCommunity;
            std::string strMyMasternodeStatistic = "mymasternodestatistic";
            batch.Write(strMyMasternodeStatistic, myMasternodeStatistic);
        }
    }
    {
        LOCK(cs_db);
        if (!WriteBatch(batch)) {
            return false;
        }
        NotifyMasternodeNetworkWideChange();
        NotifyMasternodeStatisticChange();
        return true;
    }
    return true;
}

bool CMasternodeStatisticDB::disconnectBlock(const CBlock& block, const CBlockIndex* pindex)
{
    assert(pindex != nullptr);
    uint256 blockHash = block.GetHash();
    if (HaveMasternodeStatistic(blockHash)) {
        CAmount nMasternodePaid = 0;
        ReadMasternodeStatistic(blockHash, nMasternodePaid);
        EraseMasternodeStatistic(blockHash);
        CAmount nAmountTotal = 0;
        this->ReadMasternodeTotalReward(nAmountTotal);
        {
            nAmountTotal -= nMasternodePaid;
            if (!this->WriteMasternodeTotalReward(nAmountTotal))
                return false;
        }

        int nNumTotal = 0;
        this->ReadNumMasternodeGetReward(nNumTotal);
        {
            nNumTotal -= 1;
            if (!this->WriteNumMasternodeGetReward(nNumTotal))
                return false;
        }

        //Mine Statistic
        CScript mnpayee;
        if (!isMineBlockMasternode(block, pindex, mnpayee)) {
            return true;
        } else {
            CAmount nValueReward = 0;
            CAmount nValueIssue = 0;
            CAmount nValueAd = 0;
            CAmount nValueFee = 0;
            CAmount nValueCommunity = 0;
            if (!classifyMasternodeReward(block, pindex, mnpayee, nValueReward, nValueIssue, nValueAd, nValueFee, nValueCommunity)) {
                return false;
            }
            tagMyMasternodeStatistic myMasternodeStatistic;
            if (!ReadMyMasternodeStatistic(myMasternodeStatistic)) {
                return false;
            } else {
                myMasternodeStatistic.nValueReward -= nValueReward;
                myMasternodeStatistic.nValueIssue -= nValueIssue;
                myMasternodeStatistic.nValueAd -= nValueAd;
                myMasternodeStatistic.nValueFee -= nValueFee;
                myMasternodeStatistic.nValueCommunity -= nValueCommunity;
                bool isInValid = (myMasternodeStatistic.nValueReward < 0) ||
                                 (myMasternodeStatistic.nValueIssue < 0) ||
                                 (myMasternodeStatistic.nValueAd < 0) ||
                                 (myMasternodeStatistic.nValueFee < 0) ||
                                 (myMasternodeStatistic.nValueCommunity < 0) ;
                if (isInValid) {
                    return false;
                }
                if (!this->WriteMyMasternodeStatistic(myMasternodeStatistic)) {
                    return false;
                }
            }
        }
    }
    return true;
}

bool CMasternodeStatisticDB::getAmountMean(CAmount& nAmountMean)
{
    CAmount nTotalAmount = 0;
    int nTotalNum = 0;
    if (!this->ReadMasternodeTotalReward(nTotalAmount)) {
        return false;
    }
    if (!this->ReadNumMasternodeGetReward(nTotalNum)) {
        return false;
    }
    if (0 == nTotalNum) {
        nAmountMean = 0;
    } else {
        nAmountMean = nTotalAmount / nTotalNum;
    }
    return true;
}

bool CMasternodeStatisticDB::getAmountMeanDaily(CAmount& nAmountMean)
{
    int nHeightCurrent = chainActive.Height();
    int nNumBlockDaily = Params().GetConsensus().nBlockCountPerDay;
    if (nHeightCurrent < nNumBlockDaily) {
        nNumBlockDaily = nHeightCurrent;
    }
    int nDailyNum = 0;
    CAmount nAmountDaily = 0;
    for (int nHeight = nHeightCurrent; nHeight > (nHeightCurrent - nNumBlockDaily); nHeight--) {
        uint256 blockHash = chainActive[nHeight]->GetBlockHash();
        CAmount nAmountBlock = 0;
        if (ReadMasternodeStatistic(blockHash, nAmountBlock)) {
            nAmountDaily += nAmountBlock;
            nDailyNum++;
        }
    }
    if (0 == nDailyNum) {
        return false;
    } else {
        nAmountMean = nAmountDaily / nDailyNum;
    }
    return true;
}

bool CMasternodeStatisticDB::getMyMasternodeStatistic(CAmount& nValueReward, CAmount& nValueIssue, CAmount& nValueAd, CAmount& nValueFee, CAmount& nValueCommunity)
{
    tagMyMasternodeStatistic myMasternodeStatistic;
    if (!ReadMyMasternodeStatistic(myMasternodeStatistic)) {
        return false;
    }
    nValueReward      = myMasternodeStatistic.nValueReward;
    nValueIssue       = myMasternodeStatistic.nValueIssue;
    nValueAd          = myMasternodeStatistic.nValueAd;
    nValueFee         = myMasternodeStatistic.nValueFee;
    nValueCommunity   = myMasternodeStatistic.nValueCommunity;
    return true;
}

bool CMasternodeStatisticDB::WriteMasternodeStatistic(const uint256& blockhash, const CAmount& nValueToMasternode)
{
    LOCK(cs_db);
    return Write(std::make_pair(DB_MASTERNODE_STATISTIC, blockhash), nValueToMasternode);
}

bool CMasternodeStatisticDB::EraseMasternodeStatistic(const uint256& blockhash)
{
    LOCK(cs_db);
    return Erase(std::make_pair(DB_MASTERNODE_STATISTIC, blockhash));
}

bool CMasternodeStatisticDB::HaveMasternodeStatistic(const uint256& blockhash)
{
    LOCK(cs_db);
    return Exists(std::make_pair(DB_MASTERNODE_STATISTIC, blockhash));
}

bool CMasternodeStatisticDB::ReadMasternodeStatistic(const uint256& blockhash, CAmount& nValueToMasternode)
{
    LOCK(cs_db);
    return Read(std::make_pair(DB_MASTERNODE_STATISTIC, blockhash), nValueToMasternode);
}

bool CMasternodeStatisticDB::WriteMasternodeTotalReward(const CAmount& nAmountTotal)
{
    LOCK(cs_db);
    std::string strTotalAmount = "totalamount";
    return Write(strTotalAmount, nAmountTotal);
}

bool CMasternodeStatisticDB::ReadMasternodeTotalReward(CAmount& nAmountTotal)
{
    LOCK(cs_db);
    std::string strTotalAmount = "totalamount";
    return Read(strTotalAmount, nAmountTotal);
}

bool CMasternodeStatisticDB::WriteNumMasternodeGetReward(const int& nNum)
{
    LOCK(cs_db);
    std::string strTotalNumbert = "totalnumber";
    return Write(strTotalNumbert, nNum);
}

bool CMasternodeStatisticDB::ReadNumMasternodeGetReward(int& nNum)
{
    LOCK(cs_db);
    std::string strTotalNumbert = "totalnumber";
    return Read(strTotalNumbert, nNum);
}

bool CMasternodeStatisticDB::WriteMyMasternodeStatistic(const tagMyMasternodeStatistic& _MyMasternodeStatistic)
{
    LOCK(cs_db);
    std::string strMyMasternodeStatistic = "mymasternodestatistic";
    if (Write(strMyMasternodeStatistic, _MyMasternodeStatistic)) {
        NotifyMasternodeStatisticChange();
        return true;
    } else {
        return false;
    }
}

bool CMasternodeStatisticDB::ReadMyMasternodeStatistic(tagMyMasternodeStatistic& _MyMasternodeStatistic)
{
    LOCK(cs_db);
    std::string strMyMasternodeStatistic = "mymasternodestatistic";
    return Read(strMyMasternodeStatistic, _MyMasternodeStatistic);
}

bool CMasternodeStatisticDB::getBlockMasternodePaid(const CBlock& block, CAmount& nMasternodePaid)
{
    nMasternodePaid = 0;
    for (const auto tx : block.vtx) {
        if (tx->IsCoinBase()) {
            for (const auto out : tx->vout) {
                if (out.nFlag == CTxOut::MASTERNODE) {
                    nMasternodePaid += out.nValue;
                    return true;
                }
            }
        }
    }
    return false;
}

bool CMasternodeStatisticDB::classifyMasternodeReward(const CBlock& block, const CBlockIndex* pindex, const CScript& payeeMasternode, CAmount& nValueMasternodeAll, CAmount& nValueIssue, CAmount& nValueAd, CAmount& nValueFee, CAmount& nValueCommunity)
{
    if (!pindex) {
        return false;
    }
    CScript mnscript;
    for (const auto& out : block.vtx[0]->vout) {
        if (out.nFlag == CTxOut::MASTERNODE) {
            mnscript = out.scriptPubKey;
            break;
        }
    }

    if (payeeMasternode != mnscript) {
        return false;
    }

    nValueMasternodeAll = 0;
    nValueIssue = 0;
    nValueFee = 0;
    nValueAd = 0;
    nValueCommunity = 0;
    CCoinsViewCache view(pcoinsTip);
    //Reward Issue
    CAmount nBlockReward = GetBlockClueSubsidy(pindex->nHeight, Params().GetConsensus());
    nValueIssue = (nBlockReward - nBlockReward / 2);

    //Handle Fee and Ad value
    for (const auto& ptx : block.vtx) {
        if (ptx->IsCoinBase()) {
            for (const auto& out : ptx->vout) {
                if (out.nFlag == CTxOut::REFUND) {
                    nValueFee -= out.nValue;
                }

                if (out.nFlag == CTxOut::MASTERNODE) {
                    nValueMasternodeAll = out.nValue;
                }
            }
            continue;
        }
        if (ptx->IsCoinClue()) {
            // Clue Transaction total 0.5 Fee, 0.1 to miner, 0.1 to masternode, 0.3 to tandia
            nValueFee += CLUE_COST_MASTER_NODE;
        } else {
            if (ptx->nFlag == CTransaction::BID_TX) {
                for (const auto& out : ptx->vout) {
                    if (out.nFlag == CTxOut::BID) {
                        nValueAd += out.nValue;
                    }
                }
            }
            nValueFee += (view.GetValueIn(*ptx) - ptx->GetValueOut());
            for (const auto& out : ptx->vout) {
                if (out.scriptPubKey == feeAddress) {
                    nValueCommunity += out.nValue - (out.nValue / 2);
                }
            }
        }
    }
    return true;
}

bool CMasternodeStatisticDB::isMineBlockMasternode(const CBlock& block, const CBlockIndex* pindex, CScript& mnpayee)
{
    if (!getMasterNodePayee(mnpayee)) {
        return false;
    }

    CTransactionRef txCoinBase = block.vtx[0];
    for (CTxOut txOut : txCoinBase->vout) {
        if (txOut.nFlag == CTxOut::MASTERNODE) {
            if (txOut.scriptPubKey == mnpayee) {
                return true;
            } else {
                return false;
            }
        }
    }
    return true;
}

bool CMasternodeStatisticDB::getMasterNodePayee(CScript& masternodePayee)
{
    masternode_info_t infoMn;
    for (const auto& mne : masternodeConfig.getEntries()) {
        int32_t nOutputIndex = 0;
        if (!ParseInt32(mne.getOutputIndex(), &nOutputIndex)) {
            continue;
        }
        COutPoint outpoint(uint256S(mne.getTxHash()), nOutputIndex);
        bool fFound = mnodeman.GetMasternodeInfo(outpoint, infoMn);
        if (fFound) {
            break;
        }
    }
    if (infoMn.pubKeyCollateralAddress == CPubKey()) {
        return false;
    }
    masternodePayee = GetScriptForDestination(infoMn.pubKeyCollateralAddress.GetID());
    return true;
}
