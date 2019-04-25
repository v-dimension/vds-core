// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validation.h"

#include "sodium.h"

#include "addrman.h"
#include "alert.h"
#include "arith_uint256.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "checkqueue.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "clue.h"
#include "deprecation.h"
#include "fs.h"
#include "init.h"
#include "merkleblock.h"
#include "net.h"
#include "net_processing.h"
#include "policy/policy.h"
#include "pow.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "undo.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"
#include "wallet/asyncrpcoperation_sendmany.h"
#include "script/interpreter.h"
#include "tandiadb.h"
#include <key_io.h>

#include "masternode-payments.h"
#include "masternode-sync.h"
#include "masternodeman.h"

#include <sstream>

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/math/distributions/poisson.hpp>
#include <boost/thread.hpp>
#include <boost/static_assert.hpp>

#include "librustzcash.h"

using namespace std;

#if defined(NDEBUG)
#error "Vds cannot be compiled without assertions."
#endif

#define MICRO 0.000001
#define MILLI 0.001

/**
 * Global state
 */
////////////////////////////// qtum
#include <iostream>
#include <bitset>
#include "pubkey.h"
#include <univalue.h>

std::unique_ptr<QtumState> globalState;
std::shared_ptr<dev::eth::SealEngineFace> globalSealEngine;
bool fRecordLogOpcodes = true; // false as default
bool fIsVMlogFile = false;
bool fGettingValuesDGP = false;
//////////////////////////////

CCriticalSection cs_main;

BlockMap mapBlockIndex;
CChain chainActive;
CBlockIndex* pindexBestHeader = nullptr;
CWaitableCriticalSection csBestBlock;
CConditionVariable cvBlockChange;
int nScriptCheckThreads = 0;
bool fExperimentalMode = false;
bool fImporting = false;
bool fReindex = false;
bool fTxIndex = true;
bool fLogEvents = true; // false as default
bool fAddressIndex = true; // false as default
bool fHavePruned = false;
bool fPruneMode = false;
bool fIsBareMultisigStd = true;
bool fCheckBlockIndex = false;
bool fCheckpointsEnabled = true;
bool fCoinbaseEnforcedProtectionEnabled = true;
size_t nCoinCacheUsage = 5000 * 300;
uint64_t nPruneTarget = 0;
bool fAlerts = DEFAULT_ALERTS;

CCoinsViewDB* pcoinsdbview = nullptr;
CClueViewDB* pcluedbview = nullptr;

/** Fees smaller than this (in satoshi) are considered zero fee (for relaying and mining) */
CFeeRate minRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE);

CBlockPolicyEstimator feeEstimator;
CTxMemPool mempool(&feeEstimator);
CClueViewMemPool cluepool;
std::atomic_bool g_is_mempool_loaded{false};

struct COrphanTx {
    CTransaction tx;
    NodeId fromPeer;
};

map<uint256, int64_t> mapRejectedBlocks GUARDED_BY(cs_main);
void EraseOrphansFor(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Returns true if there are nRequired or more blocks of minVersion or above
 * in the last Consensus::Params::nMajorityWindow blocks, starting at pstart and going backwards.
 */
static bool IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned nRequired, const Consensus::Params& consensusParams);
static void CheckBlockIndex(const Consensus::Params& consensusParams);

/** Constant stuff for coinbase transactions we create: */
CScript COINBASE_FLAGS;

const string strMessageMagic = "Vds Signed Message:\n";

// Internal stuff
namespace
{

struct CBlockIndexWorkComparator {

    bool operator()(CBlockIndex* pa, CBlockIndex* pb) const
    {
        // First sort by most total work, ...
        if (pa->nChainWork > pb->nChainWork) return false;
        if (pa->nChainWork < pb->nChainWork) return true;

        // ... then by earliest time received, ...
        if (pa->nSequenceId < pb->nSequenceId) return false;
        if (pa->nSequenceId > pb->nSequenceId) return true;

        // Use pointer address as tie breaker (should only happen with blocks
        // loaded from disk, as those all have id 0).
        if (pa < pb) return false;
        if (pa > pb) return true;

        // Identical blocks.
        return false;
    }
};

CBlockIndex* pindexBestInvalid;

/**
 * The set of all CBlockIndex entries with BLOCK_VALID_TRANSACTIONS (for itself and all ancestors) and
 * as good as our current tip or better. Entries may be failed, though, and pruning nodes may be
 * missing the data for the block.
 */
set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexCandidates;
/** Number of nodes with fSyncStarted. */
int nSyncStarted = 0;
/** All pairs A->B, where A (or one if its ancestors) misses transactions, but B has transactions.
 * Pruned nodes may have entries where B is missing data.
 */
multimap<CBlockIndex*, CBlockIndex*> mapBlocksUnlinked;

CCriticalSection cs_LastBlockFile;
std::vector<CBlockFileInfo> vinfoBlockFile;
int nLastBlockFile = 0;
/** Global flag to indicate we should check to see if there are
 *  block/undo files that should be deleted.  Set on startup
 *  or if we allocate more file space when we're in prune mode
 */
bool fCheckForPruning = false;

/**
 * Every received block is assigned a unique and increasing identifier, so we
 * know which one to give priority in case of a fork.
 */
CCriticalSection cs_nBlockSequenceId;
/** Blocks loaded from disk are assigned id 0, so start the counter at 1. */
uint32_t nBlockSequenceId = 1;

/** Dirty block index entries. */
set<CBlockIndex*> setDirtyBlockIndex;

/** Dirty block file entries. */
set<int> setDirtyFileInfo;
} // anon namespace

int GetAdHeight(int nBlockHeight, int nIndexPeroidBidLock)
{
    if (nBlockHeight == 0) return 0;
    if ((nIndexPeroidBidLock < 0) || (nIndexPeroidBidLock > 23)) {
        return 0;
    }
    int nHeight = nBlockHeight - nBlockHeight % Params().GetConsensus().nBidPeriod + Params().GetConsensus().nBidPeriod * (nIndexPeroidBidLock + 1);
    return nHeight;
}

bool CheckIndexBidLockTimePeroid(const int nBlockHeight, const int& nHeightCheck)
{
    int nBidPeroid = Params().GetConsensus().nBidPeriod;
    int nDiffHeight = nBlockHeight - GetAdHeight(nHeightCheck - 1);

    if (nDiffHeight < 0) {
        LogPrint("bid", "CheckIndexBidLockTimePeroid: nDiffHeight < 0\n");
        return false;
    }

    if ((nDiffHeight % nBidPeroid) != 0) {
        LogPrint("bid", "CheckIndexBidLockTimePeroid: (nDiffHeight % nBidPeroid) != 0\n");
        return false;
    }
    int nIndexPeroidBidLock = nDiffHeight / nBidPeroid;

    if ((nIndexPeroidBidLock < 0) || (nIndexPeroidBidLock > 23)) {
        LogPrint("bid", "CheckIndexBidLockTimePeroid: nIndexPeroidBidLock !in [0, 23]\n");
        return false;
    }
    return true;
}

const double CLUE_AWARD_WEIGHT[] = {
    100.0f,
    61.8f,
    38.1920f,
    23.6029f,
    14.5865f,
    9.0148f,
    5.5707f,
    3.4423f,
    2.1276f,
    1.3142f,
    0.8124f,
    0.5021f
};

double ClueAwardWeight(uint32_t level)
{
    if (level >= Params().GetConsensus().nClueChildrenDepth)
        return 0.0f;

    return CLUE_AWARD_WEIGHT[level];
}

bool CheckTxBid(const CTransaction& tx, const int& nHeightCheck, std::string& strError)
{
    assert(tx.nFlag == CTransaction::BID_TX);

    if (!CheckIndexBidLockTimePeroid(tx.nLockTime, nHeightCheck)) {
        strError = strprintf("bid locktime check failed.");
        return false;
    }
    return true;

}

bool UpdateAdKing(const CAd& ad)
{
    if (ad.adValue > g_AdKing.adValue) {
        g_AdKing = ad;
        paddb->WriteAdKing(ad.txid);
        return true;
    }
    return false;
}

bool UpdateAdKing()
{
    for (int nHeight = 0; nHeight < chainActive.Height() - Params().GetConsensus().nBidPeriod;) {
        if (paddb->HaveAd(nHeight)) {
            CAd adRead;
            paddb->ReadAd(nHeight, adRead);
            UpdateAdKing(adRead);
        }
        nHeight = GetAdHeight(nHeight + 1);
    }
}

bool ValidateAd(const CAd& ad)
{
    CTransactionRef tx;
    uint256 blockHash;
    if (!GetTransaction(ad.txid, tx, Params().GetConsensus(), blockHash, true))
        return false;
    CAmount nAdValue = 0;
    for (const CTxOut& out : tx->vout) {
        if (out.nFlag == CTxOut::BID) {
            nAdValue = out.nValue;
            if (Hash(ad.admsg.begin(), ad.admsg.end()) != out.dataHash) {
                LogPrint("ad", "bad datahash Data: %s, Hash: %s(%s)\n", ad.admsg, out.dataHash.GetHex(), Hash(ad.admsg.begin(), ad.admsg.end()).GetHex());
                return false;
            }
            break;
        }
    }
    if (nAdValue != ad.adValue)
        return false;
    return true;
}

bool GetAdValueOut(uint256 txBidHash, CAmount& valueAd)
{
    CTransactionRef tx;
    uint256 blockHash;
    if (!GetTransaction(txBidHash, tx, Params().GetConsensus(), blockHash, true))
        return false;
    if (tx->nFlag != CTransaction::BID_TX)
        return false;

    for (const CTxOut& out : tx->vout) {
        if (out.nFlag == CTxOut::BID) {
            valueAd = out.nValue;
            break;
        }
    }
    return true;
}

bool GetUTXOCoin(const COutPoint& outpoint, Coin& coin)
{
    LOCK(cs_main);
    if (!pcoinsTip->GetCoin(outpoint, coin))
        return false;
    if (coin.IsSpent())
        return false;
    return true;
}

int GetUTXOHeight(const COutPoint& outpoint)
{
    // -1 means UTXO is yet unknown or already spent
    Coin coin;
    return GetUTXOCoin(outpoint, coin) ? coin.nHeight : -1;
}

int GetUTXOConfirmations(const COutPoint& outpoint)
{
    // -1 means UTXO is yet unknown or already spent
    LOCK(cs_main);
    int nPrevoutHeight = GetUTXOHeight(outpoint);
    return (nPrevoutHeight > -1 && chainActive.Tip()) ? chainActive.Height() - nPrevoutHeight + 1 : -1;
}

int GetTandiaPeriod(const int nHeight)
{
    Consensus::Params consensus = Params().GetConsensus();

    if (nHeight < consensus.nTandiaBallotStart ) {
        return -1;
    }

    return (nHeight - consensus.nTandiaBallotStart) / consensus.nTandiaBallotPeriod;
}

CScript GetTandiaScript(int nHeight, int nIndex)
{
    Consensus::Params consensus = Params().GetConsensus();
    if (GetTandiaPeriod(nHeight) == -1)
        return Params().GetFoundersRewardScriptAtIndex(nIndex);
    std::list<Propsal> lRanks;
    int nTindex = 0;
    do {
        nHeight -= consensus.nTandiaBallotPeriod;
        if (pTandia->GetTandiaAddresses(nHeight, lRanks)) {
            if (lRanks.size() == 0) {
                if (nHeight < (int)consensus.nTandiaBallotStart) break;
                continue;
            }
            nTindex = nIndex % lRanks.size();
            std::list<Propsal>::iterator it = lRanks.begin();
            std::advance(it, nTindex);
            return it->addrScript;
        }
    } while (nHeight >= (int)consensus.nTandiaBallotStart);
    return Params().GetFoundersRewardScriptAtIndex(nIndex);
}

void GetCoinBasePaidOut(const CBlockIndex* pindex, const CBlock& block, CAmount& toMiner, CAmount& toMasterNode, CAmount& toVibPool, bool& fPaidTandia, CAmount& toTandia, CAmount& toVibPay)
{
    assert(pindex != nullptr);
    toVibPool = 0;
    toMiner = 0;
    toMasterNode = 0;
    toTandia = 0;
    fPaidTandia = false;
    toVibPool = GetBlockSubsidy(pindex->nHeight, Params().GetConsensus()) - GetBlockClueSubsidy(pindex->nHeight, Params().GetConsensus());
    for (const auto tx : block.vtx) {
        if (tx->IsCoinBase()) {
            for (const auto out : tx->vout) {
                if (out.nFlag == CTxOut::MINE)
                    toMiner += out.nValue;
                else if (out.nFlag == CTxOut::MASTERNODE)
                    toMasterNode += out.nValue;
                else if (out.nFlag == CTxOut::TANDIA) {
                    toTandia += out.nValue;
                    fPaidTandia = true;
                } else if (out.nFlag == CTxOut::VIB) {
                    toVibPay += out.nValue;
                }
            }
        }

        if (tx->IsCoinClue()) {
            toVibPool += CLUE_TOTAL;
            for (const auto out : tx->vout) {
                if (out.nFlag == CTxOut::CLUE) {
                    toVibPool -= out.nValue;
                }
            }
            toVibPool -= CLUE_COST_FEE;
            continue;
        }
    }

    return;
}

bool CalChainRandom(const int& nRandomT, const uint32_t& nRange, uint32_t& nRandomCal, int nHeight)
{
    uint256 hashB = chainActive[nHeight - nRandomT]->GetBlockHash();
    uint256 hash2nd = Hash(hashB.begin(), hashB.end());
    uint64_t unHashCheap = hash2nd.GetCheapHash();
    nRandomCal = unHashCheap % nRange;
    return true;
}

void GetCoinBaseShouldPay(const CBlockIndex* pindex, const std::vector<CTransactionRef>& vtx, CAmount& nToMasterNodeAll, CAmount& toMiner, CAmount& toMasterNode, CAmount& toVibPool, bool& fPaidTandia, CAmount& toTandia)
{
    assert(pindex != nullptr); // pindex->pprev must exist
    const Consensus::Params& params = Params().GetConsensus();
    CAmount nBlockReward = GetBlockSubsidy((pindex->nHeight + 1), params);
    CAmount nBlockClueReward = GetBlockClueSubsidy((pindex->nHeight + 1), params);
    toMiner = nBlockClueReward / 2;
    toMasterNode = nBlockClueReward - toMiner;
    toVibPool = nBlockReward - nBlockClueReward;
    toTandia = pindex->nDebtTandia;
    fPaidTandia = false;
    nToMasterNodeAll = 0;

    CAmount nFees = 0;
    CCoinsViewCache view(pcoinsTip);
    CValidationState state;
    /**
      * Fees send to miner 35%, masternode 35%, tandia 30%. 7:7:6
      */
    for (const auto& ptx : vtx) {
        if (ptx->IsCoinBase()) {
            for (const auto& out : ptx->vout) {
                if (out.nFlag == CTxOut::REFUND) {
                    nFees -= out.nValue;
                }
            }
            continue;
        }
        if (ptx->IsCoinClue()) {
            // Clue Transaction total 0.5 Fee, 0.1 to miner, 0.1 to masternode, 0.3 to tandia
            CAmount clueAmount = 0;
            for (const auto& out : ptx->vout) {
                if (out.nFlag == CTxOut::CLUE)
                    clueAmount += out.nValue;
            }
            toMiner += CLUE_COST_MINER;
            toMasterNode += CLUE_COST_MASTER_NODE;
            toTandia += CLUE_COST_TANDIA;

            if (CLUE_TOTAL - clueAmount - CLUE_COST_FEE > 0) {
                toVibPool += CLUE_TOTAL - clueAmount - CLUE_COST_FEE;
            }
        } else {
            if (ptx->nFlag == CTransaction::BID_TX) {
                for (const auto& out : ptx->vout) {
                    if (out.nFlag == CTxOut::BID) {
                        nToMasterNodeAll += out.nValue;
                    }
                }
            }
            nFees += view.GetValueIn(*ptx) - ptx->GetValueOut();
            for (const auto& out : ptx->vout) {
                if (out.scriptPubKey == feeAddress) {
                    toTandia += out.nValue / 2;
                    nToMasterNodeAll += out.nValue - (out.nValue / 2);
                }
            }
        }

        UpdateCoins(*ptx, state, view, pindex->nHeight + 1);
    }

    toMiner += (nFees * 7 / 20);
    toMasterNode += (nFees * 7 / 20);

    toTandia += (nFees - (nFees * 7 / 20) - (nFees * 7 / 20));

    // pay tandia periodly
    if (pindex->nHeight + 1 - pindex->nHeightTandiaPaid >= params.nTandiaPayPeriod)
        fPaidTandia = (toTandia >= TANDIA_AMOUNT_LIMIT);

    // season ending should pay all debt
    if (pindex->nHeight + 2 == params.nTandiaBallotStart || (pindex->nHeight + 2) % params.nBlockCountOfWeek == 0)
        fPaidTandia = (toTandia > 0);
    return;
}

bool IsClueRoot(const CTxDestination& dest, const int nCurHeight)
{
    // check if this address has an utxo greater than 1BTC at height x;

    int nHeight = Params().GetBitcoinUTXOHeight();

    CClueViewCache clueview(pclueTip);

    if (nCurHeight > 0 && nCurHeight > Params().GetBitcoinRootEnd()) {
        CClue clue;
        if (!clueview.GetClue(dest, clue))
            return false;

        if (!IsBlockInMainChain(clue.txid, nHeight))
            return false;
        return (nHeight <= Params().GetBitcoinRootEnd());
    }

    std::vector<CUtxo> vTxOut;
    return GetUTXOAtHeight(dest, nHeight, vTxOut, 0.1 * COIN);
}

bool GetTransactionClue(const CTransaction& tx, const CCoinsViewCache& view, CClue& clue, std::map<CTxDestination, CRankItem>& vItem, bool& fRoot)
{
    fRoot = false;
    if (tx.nFlag != CTransaction::CLUE_TX)
        return false;

    CTxDestination clueaddress;
    CTxDestination parent;
    CTxDestination inviter;
    for (size_t i = 0; i < tx.vin.size(); i++) {
        const Coin& coin = view.AccessCoin(tx.vin[i].prevout);
        if (coin.IsSpent())
            return false;
        CTxDestination dest;
        if (!ExtractDestination(coin.out.scriptPubKey, dest))
            return false;
        if (i == 0) {
            clueaddress = dest;
        } else {
            if (dest != clueaddress) {
                return false;
            }
        }
    }

    bool fSameParent = true;
    int nClue = 0;
    for (size_t i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        if (out.nFlag != CTxOut::CLUE)
            continue;

        CTxDestination dest;
        CRankItem item;
        if (!ExtractDestination(out.scriptPubKey, dest))
            return false;

        if (nClue == 0) {
            parent = dest;
            inviter = dest;

            if (out.nValue != CLUE_COST_PARENT_TOP)
                fSameParent = false;
        } else {
            if (out.nValue == CLUE_COST_PARENT_TOP && !fSameParent)
                inviter = dest;
        }
        item.nValue = out.nValue;
        item.dWeight = ClueAwardWeight(nClue);
        vItem[dest] = item;
        nClue += 1;
    }

    if (!fSameParent && inviter == parent)
        return false;

    if (inviter == parent && nClue == 1)
        fRoot = true;
    clue.address = clueaddress;
    clue.inviter = inviter;
    clue.parent = parent;
    clue.txid = tx.GetHash();
    return true;
}

static void LimitMempoolSize(CTxMemPool& pool, size_t limit, unsigned long age)
{
    int expired = pool.Expire(GetTime() - age);
    if (expired != 0) {
        LogPrint("mempool", "Expired %i transactions from the memory pool\n", expired);
    }

    std::vector<COutPoint> vNoSpendsRemaining;
    pool.TrimToSize(limit, &vNoSpendsRemaining);
    for (const COutPoint& removed : vNoSpendsRemaining)
        pcoinsTip->Uncache(removed);
}

/* Make mempool consistent after a reorg, by re-adding or recursively erasing
 * disconnected block transactions from the mempool, and also removing any
 * other transactions from the mempool that are no longer valid given the new
 * tip/height.
 *
 * Note: we assume that disconnectpool only contains transactions that are NOT
 * confirmed in the current chain nor already in the mempool (otherwise,
 * in-mempool descendants of such transactions would be removed).
 *
 * Passing fAddToMempool=false will skip trying to add the transactions back,
 * and instead just erase from the mempool as needed.
 */

void UpdateMempoolForReorg(DisconnectedBlockTransactions& disconnectpool, bool fAddToMempool)
{
    AssertLockHeld(cs_main);
    std::vector<uint256> vHashUpdate;
    // disconnectpool's insertion_order index sorts the entries from
    // oldest to newest, but the oldest entry will be the last tx from the
    // latest mined block that was disconnected.
    // Iterate disconnectpool in reverse, so that we add transactions
    // back to the mempool starting with the earliest transaction that had
    // been previously seen in a block.
    auto it = disconnectpool.queuedTx.get<insertion_order>().rbegin();
    while (it != disconnectpool.queuedTx.get<insertion_order>().rend()) {
        // ignore validation errors in resurrected transactions
        CValidationState stateDummy;
        if (!fAddToMempool || (*it)->IsCoinBase() ||
                !AcceptToMemoryPool(mempool, stateDummy, *it, false, nullptr /* pfMissingInputs */,
                                    nullptr /* plTxnReplaced */, true /* bypass_limits */, false /* nAbsurdFee */)) {
            // If the transaction doesn't make it in to the mempool, remove any
            // transactions that depend on it (which would now be orphans).
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
        } else if (mempool.exists((*it)->GetHash())) {
            vHashUpdate.push_back((*it)->GetHash());
        }
        ++it;
    }
    disconnectpool.queuedTx.clear();
    if (!disconnectpool.saplingAnchorToRemove.IsNull())
        mempool.removeWithAnchor(disconnectpool.saplingAnchorToRemove, SAPLING);
    // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
    // no in-mempool children, which is generally not true when adding
    // previously-confirmed transactions back to the mempool.
    // UpdateTransactionsFromBlock finds descendants of any transactions in
    // the disconnectpool that were added back and cleans up the mempool state.
    mempool.UpdateTransactionsFromBlock(vHashUpdate);

    // We also need to remove any now-immature transactions
    mempool.removeForReorg(pcoinsTip, chainActive.Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
    // Re-limit mempool size, in case we added any transactions
    LimitMempoolSize(mempool, GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
}

CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator)
{
    // Find the first block the caller has in the main chain

    for (const uint256& hash : locator.vHave) {
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            CBlockIndex* pindex = (*mi).second;
            if (chain.Contains(pindex))
                return pindex;
        }
    }
    return chain.Genesis();
}

CCoinsViewCache* pcoinsTip = nullptr;
CBlockTreeDB* pblocktree = nullptr;
CClueViewCache* pclueTip = nullptr;
CAdDB* paddb = nullptr;
StorageResults* pstorageresult = nullptr;

bool IsFinalTx(const CTransaction& tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t) tx.nLockTime <= ((int64_t) tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t) nBlockHeight : nBlockTime)) {
        return true;
    }

    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

/**
 * Check if transaction is final and can be accpeted to mempool with the
 * specified height and time. Consensus critical.
 */
bool IsFinalTxMempool(const CTransaction& tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;

    if (tx.nFlag == CTransaction::BID_TX) {
        if (CheckIndexBidLockTimePeroid(tx.nLockTime, nBlockHeight)) {
            return true;
        } else {
            return false;
        }
    }

    if ((int64_t) tx.nLockTime <= ((int64_t) tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t) nBlockHeight : nBlockTime)) {
        return true;
    }

    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

bool IsExpiredTx(const CTransaction& tx, int nBlockHeight)
{
    if (tx.nExpiryHeight == 0 || tx.IsCoinBase()) {
        return false;
    }
    return static_cast<uint32_t>(nBlockHeight) > tx.nExpiryHeight;
}

bool CheckFinalTx(const CTransaction& tx, int flags)
{
    AssertLockHeld(cs_main);

    // By convention a negative value for flags indicates that the
    // current network-enforced consensus rules should be used. In
    // a future soft-fork scenario that would mean checking which
    // rules would be enforced for the next block and setting the
    // appropriate flags. At the present time no soft-forks are
    // scheduled, so no flags are set.
    flags = std::max(flags, 0);

    // CheckFinalTx() uses chainActive.Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than chainActive.Height().
    const int nBlockHeight = chainActive.Height() + 1;

    // Timestamps on the other hand don't get any special treatment,
    // because we can't know what timestamp the next block will have,
    // and there aren't timestamp applications where it matters.
    // However this changes once median past time-locks are enforced:
    const int64_t nBlockTime = (flags & LOCKTIME_MEDIAN_TIME_PAST)
                               ? chainActive.Tip()->GetMedianTimePast()
                               : GetAdjustedTime();

    return IsFinalTxMempool(tx, nBlockHeight, nBlockTime);
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;

    for (const CTxIn& txin : tx.vin) {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }

    for (const CTxOut& txout : tx.vout) {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut& prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

bool CheckAd(const CAd& ad)
{
    uint256 msgHash;
    msgHash = Hash(ad.admsg.begin(), ad.admsg.end());
    CTransactionRef tx;
    uint256 blockHash;
    if (!GetTransaction(ad.txid, tx, Params().GetConsensus(), blockHash, true))
        return false;

    if (tx->nFlag != CTransaction::BID_TX)
        return false;

    for (const CTxOut& out : tx->vout) {
        if (out.nFlag == CTxOut::BID) {
            if (out.dataHash != msgHash)
                return false;
        }
    }

    if (chainActive[ad.blockHeight]->GetBlockHash() != blockHash)
        return false;

    return true;
}

/**
 * Threshold condition checker that triggers when unknown versionbits are seen on the network.
 */
class WarningBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    int bit;

public:
    explicit WarningBitsConditionChecker(int bitIn) : bit(bitIn) {}

    int64_t BeginTime(const Consensus::Params& params) const override
    {
        return 0;
    }
    int64_t EndTime(const Consensus::Params& params) const override
    {
        return std::numeric_limits<int64_t>::max();
    }
    int Period(const Consensus::Params& params) const override
    {
        return params.nMinerConfirmationWindow;
    }
    int Threshold(const Consensus::Params& params) const override
    {
        return params.nRuleChangeActivationThreshold;
    }

    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const override
    {
        return ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) &&
               ((pindex->nVersion >> bit) & 1) != 0 &&
               ((ComputeBlockVersion(pindex->pprev, params) >> bit) & 1) == 0;
    }
};

// Protected by cs_main
static ThresholdConditionCache warningcache[VERSIONBITS_NUM_BITS];

/**
 * Check a transaction contextually against a set of consensus rules valid at a given block height.
 *
 * Notes:
 * 1. AcceptToMemoryPool calls CheckTransaction and this function.
 * 2. ProcessNewBlock calls AcceptBlock, which calls CheckBlock (which calls CheckTransaction)
 *    and ContextualCheckBlock (which calls this function).
 * 3. The isInitBlockDownload argument is only to assist with testing.
 */
bool ContextualCheckTransaction(
    const CTransaction& tx,
    CValidationState& state,
    const int nHeight,
    const int dosLevel,
    bool (*isInitBlockDownload)())
{
    // Check that all transactions are unexpired
    if (IsExpiredTx(tx, nHeight)) {
        // Don't increase banscore if the transaction only just expired
        int expiredDosLevel = IsExpiredTx(tx, nHeight - 1) ? dosLevel : 0;
        return state.DoS(expiredDosLevel, error("ContextualCheckTransaction(): transaction is expired"), REJECT_INVALID, "tx-overwinter-expired");
    }

    if (tx.nFlag == CTransaction::BID_TX) {
        // Here should not check locktime
        std::string strError;
        if (!CheckTxBid(tx, nHeight, strError)) {
            return state.DoS(100, error("CheckBlock(): checktxbid failed %s.", strError), REJECT_INVALID, "bad-tx-bid");
        }
    }

    uint256 dataToBeSigned;

    if (!tx.vShieldedSpend.empty() ||
            !tx.vShieldedOutput.empty()) {
        // Empty output script.
        CScript scriptCode;
        try {
            dataToBeSigned = SignatureHash(scriptCode, tx, NOT_AN_INPUT, SIGHASH_ALL, SIGVERSION_BASE, nullptr);
        } catch (std::logic_error ex) {
            return state.DoS(100, error("CheckTransaction(): error computing signature hash"),
                             REJECT_INVALID, "error-computing-signature-hash");
        }
    }

    if (!tx.vShieldedSpend.empty() ||
            !tx.vShieldedOutput.empty()) {
        auto ctx = librustzcash_sapling_verification_ctx_init();

        for (const SpendDescription& spend : tx.vShieldedSpend) {
            if (!librustzcash_sapling_check_spend(
                        ctx,
                        spend.cv.begin(),
                        spend.anchor.begin(),
                        spend.nullifier.begin(),
                        spend.rk.begin(),
                        spend.zkproof.begin(),
                        spend.spendAuthSig.begin(),
                        dataToBeSigned.begin()
                    )) {
                librustzcash_sapling_verification_ctx_free(ctx);
                return state.DoS(100, error("ContextualCheckTransaction(): Sapling spend description invalid"),
                                 REJECT_INVALID, "bad-txns-sapling-spend-description-invalid");
            }
        }

        for (const OutputDescription& output : tx.vShieldedOutput) {
            if (!librustzcash_sapling_check_output(
                        ctx,
                        output.cv.begin(),
                        output.cm.begin(),
                        output.ephemeralKey.begin(),
                        output.zkproof.begin()
                    )) {
                librustzcash_sapling_verification_ctx_free(ctx);
                return state.DoS(100, error("ContextualCheckTransaction(): Sapling output description invalid"),
                                 REJECT_INVALID, "bad-txns-sapling-output-description-invalid");
            }
        }

        if (!librustzcash_sapling_final_check(
                    ctx,
                    tx.valueBalance,
                    tx.bindingSig.begin(),
                    dataToBeSigned.begin()
                )) {
            librustzcash_sapling_verification_ctx_free(ctx);
            return state.DoS(100, error("ContextualCheckTransaction(): Sapling binding signature invalid"),
                             REJECT_INVALID, "bad-txns-sapling-binding-signature-invalid");
        }

        librustzcash_sapling_verification_ctx_free(ctx);
    }
    return true;
}

bool CheckTransaction(const CTransaction& tx, CValidationState& state,
                      libzcash::ProofVerifier& verifier)
{
    // Don't count coinbase transactions because mining skews the count

    if (!CheckTransactionWithoutProofVerification(tx, state)) {
        return false;
    } else {
        // Ensure that zk-SNARKs verify

    }

    return true;
}

bool CheckTransactionWithoutProofVerification(const CTransaction& tx, CValidationState& state)
{
    // Basic checks that don't depend on any context

    // Check transaction version
    if (tx.nVersion < MIN_TX_VERSION) {
        return state.DoS(100, error("CheckTransaction(): version too low"),
                         REJECT_INVALID, "bad-txns-version-too-low");
    }
    if (tx.nExpiryHeight >= TX_EXPIRY_HEIGHT_THRESHOLD) {
        return state.DoS(100, error("CheckTransaction(): expiry height is too high"),
                         REJECT_INVALID, "bad-tx-expiry-height-too-high");
    }

    if (tx.nFlag >= CTransaction::MAX_FLAG) { // here we should reserve some flag for extensibility
        return state.DoS(100, error("CheckTransaction(): flag too high"),
                         REJECT_INVALID, "bad-txns-flag-too-high");

    }
    // Transactions containing empty `vin` must have either non-empty
    // `vjoinsplit` or non-empty `vShieldedSpend`.
    if (tx.vin.empty() && tx.vShieldedSpend.empty())
        return state.DoS(10, error("CheckTransaction(): vin empty"),
                         REJECT_INVALID, "bad-txns-vin-empty");
    // Transactions containing empty `vout` must have either non-empty
    // `vjoinsplit` or non-empty `vShieldedOutput`.
    if (tx.vout.empty() && tx.vShieldedOutput.empty())
        return state.DoS(10, error("CheckTransaction(): vout empty"),
                         REJECT_INVALID, "bad-txns-vout-empty");

    // Size limits
    BOOST_STATIC_ASSERT(MAX_BLOCK_SIZE > MAX_TX_SIZE); // sanity
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) > MAX_TX_SIZE)
        return state.DoS(100, error("CheckTransaction(): size limits failed"),
                         REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    int nToMasterNodeAll = 0;
    int nTandiaVote = 0;

    CClueViewCache clueview(pclueTip);
    int nClueParent = 0;
    int nClueCount = 0;
    for (const CTxOut& txout : tx.vout) {
        if (txout.nFlag == CTxOut::CLUE) {
            nClueCount++;
            if (!tx.IsCoinClue())
                return state.DoS(100, error("CheckTransaction(): txout clue in nonclue transaction."),
                                 REJECT_MALFORMED, "bad-txns-vout-clue-illegal");
            if (txout.nValue != CLUE_COST_PARENT && txout.nValue != CLUE_COST_PARENT_NOAWARWD && txout.nValue != 0 && txout.nValue != CLUE_COST_PARENT_TOP)
                return state.DoS(100, error("CheckTransaction(): txout clue bad value out."),
                                 REJECT_INVALID, "bad-txns-vout-clue-value");

            if (txout.nValue == CLUE_COST_PARENT_TOP || txout.nValue == CLUE_COST_PARENT_NOAWARWD) {
                if (nClueParent++)
                    return state.DoS(100, error("CheckTransaction(): more than one inviter in transaction."),
                                     REJECT_INVALID, "bad-txns-vout-clue-parent");
            }
        }

        if (txout.nFlag == CTxOut::BID) {
            nToMasterNodeAll++;
            if (nToMasterNodeAll > 1 || tx.nFlag != CTransaction::BID_TX) {
                return state.DoS(100, error("CheckTransaction(): txout.nFlag bid too much"),
                                 REJECT_INVALID, "bad-txns-vout-bid-illegal");
            }

            if (txout.nValue < Params().BidAmountLimit())
                return state.DoS(100, error("CheckTransaction: txout.nValue bid too less"),
                                 REJECT_INVALID, "bad-txns-bid-vout-value");

            if (txout.scriptPubKey != CScript()) {
                return state.DoS(100, error("CheckTransaction():: txout.scriptpubkey is illegal."),
                                 REJECT_INVALID, "bad-txns-vout-bid-scriptpubkey");
            }

            CAmount nBase = 1;
            for (int i = 0; i < BID_COUNT_PRECISION; i++) {
                nBase *= 10;
            }
            CAmount nValuePrecision = COIN / nBase;
            if ((txout.nValue % nValuePrecision) != 0) {
                string strReasonError = string("CheckTransaction():the number of digits after the decimal point is too much,should less than ") + toString(BID_COUNT_PRECISION) + string(" in BID_TX");
                return state.DoS(100, error(strReasonError.c_str()),
                                 REJECT_INVALID, "bad-txns-vout-bid-illegal-precision");
            }
        }

        if (txout.nFlag == CTxOut::TANDIA && tx.nFlag == CTransaction::TANDIA_TX) {
            nTandiaVote ++;
            if (txout.nValue > CAmount(0))
                return state.DoS(100, error("CheckTransaction(): txout.nValue tandia too much"),
                                 REJECT_INVALID, "bad-txns-vout-value-tandia-illegal");

            if (nTandiaVote > 1 || tx.nFlag != CTransaction::TANDIA_TX)
                return state.DoS(100, error("CheckTransaction(): txout.nFlag tandia too much"),
                                 REJECT_INVALID, "bad-txns-vout-tandia-illegal");
            CTxDestination dest;
            if (!ExtractDestination(txout.scriptPubKey, dest))
                return state.DoS(100, error("ExtractDestination: clue scriptpubkey cannot extract to txdestination."),
                                 REJECT_INVALID, "bad-txns-vout-clue-script-invalid");

            // here clue must exists before this block. so use pclueTip.
            if (!clueview.HaveClue(dest)) {
                return state.DoS(100, error("CheckTransaction(): txout address is not a clue address"),
                                 REJECT_INVALID, "bad-txns-vout-address-tandia-illegal");
            }
        }

        if (txout.nValue < 0)
            return state.DoS(100, error("CheckTransaction(): txout.nValue negative"),
                             REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, error("CheckTransaction(): txout.nValue too high"),
                             REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, error("CheckTransaction(): txout total out of range"),
                             REJECT_INVALID, "bad-txns-txouttotal-toolarge");

        /////////////////////////////////////////////////////////// // qtum
        if (txout.scriptPubKey.HasOpCall() || txout.scriptPubKey.HasOpCreate()) {
            std::vector<valtype> vSolutions;
            txnouttype whichType;
            if (!Solver(txout.scriptPubKey, whichType, vSolutions, true)) {
                return state.DoS(100, error("CheckTransaction(): txout.script solve failed"),
                                 REJECT_INVALID, "bad-txns-contract-nonstandard");
            }
        }
        ///////////////////////////////////////////////////////////
    }
    if (nClueCount > Params().ClueChildrenDepth())
        return state.DoS(100, error("CheckTransaction(): more than limited depth clue vouts."),
                         REJECT_INVALID, "bad-txns-clue-vouts");

    if (tx.nFlag == CTransaction::BID_TX && nToMasterNodeAll == 0) {
        return state.DoS(100, error("CheckTransaction(): bid transaction has no bid vout."),
                         REJECT_INVALID, "bad-txns-bid-vout");
    }

    // Check for non-zero valueBalance when there are no Sapling inputs or outputs
    if (tx.vShieldedSpend.empty() && tx.vShieldedOutput.empty() && tx.valueBalance != 0) {
        return state.DoS(100, error("CheckTransaction(): tx.valueBalance has no sources or sinks"),
                         REJECT_INVALID, "bad-txns-valuebalance-nonzero");
    }

    // Check for overflow valueBalance
    if (tx.valueBalance > MAX_MONEY || tx.valueBalance < -MAX_MONEY) {
        return state.DoS(100, error("CheckTransaction(): abs(tx.valueBalance) too large"),
                         REJECT_INVALID, "bad-txns-valuebalance-toolarge");
    }


    CAmount targetFee = std::max<CAmount>(nValueOut / 200, ASYNC_RPC_OPERATION_DEFAULT_MINERS_FEE);

    if (tx.valueBalance <= 0) {
        // NB: negative valueBalance "takes" money from the transparent value pool just as outputs do
        nValueOut += -tx.valueBalance;

        if (!MoneyRange(nValueOut)) {
            return state.DoS(100, error("CheckTransaction(): txout total out of range"),
                             REJECT_INVALID, "bad-txns-txouttotal-toolarge");
        }
    }

    // Check feerate for anon to transparent std::min(x * 5/1000, 500000)
    if (tx.vShieldedSpend.size() != 0 && tx.vout.size() != 0) {
        if ((tx.GetShieldedValueIn() - tx.GetValueOut()) < targetFee) {
            return state.DoS(50, error("CheckTransaction(): shield transaction insufficent fee"),
                             REJECT_INSUFFICIENTFEE, "bad-txns-fee-insufficent");
        }
    }

    // Ensure input values do not exceed MAX_MONEY
    // We have not resolved the txin values at this stage,
    // but we do know what the joinsplits claim to add
    // to the value pool.
    {
        CAmount nValueIn = 0;
        // Also check for Sapling
        if (tx.valueBalance >= 0) {
            // NB: positive valueBalance "adds" money to the transparent value pool, just as inputs do
            nValueIn += tx.valueBalance;

            if (!MoneyRange(nValueIn)) {
                return state.DoS(100, error("CheckTransaction(): txin total out of range"),
                                 REJECT_INVALID, "bad-txns-txintotal-toolarge");
            }
        }
    }


    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;

    for (const CTxIn& txin : tx.vin) {
        if (vInOutPoints.count(txin.prevout))
            return state.DoS(100, error("CheckTransaction(): duplicate inputs"),
                             REJECT_INVALID, "bad-txns-inputs-duplicate");
        vInOutPoints.insert(txin.prevout);
    }

    // Check for duplicate sapling nullifiers in this transaction
    {
        set<uint256> vSaplingNullifiers;
        for (const SpendDescription& spend_desc : tx.vShieldedSpend) {
            if (vSaplingNullifiers.count(spend_desc.nullifier))
                return state.DoS(100, error("CheckTransaction(): duplicate nullifiers"),
                                 REJECT_INVALID, "bad-spend-description-nullifiers-duplicate");

            vSaplingNullifiers.insert(spend_desc.nullifier);
        }
    }

    if (tx.IsCoinBase()) {
        // A coinbase transaction cannot have spend descriptions or output descriptions
        if (tx.vShieldedSpend.size() > 0)
            return state.DoS(100, error("CheckTransaction(): coinbase has spend descriptions"),
                             REJECT_INVALID, "bad-cb-has-spend-description");
        if (tx.vShieldedOutput.size() > 0)
            return state.DoS(100, error("CheckTransaction(): coinbase has output descriptions"),
                             REJECT_INVALID, "bad-cb-has-output-description");

        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, error("CheckTransaction(): coinbase script size"),
                             REJECT_INVALID, "bad-cb-length");
    } else {
        for (const CTxIn& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, error("CheckTransaction(): prevout is null"),
                                 REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}

CAmount GetMinRelayFee(const CTransaction& tx, unsigned int nBytes, bool fAllowFree)
{
    {
        LOCK(mempool.cs);
        uint256 hash = tx.GetHash();
        CAmount nFeeDelta = 0;
        mempool.ApplyDelta(hash, nFeeDelta);
        if (nFeeDelta > 0)
            return 0;
    }

    CAmount nMinFee = ::minRelayTxFee.GetFee(nBytes);

    if (fAllowFree) {
        // There is a free transaction area in blocks created by most miners,
        // * If we are relaying we allow transactions up to DEFAULT_BLOCK_PRIORITY_SIZE - 1000
        //   to be considered to fall into this category. We don't want to encourage sending
        //   multiple transactions instead of one big transaction to avoid fees.
        if (nBytes < (DEFAULT_BLOCK_PRIORITY_SIZE - 1000))
            nMinFee = 0;
    }

    if (!MoneyRange(nMinFee))
        nMinFee = MAX_MONEY;
    return nMinFee;
}

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState& state)
{
    return strprintf("%s (code %i)",
                     state.GetRejectReason(),
                     //        state.GetDebugMessage().empty() ? "" : ", "+state.GetDebugMessage(),
                     state.GetRejectCode());
}

bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState& state, const CTransactionRef& tx, bool fLimitFree,
                        bool* pfMissingInputs, std::list<CTransactionRef>* plTxnReplaced,
                        bool fOverrideMempoolLimitbool, bool fRejectAbsurdFee, bool fDryRun)
{
    return AcceptToMemoryPoolWithTime(pool, state, tx, fLimitFree, pfMissingInputs, GetTime(), plTxnReplaced, fOverrideMempoolLimitbool, fRejectAbsurdFee, fDryRun);
}

bool AcceptToMemoryPoolWithTime(CTxMemPool& pool, CValidationState& state, const CTransactionRef& ptx, bool fLimitFree,
                                bool* pfMissingInputs, int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced, bool fOverrideMempoolLimit, bool fRejectAbsurdFee, bool fDryRun)
{
    AssertLockHeld(cs_main);
    LOCK(pool.cs);
    if (pfMissingInputs)
        *pfMissingInputs = false;

    int nextBlockHeight = chainActive.Height() + 1;
    const CTransaction& tx = *ptx;

    if (nextBlockHeight < Params().GetConsensus().nTandiaBallotStart && tx.nFlag == CTransaction::TANDIA_TX)
        return state.DoS(50, error("%s: tandia should not vote this time", __func__), REJECT_INVALID, "bad-txns-tandiavote");

    auto verifier = libzcash::ProofVerifier::Strict();
    if (!CheckTransaction(tx, state, verifier))
        return error("AcceptToMemoryPool: CheckTransaction failed");

    // DoS level set to 10 to be more forgiving.
    // Check transaction contextually against the set of consensus rules which apply in the next block to be mined.
    if (!ContextualCheckTransaction(tx, state, nextBlockHeight, 10)) {
        return error("AcceptToMemoryPool: ContextualCheckTransaction failed");
    }

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, error("AcceptToMemoryPool: coinbase as individual tx"),
                         REJECT_INVALID, "coinbase");


    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
    string reason;
    if (Params().RequireStandard() && !IsStandardTx(tx, reason))
        return state.DoS(0,
                         error("AcceptToMemoryPool: nonstandard transaction: %s", reason),
                         REJECT_NONSTANDARD, reason);

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTx(tx, STANDARD_LOCKTIME_VERIFY_FLAGS)) {
        LogPrintf("tx CheckFinalTx failed\n");
        return state.DoS(0, false, REJECT_NONSTANDARD, "non-final");
    }

    // is it already in the memory pool?
    uint256 hash = tx.GetHash();
    if (pool.exists(hash))
        return false;


    // Check for conflicts with in-memory transactions
    {
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            COutPoint outpoint = tx.vin[i].prevout;
            if (pool.mapNextTx.count(outpoint)) {
                // Disable replacement feature for now
                return false;
            }
        }

        for (const SpendDescription& spendDescription : tx.vShieldedSpend) {
            if (pool.nullifierExists(spendDescription.nullifier, SAPLING)) {
                return false;
            }
        }
    }

    {
        CCoinsView dummy;
        CClueView cluedummy;
        CCoinsViewCache view(&dummy);
        CClueViewCache clueview(&cluedummy);

        CAmount nValueIn = 0;
        LockPoints lp;
        {
            CCoinsViewMemPool viewMemPool(pcoinsTip, pool);
            view.SetBackend(viewMemPool);

            // do we already have it?
            if (tx.vout.size() > 0 && view.HaveCoin(COutPoint(hash, 0)))
                return false;

            // do all inputs exist?
            // Note that this does not check for the presence of actual outputs (see the next check for that),
            // and only helps with filling in pfMissingInputs (to determine missing vs spent).

            BOOST_FOREACH(const CTxIn txin, tx.vin) {
                if (!view.HaveCoin(txin.prevout)) {
                    if (pfMissingInputs)
                        *pfMissingInputs = true;
                    return false;
                }
            }

            // are the actual inputs available?
            if (!view.HaveInputs(tx))
                return state.Invalid(error("AcceptToMemoryPool: inputs already spent"),
                                     REJECT_DUPLICATE, "bad-txns-inputs-spent");

            // are the joinsplit's requirements met?
            if (!view.HaveShieldedRequirements(tx))
                return state.Invalid(error("AcceptToMemoryPool: joinsplit requirements not met"),
                                     REJECT_DUPLICATE, "bad-txns-joinsplit-requirements-not-met");

            // Bring the best block into scope
            view.GetBestBlock();

            nValueIn = view.GetValueIn(tx);

            // we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
            view.SetBackend(dummy);
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (Params().RequireStandard() && !AreInputsStandard(tx, view))
            return error("AcceptToMemoryPool: nonstandard transaction input");

        // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_STANDARD_TX_SIGOPS is less than
        // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
        unsigned int nSigOps = GetLegacySigOpCount(tx);
        nSigOps += GetP2SHSigOpCount(tx, view);
        if (nSigOps > MAX_STANDARD_TX_SIGOPS)
            return state.DoS(0,
                             error("AcceptToMemoryPool: too many sigops %s, %d > %d",
                                   hash.ToString(), nSigOps, MAX_STANDARD_TX_SIGOPS),
                             REJECT_NONSTANDARD, "bad-txns-too-many-sigops");

        CAmount nValueOut = tx.GetValueOut();
        CAmount nFees = nValueIn - nValueOut;
        dev::u256 txMinGasPrice = 0;

        dev::u256 sumGas = dev::u256(0);
        //////////////////////////////////////////////////////////// // qtum
        if (tx.HasCreateOrCall()) {

            if (!CheckSenderScript(view, tx)) {
                return state.DoS(1, false, REJECT_INVALID, "bad-txns-invalid-sender-script");
            }

            QtumDGP qtumDGP(globalState.get(), fGettingValuesDGP);
            uint64_t minGasPrice = qtumDGP.getMinGasPrice(chainActive.Tip()->nHeight + 1);
            uint64_t blockGasLimit = qtumDGP.getBlockGasLimit(chainActive.Tip()->nHeight + 1);
            size_t count = 0;
            for (const CTxOut& o : tx.vout)
                count += o.scriptPubKey.HasOpCreate() || o.scriptPubKey.HasOpCall() ? 1 : 0;
            QtumTxConverter converter(tx, NULL);
            ExtractQtumTX resultConverter;
            if (!converter.extractionQtumTransactions(resultConverter)) {
                return state.DoS(100, error("AcceptToMempool(): Contract transaction of the wrong format"), REJECT_INVALID, "bad-tx-bad-contract-format");
            }
            std::vector<QtumTransaction> qtumTransactions = resultConverter.first;
            std::vector<EthTransactionParams> qtumETP = resultConverter.second;

            sumGas = dev::u256(0);
            dev::u256 gasAllTxs = dev::u256(0);
            for (QtumTransaction qtumTransaction : qtumTransactions) {
                sumGas += qtumTransaction.gas() * qtumTransaction.gasPrice();

                if (sumGas > dev::u256(INT64_MAX)) {
                    return state.DoS(100, error("AcceptToMempool(): Transaction's gas stipend overflows"), REJECT_INVALID, "bad-tx-gas-stipend-overflow");
                }

                if (sumGas > dev::u256(nFees)) {
                    return state.DoS(100, error("AcceptToMempool(): Transaction fee does not cover the gas stipend"), REJECT_INVALID, "bad-txns-fee-notenough");
                }

                if (txMinGasPrice != 0) {
                    txMinGasPrice = std::min(txMinGasPrice, qtumTransaction.gasPrice());
                } else {
                    txMinGasPrice = qtumTransaction.gasPrice();
                }
                VersionVM v = qtumTransaction.getVersion();
                if (v.format != 0)
                    return state.DoS(100, error("AcceptToMempool(): Contract execution uses unknown version format"), REJECT_INVALID, "bad-tx-version-format");
                if (v.rootVM != 1)
                    return state.DoS(100, error("AcceptToMempool(): Contract execution uses unknown root VM"), REJECT_INVALID, "bad-tx-version-rootvm");
                if (v.vmVersion != 0)
                    return state.DoS(100, error("AcceptToMempool(): Contract execution uses unknown VM version"), REJECT_INVALID, "bad-tx-version-vmversion");
                if (v.flagOptions != 0)
                    return state.DoS(100, error("AcceptToMempool(): Contract execution uses unknown flag options"), REJECT_INVALID, "bad-tx-version-flags");

                //check gas limit is not less than minimum mempool gas limit
                if (qtumTransaction.gas() < GetArg("-minmempoolgaslimit", MEMPOOL_MIN_GAS_LIMIT))
                    return state.DoS(100, error("AcceptToMempool(): Contract execution has lower gas limit than allowed to accept into mempool"), REJECT_INVALID, "bad-tx-too-little-mempool-gas");

                //check gas limit is not less than minimum gas limit (unless it is a no-exec tx)
                if (qtumTransaction.gas() < MINIMUM_GAS_LIMIT && v.rootVM != 0)
                    return state.DoS(100, error("AcceptToMempool(): Contract execution has lower gas limit than allowed"), REJECT_INVALID, "bad-tx-too-little-gas");

                if (qtumTransaction.gas() > UINT32_MAX)
                    return state.DoS(100, error("AcceptToMempool(): Contract execution can not specify greater gas limit than can fit in 32-bits"), REJECT_INVALID, "bad-tx-too-much-gas");

                gasAllTxs += qtumTransaction.gas();
                if (gasAllTxs > dev::u256(blockGasLimit))
                    return state.DoS(1, false, REJECT_INVALID, "bad-txns-gas-exceeds-blockgaslimit");

                //don't allow less than DGP set minimum gas price to prevent MPoS greedy mining/spammers
                if (v.rootVM != 0 && (uint64_t) qtumTransaction.gasPrice() < minGasPrice)
                    return state.DoS(100, error("AcceptToMempool(): Contract execution has lower gas price than allowed"), REJECT_INVALID, "bad-tx-low-gas-price");
            }

            if (!CheckMinGasPrice(qtumETP, minGasPrice))
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-small-gasprice");

            if (count > qtumTransactions.size())
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-incorrect-format");

            //            add here for compile ok
            bool rawTx = true;
            CAmount nAbsurdFee = 0;

            if (rawTx && nAbsurdFee && dev::u256(nFees) > dev::u256(nAbsurdFee) + sumGas)
                return state.Invalid(false,
                                     REJECT_HIGHFEE, "absurdly-high-fee",
                                     strprintf("%d > %d", nFees, nAbsurdFee));
        }
        ////////////////////////////////////////////////////////////

        // Keep track of transactions that spend a coinbase, which we re-scan
        // during reorgs to ensure COINBASE_MATURITY is still met.
        bool fSpendsCoinbase = false;

        BOOST_FOREACH(const CTxIn & txin, tx.vin) {
            const Coin& coin = view.AccessCoin(txin.prevout);
            if (coin.IsCoinBase()) {
                fSpendsCoinbase = true;
                break;
            }
        }

        if (tx.IsCoinClue()) {
            CCoinsViewCache view(pcoinsTip);
            if (!ContextualCheckClueTransaction(tx, state, view, cluepool, Params().GetConsensus(), nextBlockHeight))
                return false;
        }

        CTransactionRef ptx = MakeTransactionRef(tx);
        CTxMemPoolEntry entry(ptx, nFees, nAcceptTime, chainActive.Height(),
                              fSpendsCoinbase, nSigOps, lp, CAmount(txMinGasPrice));
        unsigned int nSize = entry.GetTxSize();

        if (tx.nFlag == CTransaction::BID_TX) {
            if (pool.mapBiggestBid.find(tx.nLockTime) == pool.mapBiggestBid.end()) {
                CAmount nValueOut = 0;
                for (auto txOut : tx.vout) {
                    if (txOut.nFlag == CTxOut::BID) {
                        nValueOut = txOut.nValue;
                    }
                }
                pool.mapBiggestBid[tx.nLockTime] = std::make_pair (tx.GetHash(), nValueOut);
            } else {
                CAmount nValueOut = 0;
                for (auto txOut : tx.vout) {
                    if (txOut.nFlag == CTxOut::BID) {
                        nValueOut = txOut.nValue;
                    }
                }
                CAmount nValueOutOld = pool.mapBiggestBid[tx.nLockTime].second;
                if (nValueOut < nValueOutOld) {
                    return state.DoS(1,
                                     error("AcceptToMemoryPool: bid price less than current max."),
                                     REJECT_INVALID, "bad-txns-bid-less-price");
                } else {
                    CTxMemPool::txiter mi = pool.mapTx.find(pool.mapBiggestBid[tx.nLockTime].first);
                    if (mi != pool.mapTx.end()) {
                        pool.removeRecursive(mi->GetTx(), MemPoolRemovalReason::REPLACED);
                    }
                    pool.mapBiggestBid[tx.nLockTime] = std::make_pair (tx.GetHash(), nValueOut);
                }
            }
        }
        // Accept a tx if it contains joinsplits and has at least the default fee specified by v_sendmany.
        {
            // Don't accept it if it can't get into a block
            CAmount txMinFee = GetMinRelayFee(tx, nSize, true);
            if (fLimitFree && nFees < txMinFee)
                return state.DoS(0, error("AcceptToMemoryPool: not enough fees %s, %d < %d",
                                          hash.ToString(), nFees, txMinFee),
                                 REJECT_INSUFFICIENTFEE, "insufficient fee");
        }

        // Continuously rate-limit free (really, very-low-fee) transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (fLimitFree && nFees < ::minRelayTxFee.GetFee(nSize)) {
            static CCriticalSection csFreeLimiter;
            static double dFreeCount;
            static int64_t nLastTime;
            int64_t nNow = GetTime();

            LOCK(csFreeLimiter);

            // Use an exponentially decaying ~10-minute window:
            dFreeCount *= pow(1.0 - 1.0 / 600.0, (double) (nNow - nLastTime));
            nLastTime = nNow;
            // -limitfreerelay unit is thousand-bytes-per-minute
            // At default rate it would take over a month to fill 1GB
            if (dFreeCount >= GetArg("-limitfreerelay", 15) * 10 * 1000)
                return state.DoS(0, error("AcceptToMemoryPool: free transaction rejected by rate limiter"),
                                 REJECT_INSUFFICIENTFEE, "rate limited free transaction");
            LogPrint("mempool", "Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount + nSize);
            dFreeCount += nSize;
        }

        if (fRejectAbsurdFee && nFees > ::minRelayTxFee.GetFee(nSize) * 10000 + sumGas && tx.nFlag != CTransaction::CLUE_TX && tx.nFlag != CTransaction::BID_TX) {
            if (tx.vShieldedOutput.empty())
                return error("AcceptToMemoryPool: absurdly high fees %s, %d > %d",
                             hash.ToString(),
                             nFees, ::minRelayTxFee.GetFee(nSize) * 10000);
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        PrecomputedTransactionData txdata(tx);
        if (!ContextualCheckInputs(tx, state, view, cluepool, true, STANDARD_SCRIPT_VERIFY_FLAGS, true, txdata, Params().GetConsensus(), NULL)) {
            return error("AcceptToMemoryPool: ConnectInputs failed %s", hash.ToString());
        }

        // Check again against just the consensus-critical mandatory script
        // verification flags, in case of bugs in the standard flags that cause
        // transactions to pass as valid when they're actually invalid. For
        // instance the STRICTENC flag was incorrectly allowing certain
        // CHECKSIG NOT scripts to pass, even though they were invalid.
        //
        // There is a similar check in CreateNewBlock() to prevent creating
        // invalid blocks, however allowing such transactions into the mempool
        // can be exploited as a DoS attack.
        if (!ContextualCheckInputs(tx, state, view, cluepool, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true, txdata, Params().GetConsensus(), NULL)) {
            return error("AcceptToMemoryPool: BUG! PLEASE REPORT THIS! ConnectInputs failed against MANDATORY but not STANDARD flags %s", hash.ToString());
        }

        UpdateClue(tx, state, view, cluepool);
        // Store transaction in memory
        pool.addUnchecked(hash, entry, !IsInitialBlockDownload());

        pool.addAddressIndex(entry, view);
        pool.addSpentIndex(entry, view);
    }

    GetMainSignals().TransactionAddedToMempool(ptx);

    return true;
}

/** Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock */
bool GetTransaction(const uint256& hash, CTransactionRef& txOut, const Consensus::Params& consensusParams, uint256& hashBlock, bool fAllowSlow)
{
    CBlockIndex* pindexSlow = NULL;

    LOCK(cs_main);

    CTransactionRef ptx = mempool.get(hash);
    if (ptx) {
        txOut = ptx;
        return true;
    }

    if (fTxIndex) {
        // Check if this is the coinbase transaction in genesis block
        for (const auto& tx : Params().GenesisBlock().vtx) {
            if (tx->GetHash() == hash) {
                txOut = tx;
                hashBlock = consensusParams.hashGenesisBlock;
                return true;
            }
        }

        CDiskTxPos postx;
        if (pblocktree->ReadTxIndex(hash, postx)) {
            CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
            if (file.IsNull())
                return error("%s: OpenBlockFile failed", __func__);
            CBlockHeader header;
            try {
                file >> header;
                fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
                file >> txOut;
            } catch (const std::exception& e) {
                return error("%s: Deserialize or I/O error - %s", __func__, e.what());
            }
            hashBlock = header.GetHash();
            if (txOut->GetHash() != hash)
                return error("%s: txid mismatch", __func__);
            return true;
        }
    }

    if (fAllowSlow) { // use coin database to locate block that contains transaction, and scan it
        const Coin& coin = AccessByTxid(*pcoinsTip, hash);
        if (!coin.IsSpent()) pindexSlow = chainActive[coin.nHeight];
    }

    if (pindexSlow) {
        CBlock block;
        if (ReadBlockFromDisk(block, pindexSlow, consensusParams)) {
            for (const auto& tx : block.vtx) {
                if (tx->GetHash() == hash) {
                    txOut = tx;
                    hashBlock = pindexSlow->GetBlockHash();
                    return true;
                }
            }
        }
    }

    return false;
}

/** Return merkletransaction in tx, and if it was found inside a block, its hash is placed in hashBlock */
bool GetMerkleTransaction(const uint256& hash, CMerkleTransaction& txOut, const Consensus::Params& consensusParams)
{
    CBlockIndex* pindexSlow = NULL;
    bool fFindTx = false;
    CTransactionRef rTx;
    int nIndex = -1;
    CBlock block;

    LOCK(cs_main);


    if (fTxIndex) {
        // Check if this is the coinbase transaction in genesis block
        for (int i = 0; i < Params().GenesisBlock().vtx.size(); i++) {
            CTransactionRef tx = Params().GenesisBlock().vtx[i];
            if (tx->GetHash() == hash) {
                rTx = tx;
                nIndex = i;
                block = Params().GenesisBlock();
                fFindTx = true;
                break;
            }
        }

        if (fFindTx) {
            txOut = CMerkleTransaction(rTx, block, nIndex);
        }

        CDiskTxPos postx;
        if (pblocktree->ReadTxIndex(hash, postx)) {
            CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
            if (file.IsNull())
                return error("%s: OpenBlockFile failed", __func__);
            try {
                file >> block;
            } catch (const std::exception& e) {
                return error("%s: Deserialize or I/O error - %s", __func__, e.what());
            }

            fFindTx = true;
            for (int i = 0; i < block.vtx.size(); i++) {
                CTransactionRef tx = block.vtx[i];
                if (tx->GetHash() == hash) {
                    txOut = CMerkleTransaction(tx, block, i);
                    return true;
                }
            }
        }
    }

    if (!fFindTx) {
        const Coin& coin = AccessByTxid(*pcoinsTip, hash);
        if (!coin.IsSpent()) pindexSlow = chainActive[coin.nHeight];

        if (pindexSlow) {
            if (!ReadBlockFromDisk(block, pindexSlow, consensusParams))
                return false;
        }
    }

    for (int i = 0; i < block.vtx.size(); i++) {
        CTransactionRef tx = block.vtx[i];
        if (tx->GetHash() == hash) {
            txOut = CMerkleTransaction(tx, block, i);
            return true;
        }
    }

    return false;
}

bool GetMerkleTransactionWithAnonymous(const int blockHeight, std::map<int, std::map<uint256, char>>& filterdTxids, std::vector<CMerkleTxBlock>& output)
{
    AnonymousBlock ablock;
    std::map<int, std::map<uint256, char>>::iterator filterItor = filterdTxids.find(blockHeight);
    std::map<uint256, char> filteredTxs;
    if (filterItor != filterdTxids.end())
        filteredTxs = filterItor->second;

    if (blockHeight > chainActive.Height())
        return false;

    uint256 blockHash = chainActive[blockHeight]->GetBlockHash();

    if (!pblocktree->ReadAnonymousBlock(blockHash, ablock))
        return false;

    if (filteredTxs.size() == 0 && ablock.txs.size() == 0) {
        if (filterItor != filterdTxids.end())
            filterdTxids.erase(filterItor);
        return true;
    }

    CBlock block;
    bool read;
    int index = 0;
    CBlockIndex* pblockindex = nullptr;
    {
        LOCK(cs_main);

        if (mapBlockIndex.find(blockHash) != mapBlockIndex.end()) {
            pblockindex = mapBlockIndex[blockHash];
        }
        assert(pblockindex != NULL);

        if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
            LogPrintf("Cano not reade block %s from disk", blockHash.ToString().c_str());
            return false;
        }
    }
    CMerkleTxBlock merkleBlock(blockHash);
    std::vector<AnonymousTxInfo>::iterator itor_anonymousTx = ablock.txs.begin();
    for (CTransactionRef tx : block.vtx) {
        read = false;

        uint256 txid = tx->GetHash();
        if (filteredTxs.find(txid) != filteredTxs.end())
            read = true;

        boost::optional<SaplingMerkleTree> saplingMerkleTree = boost::none;
        if (itor_anonymousTx != ablock.txs.end()) {
            if (itor_anonymousTx->txid == txid) {
                read = true;
                saplingMerkleTree = itor_anonymousTx->saplingMerkleTree;
                itor_anonymousTx++;
            }
        }

        if (read) {
            merkleBlock.txs.emplace_back(tx, block, index, saplingMerkleTree);
        }
        index++;
    }

    if (merkleBlock.txs.size())
        output.push_back(merkleBlock);

    if (filterItor != filterdTxids.find(blockHeight))
        filterdTxids.erase(filterItor);

    return true;
}

bool GetSampleMerkleTransactionWithAnonymous(const int blockHeight, std::map<int, std::map<uint256, char> >& filterdTxids, std::vector<CMerkleTxBlockSample>& output)
{
    LOCK(cs_main);
    AnonymousBlock ablock;
    std::map<int, std::map<uint256, char>>::iterator filterItor = filterdTxids.find(blockHeight);
    std::map<uint256, char> filteredTxs;
    if (filterItor != filterdTxids.end())
        filteredTxs = filterItor->second;

    if (blockHeight > chainActive.Height() || blockHeight < 1)
        return false;

    CBlockIndex* blockIdx = chainActive[blockHeight];
    uint256 blockHash = blockIdx->GetBlockHash();
    if ((blockHeight <= chainActive.Height()) && (blockHeight >= 100)) {
        CBlockIndex* prevBlockIdx = chainActive[blockHeight - 1];
        if (blockIdx->hashFinalSaplingRoot != prevBlockIdx->hashFinalSaplingRoot) {
            if (!pblocktree->ReadAnonymousBlock(blockHash, ablock))
                return false;
        }
    }

    CMerkleTxBlockSample merkleBlock(blockHash);
    if (ablock.txs.size())
        merkleBlock.tree = ablock.txs[0].saplingMerkleTree;

    if (filteredTxs.empty() && ablock.txs.empty())
        return true;

    CBlock block;
    if (!ReadBlockFromDisk(block, blockIdx, Params().GetConsensus())) {
        LogPrintf("Cano not reade block %s from disk", blockHash.ToString().c_str());
    }

    BOOST_FOREACH (CTransactionRef tx, block.vtx) {
        uint256 txid = tx->GetHash();
        if (filteredTxs.find(txid) != filteredTxs.end())
            merkleBlock.txs.push_back(tx);
        else if (tx->vShieldedSpend.size() || tx->vShieldedOutput.size())
            merkleBlock.txs.push_back(tx);
    }

    output.push_back(merkleBlock);
    return true;
}

bool GetIndexKey(const CScript& scritPubKey, uint160& hashBytes, txnouttype& type)
{
    std::vector<std::vector<unsigned char> > vSolutions;
    if (!Solver(scritPubKey, type, vSolutions))
        return false;
    switch (type) {
    case TX_NONSTANDARD:
        return "nonstandard";
    case TX_PUBKEY:
    case TX_WITNESS_V0_SCRIPTHASH:
        memcpy(hashBytes.begin(), CPubKey(vSolutions[0]).GetID().begin(), 20);
        type = TX_PUBKEYHASH;
        return true;
    case TX_PUBKEYHASH:
    case TX_SCRIPTHASH:
    case TX_WITNESS_V0_KEYHASH:
        std::copy(vSolutions[0].begin(), vSolutions[0].end(), hashBytes.begin());
        return true;
    case TX_MULTISIG: {
        CScriptID id(scritPubKey);
        std::copy(id.begin(), id.end(), hashBytes.begin());
    }
    return true;
    case TX_NULL_DATA:
        return false;
    case TX_CREATE:
        return false;
    case TX_CALL:
        return false;
    }

    return false;
}

bool GetSpentIndex(CSpentIndexKey& key, CSpentIndexValue& value)
{
    if (mempool.getSpentIndex(key, value))
        return true;

    if (!pblocktree->ReadSpentIndex(key, value))
        return false;

    return true;
}

bool GetAddressIndex(uint160 addressHash, int type,
                     std::vector<std::pair<CAddressIndexKey, CAmount> >& addressIndex, int start, int end)
{
    if (!fAddressIndex)
        return error("address index not enabled");

    if (!pblocktree->ReadAddressIndex(addressHash, type, addressIndex, start, end))
        return error("unable to get txids for address");

    return true;
}

bool GetUTXOAtHeight(const CScript& script, const int nHeight, std::vector<CUtxo>& vTxOut, const CAmount& valueLimit)
{
    int start = 1;
    int end = nHeight;
    uint160 dest;
    txnouttype type;
    std::vector<std::pair<uint160, int> > addresses;
    if (!GetIndexKey(script, dest, type))
        return false;

    addresses.push_back(std::make_pair(dest, type));

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (!GetAddressIndex((*it).first, (*it).second, addressIndex, start, end)) {
            return false;
        }
    }

    int ret = 0;
    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it = addressIndex.begin(); it != addressIndex.end(); it++) {
        int height = it->first.blockHeight;
        uint256 txid = it->first.txhash;

        if (it->second >= valueLimit) {
            CSpentIndexKey key(txid, it->first.index);
            CSpentIndexValue value;

            if (!GetSpentIndex(key, value)) {
                CUtxo txout;
                txout.txid = txid;
                txout.n = it->first.index;
                txout.nValue = it->second;
                txout.nHeight = height;
                vTxOut.push_back(txout);
                ret += 1;
                continue;
            }

            if (value.blockHeight > end && end >= 0) {
                CUtxo txout;
                txout.txid = txid;
                txout.n = it->first.index;
                txout.nValue = it->second;
                txout.nHeight = height;
                vTxOut.push_back(txout);
                ret += 1;
            }
        }
    }
    return (ret > 0);
}
//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

bool WriteBlockToDisk(const CBlock& block, CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("WriteBlockToDisk: OpenBlockFile failed");

    // Write index header
    unsigned int nSize = GetSerializeSize(fileout, block);
    fileout << FLATDATA(messageStart) << nSize;

    // Write block
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("WriteBlockToDisk: ftell failed");
    pos.nPos = (unsigned int) fileOutPos;
    fileout << block;

    return true;
}

bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos, const Consensus::Params& consensusParams)
{
    block.SetNull();

    // Open history file to read
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("ReadBlockFromDisk: OpenBlockFile failed for %s", pos.ToString());

    // Read block
    try {
        filein >> block;
    }    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
    }

    // Check the header
    if (!(CheckEquihashSolution(&block, Params()) &&
            CheckProofOfWork(block.GetPoWHash(), block.nBits, Params().GetConsensus())))
        return error("ReadBlockFromDisk: Errors in block header at %s", pos.ToString());

    return true;
}

bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams)
{
    if (!ReadBlockFromDisk(block, pindex->GetBlockPos(), consensusParams))
        return false;
    if (block.GetHash() != pindex->GetBlockHash())
        return error("ReadBlockFromDisk(CBlock&, CBlockIndex*): GetHash() doesn't match index for %s at %s",
                     pindex->ToString(), pindex->GetBlockPos().ToString());
    return true;
}

int64_t GetLastSeasonClues(int nHeight, const Consensus::Params& consensusParams)
{
    LOCK(cs_main);
    if (chainActive.Tip() == NULL) return -1;
    if (nHeight < -1 ) return -1;

    int nWeek = nHeight / consensusParams.nBlockCountOfWeek;
    if (nWeek < 3) {
        return -1;
    }

    int nLastWeekMaxBlock = nWeek * consensusParams.nBlockCountOfWeek - 1;
    int nLastWeekMinBlock = (nWeek - 1) * consensusParams.nBlockCountOfWeek - 1;
    if (nWeek == 3) {
        nLastWeekMinBlock = 1;
    }

    if (nLastWeekMaxBlock > chainActive.Height())
        return -1;

    return chainActive[nLastWeekMaxBlock]->nChainClueTx - chainActive[nLastWeekMinBlock]->nChainClueTx;
}


CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)
{
    if (nHeight == 0)
        return 100000000 * COIN;
    CAmount nSubsidy = 500 * COIN;

    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 391)
        return 0;

    for (int i = 0; i < halvings; i++) {
        nSubsidy *= 0.95;
    }

    return nSubsidy;
}

CAmount GetBlockClueSubsidy(int nHeight, const Consensus::Params& consensusParams, bool fLimit)
{
    if (nHeight == 0)
        return 100000000 * COIN;
    CAmount nSubsidy = 500 * COIN;

    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 391)
        return 0;

    for (int i = 0; i < halvings; i++) {
        nSubsidy *= 0.95;
    }

    int64_t nClueTx = GetLastSeasonClues(nHeight, consensusParams);

    if (nClueTx == -1)
        return nSubsidy;

    int nBlocksOfLastSeason = 0;
    if (nHeight / consensusParams.nBlockCountOfWeek > 3)
        nBlocksOfLastSeason = consensusParams.nBlockCountOfSeason;
    else
        nBlocksOfLastSeason = consensusParams.nBlockCountOf1stSeason;
    CAmount nClueLastPerBlockCost = nClueTx * CLUE_TOTAL / consensusParams.nBlockCountOfWeek + chainActive[nHeight - nBlocksOfLastSeason]->nClueLeft;
    CAmount nMinSubdisy = nSubsidy * 0.01;

    nMinSubdisy = std::max(nMinSubdisy, nClueLastPerBlockCost);
    if (fLimit)
        return std::min(nSubsidy, nMinSubdisy);
    return nMinSubdisy;
}

bool GetBlockHash(uint256& hashRet, int nBlockHeight)
{
    LOCK(cs_main);
    if (chainActive.Tip() == NULL) return false;
    if (nBlockHeight < -1 || nBlockHeight > chainActive.Height()) return false;
    if (nBlockHeight == -1) nBlockHeight = chainActive.Height();
    hashRet = chainActive[nBlockHeight]->GetBlockHash();
    return true;
}

bool IsBlockInMainChain(const uint256& blockhash, int& nBlockHeight)
{
    LOCK(cs_main);
    BlockMap::const_iterator it = mapBlockIndex.find(blockhash);
    if (it == mapBlockIndex.end())
        return false;
    const CBlockIndex* pindex = it->second;
    if (!chainActive.Contains(pindex))
        return false;
    nBlockHeight = pindex->nHeight;
    return true;
}

CAmount GetMasternodePayment(int nHeight, CAmount blockValue)
{
    CAmount ret = (blockValue - blockValue / 100) / 2;
    return ret;
}

bool IsInitialBlockDownload()
{
    static bool lockIBDState = false;
    if (lockIBDState)
        return false;
    if (fImporting || fReindex)
        return true;
    LOCK(cs_main);
    const CChainParams& chainParams = Params();
    if (chainActive.Tip() == NULL)
        return true;
    //    if (chainActive.Tip()->nChainWork < UintToArith256(chainParams.GetConsensus().nMinimumChainWork))
    //        return true;
    if (chainActive.Tip()->GetBlockTime() < (GetTime() - chainParams.MaxTipAge()))
        return true;
    lockIBDState = true;
    return false;
}

bool fLargeWorkForkFound = false;
bool fLargeWorkInvalidChainFound = false;
CBlockIndex* pindexBestForkTip = NULL, *pindexBestForkBase = NULL;

void CheckForkWarningConditions()
{
    AssertLockHeld(cs_main);
    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before the last checkpoint)
    if (IsInitialBlockDownload())
        return;

    // If our best fork is no longer within 288 blocks (+/- 12 hours if no one mines it)
    // of our head, drop it
    if (pindexBestForkTip && chainActive.Height() - pindexBestForkTip->nHeight >= 288)
        pindexBestForkTip = NULL;

    if (pindexBestForkTip || (pindexBestInvalid && pindexBestInvalid->nChainWork > chainActive.Tip()->nChainWork + (GetBlockProof(*chainActive.Tip()) * 6))) {
        if (!fLargeWorkForkFound && pindexBestForkBase) {
            std::string warning = std::string("'Warning: Large-work fork detected, forking after block ") +
                                  pindexBestForkBase->phashBlock->ToString() + std::string("'");
            CAlert::Notify(warning, true);
        }
        if (pindexBestForkTip && pindexBestForkBase) {
            LogPrintf("%s: Warning: Large valid fork found\n  forking the chain at height %d (%s)\n  lasting to height %d (%s).\nChain state database corruption likely.\n", __func__,
                      pindexBestForkBase->nHeight, pindexBestForkBase->phashBlock->ToString(),
                      pindexBestForkTip->nHeight, pindexBestForkTip->phashBlock->ToString());
            fLargeWorkForkFound = true;
        } else {
            std::string warning = std::string("Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.");
            LogPrintf("%s: %s\n", warning.c_str(), __func__);
            ReprocessBlocks(288);
            CAlert::Notify(warning, true);
            fLargeWorkInvalidChainFound = true;
        }
    } else {
        fLargeWorkForkFound = false;
        fLargeWorkInvalidChainFound = false;
    }
}

void CheckForkWarningConditionsOnNewFork(CBlockIndex* pindexNewForkTip)
{
    AssertLockHeld(cs_main);
    // If we are on a fork that is sufficiently large, set a warning flag
    CBlockIndex* pfork = pindexNewForkTip;
    CBlockIndex* plonger = chainActive.Tip();
    while (pfork && pfork != plonger) {
        while (plonger && plonger->nHeight > pfork->nHeight)
            plonger = plonger->pprev;
        if (pfork == plonger)
            break;
        pfork = pfork->pprev;
    }

    // We define a condition where we should warn the user about as a fork of at least 7 blocks
    // with a tip within 72 blocks (+/- 3 hours if no one mines it) of ours
    // We use 7 blocks rather arbitrarily as it represents just under 10% of sustained network
    // hash rate operating on the fork.
    // or a chain that is entirely longer than ours and invalid (note that this should be detected by both)
    // We define it this way because it allows us to only store the highest fork tip (+ base) which meets
    // the 7-block condition and from this always have the most-likely-to-cause-warning fork
    if (pfork && (!pindexBestForkTip || (pindexBestForkTip && pindexNewForkTip->nHeight > pindexBestForkTip->nHeight)) &&
            pindexNewForkTip->nChainWork - pfork->nChainWork > (GetBlockProof(*pfork) * 7) &&
            chainActive.Height() - pindexNewForkTip->nHeight < 72) {
        pindexBestForkTip = pindexNewForkTip;
        pindexBestForkBase = pfork;
    }

    CheckForkWarningConditions();
}

void static InvalidChainFound(CBlockIndex* pindexNew)
{
    if (!pindexBestInvalid || pindexNew->nChainWork > pindexBestInvalid->nChainWork)
        pindexBestInvalid = pindexNew;

    LogPrintf("%s: invalid block=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
              pindexNew->GetBlockHash().ToString(), pindexNew->nHeight,
              log(pindexNew->nChainWork.getdouble()) / log(2.0), DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
                      pindexNew->GetBlockTime()));
    CBlockIndex* tip = chainActive.Tip();
    assert(tip);
    LogPrintf("%s:  current best=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
              tip->GetBlockHash().ToString(), chainActive.Height(), log(tip->nChainWork.getdouble()) / log(2.0),
              DateTimeStrFormat("%Y-%m-%d %H:%M:%S", tip->GetBlockTime()));
    CheckForkWarningConditions();
}

void static InvalidBlockFound(CBlockIndex* pindex, const CValidationState& state)
{
    if (!state.CorruptionPossible()) {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        setDirtyBlockIndex.insert(pindex);
        setBlockIndexCandidates.erase(pindex);
        InvalidChainFound(pindex);
    }
}

void UpdateClue(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& view, CClueViewCache& clueinputs, int nHeight, const uint256& hash)
{
    if (!tx.IsCoinClue())
        return;
    CClue clue;
    bool fRoot;
    std::map<CTxDestination, CRankItem> mapItems;

    if (!GetTransactionClue(tx, view, clue, mapItems, fRoot)) {
        LogPrint("clue", "UpdateClue(): GetTransactionClue failed.\n");
        return;
    }

    if (fRoot) {
        if (!clueinputs.HaveClue(clue.parent)) {
            CClue root;
            root.address = clue.parent;
            root.txid = hash;
            assert(clueinputs.AddRoot(root));
        }
    }

    assert(clueinputs.AddClue(clue));
    int nSeason = Params().SeasonOfBlock(nHeight);
    mapItems[clue.inviter].nInvitees += 1;
    for (std::map<CTxDestination, CRankItem>::iterator it = mapItems.begin(); it != mapItems.end(); it++) {
        clueinputs.AddRankItem(it->first, nSeason, it->second);
    }
}

void UndoClue(const CTransaction& tx, CValidationState& state, CCoinsViewCache& view, CClueViewCache& clueinputs, int nHeight, const uint256& hash)
{
    if (!tx.IsCoinClue())
        return;
    CClue clue;
    bool fRoot;
    std::map<CTxDestination, CRankItem> mapItems;
    if (!GetTransactionClue(tx, view, clue, mapItems, fRoot)) {
        LogPrint("clue", "UndoClue(): GetTransactionClue failed.\n");
        return;
    }

    assert(clueinputs.DeleteClue(clue.address));
    if (fRoot) {
        if (clueinputs.ChildrenSize(clue.parent) == 0) {
            clueinputs.DeleteClue(clue.parent);
        }
    }

    int nSeason = Params().SeasonOfBlock(nHeight);
    mapItems[clue.inviter].nInvitees += 1;
    for (std::map<CTxDestination, CRankItem>::iterator it = mapItems.begin(); it != mapItems.end(); it++) {
        // change to depositive for disconnect;
        it->second.nInvitees *= -1;
        it->second.nValue *= -1;
        it->second.dWeight *= -1;
        clueinputs.AddRankItem(it->first, nSeason, it->second);
    }
}

void UpdateCoins(const CTransaction& tx, CValidationState& state, CCoinsViewCache& inputs, CTxUndo& txundo, int nHeight)
{
    // mark inputs spent
    if (!tx.IsCoinBase()) {
        txundo.vprevout.reserve(tx.vin.size());

        BOOST_FOREACH(const CTxIn & txin, tx.vin) {
            txundo.vprevout.emplace_back();
            bool is_spent = inputs.SpendCoin(txin.prevout, &txundo.vprevout.back());
            assert(is_spent);
        }
    }
    // spend nullifiers
    inputs.SetNullifiers(tx, true);

    // add outputs
    AddCoins(inputs, tx, nHeight);
}

void UpdateCoins(const CTransaction& tx, CValidationState& state, CCoinsViewCache& inputs, int nHeight)
{
    CTxUndo txundo;
    UpdateCoins(tx, state, inputs, txundo, nHeight);
}

bool CScriptCheck::operator()()
{
    const CScript& scriptSig = ptxTo->vin[nIn].scriptSig;

    if (!VerifyScript(scriptSig, scriptPubKey, &ptxTo->vin[nIn].scriptWitness, nFlags, CachingTransactionSignatureChecker(ptxTo, nIn, cacheStore, *txdata), &error)) {
        return ::error("CScriptCheck(): %s:%d VerifySignature failed: %s", ptxTo->GetHash().ToString(), nIn, ScriptErrorString(error));
    }
    return true;
}

int GetSpendHeight(const CCoinsViewCache& inputs)
{
    LOCK(cs_main);
    CBlockIndex* pindexPrev = mapBlockIndex.find(inputs.GetBestBlock())->second;
    return pindexPrev->nHeight + 1;
}

namespace Consensus
{


bool CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, const CClueViewCache& clueinputs, int nSpendHeight, const Consensus::Params& consensusParams, CAmount& txfee)
{
    // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
    // for an attacker to attempt to split the network.
    if (!inputs.HaveInputs(tx))
        return state.Invalid(error("CheckInputs(): %s inputs unavailable", tx.GetHash().ToString()));

    // are the JoinSplit's requirements met?
    if (!inputs.HaveShieldedRequirements(tx))
        return state.Invalid(error("CheckInputs(): %s JoinSplit requirements not met", tx.GetHash().ToString()));

    CAmount nValueIn = 0;
    CAmount nFees = 0;
    CTxDestination clueaddr;

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const COutPoint& prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        if (coin.IsCoinBase()) {
            // Ensure that coinbases are matured
            if (nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
                return state.Invalid(
                           error("CheckInputs(): tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight),
                           REJECT_INVALID, "bad-txns-premature-spend-of-coinbase");
            }

            // Ensure that coinbases cannot be spent to transparent outputs
            // Disabled on regtest
            if (fCoinbaseEnforcedProtectionEnabled &&
                    consensusParams.fCoinbaseMustBeProtected &&
                    !tx.vout.empty()) {
                return state.Invalid(
                           error("CheckInputs(): tried to spend coinbase with transparent outputs"),
                           REJECT_INVALID, "bad-txns-coinbase-spend-has-transparent-outputs");
            }
        }

        if (!coin.out.scriptPubKey.HasOpCall()
                && !coin.out.scriptPubKey.HasOpSpend()
                && !coin.out.scriptPubKey.HasOpCreate()) {

            CTxDestination address;
            if (!ExtractDestination(coin.out.scriptPubKey, address))
                return state.Invalid(
                           error("CheckInputs(): prevout scriptPubkey is invalid."),
                           REJECT_INVALID, "bad-txns-coin-scriptPubKey-invalid");

            if (tx.nFlag == CTransaction::TANDIA_TX) {
                if (!clueinputs.HaveClue(address))
                    return state.Invalid(
                               error("CheckInputs(): prevout scriptPubkey is not clued."),
                               REJECT_INVALID, "bad-txns-tandia-scriptPubKey-invalid");
            }

            if (tx.nFlag == CTransaction::CLUE_TX) {
                if (i == 0)
                    clueaddr = address;

                if (clueaddr != address)
                    return state.Invalid(
                               error("CheckInputs(): prevout scriptpubkey are not same."),
                               REJECT_INVALID, "bad-txns-clue-vin-address");

                if (clueinputs.IsConflict(address, tx.GetHash()))
                    return state.Invalid(
                               error("CheckInputs(): prevout scriptPubkey is clued for clue."),
                               REJECT_INVALID, "bad-txns-clue-scriptPubkey-invalid");
            }
        }

        if (coin.out.nFlag == CTxOut::CLUE) {
            if (nSpendHeight - coin.nHeight < consensusParams.nClueMaturity) {
                return state.Invalid(error("CheckInputs(): try to spend coin clue at depth: %d", nSpendHeight - coin.nHeight), REJECT_INVALID, "bad-txns-coinclue-depth");
            }
        }
        // Check for negative or overflow input values
        nValueIn += coin.out.nValue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn))
            return state.DoS(100, error("CheckInputs(): txin values out of range"),
                             REJECT_INVALID, "bad-txns-inputvalues-outofrange");

    }

    // Check special transactions
    if (tx.nFlag > CTransaction::MAX_FLAG)
        return state.DoS(100, error("CheckInputs(): nFlag is too large"),
                         REJECT_INVALID, "bad-txns-flag-verification-failed");

    nValueIn += tx.GetShieldedValueIn();
    if (!MoneyRange(nValueIn))
        return state.DoS(100, error("CheckInputs(): vpub_old values out of range"),
                         REJECT_INVALID, "bad-txns-inputvalues-outofrange");

    if (nValueIn < tx.GetValueOut())
        return state.DoS(100, error("CheckInputs(): %s value in (%s) < value out (%s)",
                                    tx.GetHash().ToString(), FormatMoney(nValueIn), FormatMoney(tx.GetValueOut())),
                         REJECT_INVALID, "bad-txns-in-belowout");

    // Tally transaction fees
    CAmount nTxFee = nValueIn - tx.GetValueOut();
    if (nTxFee < 0)
        return state.DoS(100, error("CheckInputs(): %s nTxFee < 0", tx.GetHash().ToString()),
                         REJECT_INVALID, "bad-txns-fee-negative");
    nFees += nTxFee;
    if (!MoneyRange(nFees))
        return state.DoS(100, error("CheckInputs(): nFees out of range"),
                         REJECT_INVALID, "bad-txns-fee-outofrange");

    txfee = nFees;
    return true;
}
}// namespace Consensus

bool CheckClueParentsRelationship(const std::vector<CTxDestination>& parents, CValidationState& state, const CClueViewCache& clueinputs)
{
    assert(parents.size() > 0);

    CTxDestination parentcache = parents[0];
    std::vector<CTxDestination> vParents;
    CClueViewCache cluecache(clueinputs);
    vParents.push_back(parentcache);
    if (!cluecache.GetParents(parentcache, vParents))
        return state.DoS(100, error("invalid clue parent"), REJECT_MALFORMED, "bad-clue-tree");

    for (size_t i = 0; i < vParents.size(); i++) {
        if (vParents[i] != parents[i])
            return state.DoS(100, error("clue parent not match %s != %s", EncodeDestination(vParents[i]),
                                        EncodeDestination(parents[i])), REJECT_MALFORMED, "bad-clue-tree-order");
    }

    return true;
}

bool ContextualCheckClueTransaction(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, const CClueViewCache& clueinputs, const Consensus::Params& consensusParams, const int nHeight)
{
    CAmount clueParentFee = 0;
    CAmount totalIn = 0;
    bool fFirstIn = true;
    CTxDestination firstAddr;
    for (auto in : tx.vin) {
        const Coin& coin = inputs.AccessCoin(in.prevout);

        const CTxOut& ptxout = coin.out;
        CTxDestination addressIn;
        if (!ExtractDestination(ptxout.scriptPubKey, addressIn)) {
            return state.DoS(100, error("ContextualCheckClueTransaction(): ExtractDestination failed"),
                             REJECT_INVALID, "bad-txns-vin-scriptPubkey-verification-failed");
        }
        if (fFirstIn) {
            firstAddr = addressIn;
            fFirstIn = false;
        } else {
            if (firstAddr != addressIn)
                return state.DoS(100, error("ContextualCheckClueTransaction(): diffrent vin address."),
                                 REJECT_INVALID, "bad-txns-vin-scriptpubkey-diffrent");
        }

        totalIn += ptxout.nValue;
    }

    if (totalIn < CLUE_TOTAL)
        return state.DoS(100, error("CheckClueTransaction(): Input money not enough!"),
                         REJECT_INVALID, "input-money-not-enougth");

    int noClueOutCount = 0;
    CAmount totalOutValue = 0;
    CAmount totalClueSpent = 0;
    std::vector<CTxDestination> parents;
    int inviterCount = 0;

    for (int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        CTxDestination address;
        if (!ExtractDestination(out.scriptPubKey, address))
            return state.DoS(100, error("CheckClueTransaction(): ExtractDestination failed"),
                             REJECT_INVALID, "bad-txns-scriptPubkey-verification-failed");

        totalOutValue += out.nValue;
        if (out.nFlag == CTxOut::CLUE) {
            if (noClueOutCount != 0)
                return state.DoS(100, error("CheckClueTransaction(): Invalidate clue transaction vouts struction."),
                                 REJECT_INVALID, "invalid-clue-txout-struction");

            if (i == 0) {
                if (clueinputs.ChildrenSize(address) >= consensusParams.nClueChildrenWidth)
                    return state.DoS(0, error("CheckClueTransaction(): parent is full."),
                                     REJECT_INVALID, "bad-txns-clue-parent-full");
            }

            if (i > 0 && !clueinputs.HaveClue(address)) {
                return state.DoS(1, error("CheckClueTransaction(): parent is not clued."),
                                 REJECT_INVALID, "bad-txns-clue-parent");
            }


            parents.push_back(address);

            totalClueSpent += out.nValue;
            if (out.nValue == CLUE_COST_PARENT_NOAWARWD || out.nValue == CLUE_COST_PARENT_TOP) {
                if (inviterCount > 0)
                    return state.DoS(100, error("CheckClueTransaction(): Too many directly parent"),
                                     REJECT_INVALID, "too-many-directly-parent");

                inviterCount++;
            } else if (out.nValue != 0 && out.nValue != CLUE_COST_PARENT) {
                return state.DoS(100, error("CheckClueTransaction(): Invalidate money for clue vout"),
                                 REJECT_INVALID, "invalidate-clue-money");
            }

            clueParentFee += out.nValue;
            if (parents.size() == 0)
                return state.DoS(100, error("CheckClueTransaction(): Invalidate vout order, clue vout must before normal vout"),
                                 REJECT_INVALID, "bad-clue-vout-order-verification-failed");
        } else
            noClueOutCount++;
    }

    if (inviterCount < 1)
        return state.DoS(100, error("CheckClueTransaction(): No direct parent."),
                         REJECT_INVALID, "no-direct-parents");

    if (parents.size() < 1)
        return state.DoS(100, error("CheckClueTransaction(): No clue parents."),
                         REJECT_INVALID, "no-clue-parents");

    CAmount fee = totalIn - totalOutValue;
//check miner value and fee
    if (fee < CLUE_COST_FEE)
        return state.DoS(100, error("CheckClueTransaction(): invalidate fee for clue tx"),
                         REJECT_INVALID, "bad-clue-fee");

    if (fee + totalClueSpent < CLUE_TOTAL)
        return state.DoS(100, error("CheckClueTransaction(): Spent for clue tx must be 10"),
                         REJECT_INVALID, "bad-clue-total-spent");


    if (clueinputs.HaveClue(firstAddr) || IsClueRoot(firstAddr, nHeight))
        return state.DoS(100, error("CheckClueTransaction(): address invalid failed"),
                         REJECT_INVALID, "bad-txns-vin-address-clued");

    if (parents.size() == 1 && IsClueRoot(parents[0], nHeight))
        return true;

//check exist clue tree
    if (!CheckClueParentsRelationship(parents, state, clueinputs))
        return false;

    return true;
}

bool ContextualCheckInputs(const CTransaction& tx,
                           CValidationState& state,
                           const CCoinsViewCache& inputs,
                           const CClueViewCache& clueinputs,
                           bool fScriptChecks,
                           unsigned int flags,
                           bool cacheStore,
                           PrecomputedTransactionData& txdata,
                           const Consensus::Params& consensusParams,
                           std::vector<CScriptCheck>* pvChecks)
{
    CAmount fee;
    if (!Consensus::CheckTxInputs(tx, state, inputs, clueinputs, GetSpendHeight(inputs), consensusParams, fee))
        return false;

    if (!tx.IsCoinBase()) {
        if (pvChecks)
            pvChecks->reserve(tx.vin.size());

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.

        // Skip ECDSA signature verification when connecting blocks
        // before the last block chain checkpoint. This is safe because block merkle hashes are
        // still computed and checked, and any change will be caught at the next checkpoint.
        if (fScriptChecks) {
            for (unsigned int i = 0; i < tx.vin.size(); i++) {
                const COutPoint& prevout = tx.vin[i].prevout;
                const Coin& coin = inputs.AccessCoin(prevout);
                assert(!coin.IsSpent());

                // Verify signature
                CScriptCheck check(coin.out.scriptPubKey, coin.out.nValue, tx, i, flags, cacheStore, &txdata);
                if (pvChecks) {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                } else if (!check()) {
                    if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                        // Check whether the failure was caused by a
                        // non-mandatory script verification check, such as
                        // non-standard DER encodings or non-null dummy
                        // arguments; if so, don't trigger DoS protection to
                        // avoid splitting the network between upgraded and
                        // non-upgraded nodes.
                        CScriptCheck check2(coin.out.scriptPubKey, coin.out.nValue, tx, i,
                                            flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, cacheStore, &txdata);
                        if (check2())
                            return state.Invalid(false, REJECT_NONSTANDARD, strprintf("non-mandatory-script-verify-flag (%s)", ScriptErrorString(check.GetScriptError())));
                    }
                    // Failures of other flags indicate a transaction that is
                    // invalid in new blocks, e.g. a invalid P2SH. We DoS ban
                    // such nodes as they are not following the protocol. That
                    // said during an upgrade careful thought should be taken
                    // as to the correct behavior - we may want to continue
                    // peering with non-upgraded nodes even after a soft-fork
                    // super-majority vote has passed.
                    return state.DoS(100, false, REJECT_INVALID, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(check.GetScriptError())));
                }
            }
        }
    }

    return true;
}

namespace
{

bool UndoWriteToDisk(const CBlockUndo& blockundo, CDiskBlockPos& pos, const uint256& hashBlock, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Write index header
    unsigned int nSize = GetSerializeSize(fileout, blockundo);

    fileout << FLATDATA(messageStart) << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("%s: ftell failed", __func__);
    pos.nPos = (unsigned int) fileOutPos;
    fileout << blockundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    fileout << hasher.GetHash();

    return true;
}

bool UndoReadFromDisk(CBlockUndo& blockundo, const CDiskBlockPos& pos, const uint256& hashBlock)
{
    // Open history file to read
    CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: OpenBlockFile failed", __func__);

    // Read block
    uint256 hashChecksum;
    try {
        filein >> blockundo;
        filein >> hashChecksum;
    }    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    if (hashChecksum != hasher.GetHash())
        return error("%s: Checksum mismatch", __func__);

    return true;
}

/** Abort with a message */
bool AbortNode(const std::string& strMessage, const std::string& userMessage = "")
{
    strMiscWarning = strMessage;
    LogPrintf("*** %s\n", strMessage);
    uiInterface.ThreadSafeMessageBox(
        userMessage.empty() ? _("Error: A fatal internal error occurred, see debug.log for details") : userMessage,
        "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
    return false;
}

bool AbortNode(CValidationState& state, const std::string& strMessage, const std::string& userMessage = "")
{
    AbortNode(strMessage, userMessage);
    return state.Error(strMessage);
}

} // anon namespace

enum DisconnectResult {
    DISCONNECT_OK, // All good.
    DISCONNECT_UNCLEAN, // Rolled back, but UTXO set was inconsistent with block.
    DISCONNECT_FAILED // Something else went wrong.
};

/**
 * Restore the UTXO in a Coin at a given COutPoint
 * @param undo The Coin to be restored.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return A DisconnectResult as an int
 */
int ApplyTxInUndo(Coin&& undo, CCoinsViewCache& view, const COutPoint& out)
{
    bool fClean = true;

    if (view.HaveCoin(out)) fClean = false; // overwriting transaction output

    if (undo.nHeight == 0) {
        // Missing undo metadata (height and coinbase). Older versions included this
        // information only in undo records for the last spend of a transactions'
        // outputs. This implies that it must be present for some other output of the same tx.
        const Coin& alternate = AccessByTxid(view, out.hash);
        if (!alternate.IsSpent()) {
            undo.nHeight = alternate.nHeight;
            undo.fCoinBase = alternate.fCoinBase;
        } else {
            return DISCONNECT_FAILED; // adding output for transaction without known metadata
        }
    }
    view.AddCoin(out, std::move(undo), undo.fCoinBase);

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}


/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  When UNCLEAN or FAILED is returned, view is left in an indeterminate state. */
static DisconnectResult DisconnectBlock(const CBlock& block, CValidationState& state, const CBlockIndex* pindex, CCoinsViewCache& view, CClueViewCache& clueview)
{
    assert(pindex->GetBlockHash() == view.GetBestBlock());
    assert(pindex->GetBlockHash() == clueview.GetBestBlock());

    bool fClean = true;

    CBlockUndo blockUndo;
    CDiskBlockPos pos = pindex->GetUndoPos();

    if (pos.IsNull()) {
        error("DisconnectBlock(): no undo data available");
        return DISCONNECT_FAILED;
    }
    if (!UndoReadFromDisk(blockUndo, pos, pindex->pprev->GetBlockHash())) {
        error("DisconnectBlock(): failure reading undo data");
        return DISCONNECT_FAILED;
    }

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {
        error("DisconnectBlock(): block and undo data inconsistent");
        return DISCONNECT_FAILED;
    }

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > addressUnspentIndex;
    std::vector<std::pair<CSpentIndexKey, CSpentIndexValue> > spentIndex;

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction& tx = *(block.vtx[i]);
        uint256 hash = tx.GetHash();
        bool is_coinbase = tx.IsCoinBase();

        for (unsigned int k = tx.vout.size(); k-- > 0;) {
            const CTxOut& out = tx.vout[k];

            uint160 hashBytes;
            txnouttype addressType = TX_NONSTANDARD;
            if (GetIndexKey(out.scriptPubKey, hashBytes, addressType)) {
                // undo receiving activity
                addressIndex.push_back(std::make_pair(CAddressIndexKey(addressType, uint160(hashBytes), pindex->nHeight, i, hash, k, false), out.nValue));

                // undo unspent index
                addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(addressType, uint160(hashBytes), hash, k), CAddressUnspentValue()));

            } else {
                continue;
            }

        }


        // Check that all outputs are available and match the outputs in the block itself
        // exactly.
        for (size_t o = 0; o < tx.vout.size(); o++) {
            if (!tx.vout[o].scriptPubKey.IsUnspendable()) {
                COutPoint out(hash, o);
                Coin coin;
                bool is_spent = view.SpendCoin(out, &coin);
                if (!is_spent || tx.vout[o] != coin.out || pindex->nHeight != coin.nHeight || is_coinbase != coin.fCoinBase) {
                    fClean = false; // transaction output mismatch
                }
            }
        }

        // unspend nullifiers
        view.SetNullifiers(tx, false);

        // restore inputs
        if (i > 0) { // not coinbases
            CTxUndo& txundo = blockUndo.vtxundo[i - 1];
            if (txundo.vprevout.size() != tx.vin.size()) {
                error("DisconnectBlock(): transaction and undo data inconsistent");
                return DISCONNECT_FAILED;
            }

            //rescan vid weekly statistics data

            for (unsigned int j = tx.vin.size(); j-- > 0;) {
                const COutPoint& out = tx.vin[j].prevout;
                int undoHeight = txundo.vprevout[j].nHeight;
                int res = ApplyTxInUndo(std::move(txundo.vprevout[j]), view, out);
                if (res == DISCONNECT_FAILED) return DISCONNECT_FAILED;
                fClean = fClean && res != DISCONNECT_UNCLEAN;

                const CTxIn input = tx.vin[j];

                const Coin& coin = view.AccessCoin(tx.vin[j].prevout);
                const CTxOut& prevout = coin.out;

                if (tx.nFlag == CTransaction::TANDIA_TX) {
                    for (std::vector<CTxOut>::const_iterator it = tx.vout.begin(); it < tx.vout.end(); it++) {
                        if (it->nFlag == CTxOut::TANDIA) {
                            if (!pTandia->UndoVote(pindex->nHeight, prevout.scriptPubKey, it->scriptPubKey, hash))
                                fClean = DISCONNECT_UNCLEAN;
                        }
                    }
                }

                spentIndex.push_back(std::make_pair(CSpentIndexKey(input.prevout.hash, input.prevout.n), CSpentIndexValue()));

                uint160 hashBytes;
                txnouttype addressType = TX_NONSTANDARD;
                if (GetIndexKey(prevout.scriptPubKey, hashBytes, addressType)) {
                    // undo spending activity
                    addressIndex.push_back(std::make_pair(CAddressIndexKey(addressType, uint160(hashBytes), pindex->nHeight, i, hash, j, true), prevout.nValue * -1));

                    // restore unspent index
                    addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(addressType, uint160(hashBytes), input.prevout.hash, input.prevout.n), CAddressUnspentValue(prevout.nValue, prevout.scriptPubKey, undoHeight)));

                } else {
                    continue;
                }

            }
            // CAUTION: here must after coinsview update.
            if (tx.IsCoinClue()) {
                UndoClue(tx, state, view, clueview, pindex->nHeight, pindex->GetBlockHash());
            }

            if (tx.nFlag == CTransaction::BID_TX) {
                if (paddb->HaveAd(tx.GetHash())) {
                    CAd adRead;
                    paddb->ReadAd(tx.GetHash(), adRead);
                    paddb->Erase(tx.GetHash());
                    if (adRead.txid == g_AdKing.txid) {
                        g_AdKing.SetNull();
                        paddb->EraseAdKing();
                        if (!paddb->GetAdKingLast(g_AdKing)) {
                            UpdateAdKing();
                        } else {
                            paddb->WriteAdKing(g_AdKing.txid);
                        }
                    }
                }

                if (paddb->HaveAd(pindex->nHeight)) {
                    paddb->Erase(pindex->nHeight);
                }
            }
        }
    }

    view.PopAnchor(pindex->pprev->hashFinalSaplingRoot, SAPLING);

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev->GetBlockHash());
    clueview.SetBestBlock(pindex->pprev->GetBlockHash());

    globalState->setRoot(uintToh256(pindex->pprev->hashStateRoot)); // qtum
    globalState->setRootUTXO(uintToh256(pindex->pprev->hashUTXORoot)); // qtum

    if (!pblocktree->EraseAddressIndex(addressIndex)) {
        AbortNode("Failed to delete address index");
        return DISCONNECT_FAILED;
    }
    if (!pblocktree->UpdateAddressUnspentIndex(addressUnspentIndex)) {
        AbortNode("Failed to write address unspent index");
        return DISCONNECT_FAILED;
    }

    if (!pblocktree->EraseAnonymousBlock(pindex->GetBlockHash())) {
        AbortNode(state, "Failed to delete anonymous block index");
        return DISCONNECT_FAILED;
    }

    if (fClean) {
        return DISCONNECT_OK;
    }

    return DISCONNECT_UNCLEAN;
}

void static FlushBlockFile(bool fFinalize = false)
{
    LOCK(cs_LastBlockFile);

    CDiskBlockPos posOld(nLastBlockFile, 0);

    FILE* fileOld = OpenBlockFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }

    fileOld = OpenUndoFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nUndoSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }
}

bool FindUndoPos(CValidationState& state, int nFile, CDiskBlockPos& pos, unsigned int nAddSize);

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck()
{
    RenameThread("vds-scriptch");
    scriptcheckqueue.Thread();
}

//
// Called periodically asynchronously; alerts if it smells like
// we're being fed a bad chain (blocks being generated much
// too slowly or too quickly).
//

void PartitionCheck(bool (*initialDownloadCheck)(), CCriticalSection& cs, const CBlockIndex* const& bestHeader,
                    int64_t nPowTargetSpacing)
{
    if (bestHeader == NULL || initialDownloadCheck()) return;

    static int64_t lastAlertTime = 0;
    int64_t now = GetAdjustedTime();
    if (lastAlertTime > now - 60 * 60 * 24) return; // Alert at most once per day

    const int SPAN_HOURS = 4;
    const int SPAN_SECONDS = SPAN_HOURS * 60 * 60;
    int BLOCKS_EXPECTED = SPAN_SECONDS / nPowTargetSpacing;

    boost::math::poisson_distribution<double> poisson(BLOCKS_EXPECTED);

    std::string strWarning;
    int64_t startTime = GetAdjustedTime() - SPAN_SECONDS;

    LOCK(cs);
    const CBlockIndex* i = bestHeader;
    int nBlocks = 0;
    while (i->GetBlockTime() >= startTime) {
        ++nBlocks;
        i = i->pprev;
        if (i == NULL) return; // Ran out of chain, we must not be fully sync'ed
    }

    // How likely is it to find that many by chance?
    double p = boost::math::pdf(poisson, nBlocks);

    LogPrint("partitioncheck", "%s : Found %d blocks in the last %d hours\n", __func__, nBlocks, SPAN_HOURS);
    LogPrint("partitioncheck", "%s : likelihood: %g\n", __func__, p);

    // Aim for one false-positive about every fifty years of normal running:
    const int FIFTY_YEARS = 50 * 365 * 24 * 60 * 60;
    double alertThreshold = 1.0 / (FIFTY_YEARS / SPAN_SECONDS);

    if (p <= alertThreshold && nBlocks < BLOCKS_EXPECTED) {
        // Many fewer blocks than expected: alert!
        strWarning = strprintf(_("WARNING: check your network connection, %d blocks received in the last %d hours (%d expected)"),
                               nBlocks, SPAN_HOURS, BLOCKS_EXPECTED);
    } else if (p <= alertThreshold && nBlocks > BLOCKS_EXPECTED) {
        // Many more blocks than expected: alert!
        strWarning = strprintf(_("WARNING: abnormally high number of blocks generated, %d blocks received in the last %d hours (%d expected)"),
                               nBlocks, SPAN_HOURS, BLOCKS_EXPECTED);
    }
    if (!strWarning.empty()) {
        strMiscWarning = strWarning;
        CAlert::Notify(strWarning, true);
        lastAlertTime = now;
    }
}

static int64_t nTimeVerify = 0;
static int64_t nTimeConnect = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeCallbacks = 0;
static int64_t nTimeTotal = 0;

/////////////////////////////////////////////////////////////////////// qtum

bool CheckSenderScript(const CCoinsViewCache& view, const CTransaction& tx)
{
    CScript script = view.AccessCoin(tx.vin[0].prevout).out.scriptPubKey;
    if (!script.IsPayToPublicKeyHash() && !script.IsPayToPubkey()) {
        return false;
    }
    return true;
}

std::vector<ResultExecute> CallContract(const dev::Address& addrContract, std::vector<unsigned char> opcode, const dev::Address& sender, uint64_t gasLimit)
{
    CBlock block;
    CMutableTransaction tx;

    CBlockIndex* pblockindex = mapBlockIndex[chainActive.Tip()->GetBlockHash()];
    ReadBlockFromDisk(block, pblockindex, Params().GetConsensus());
    block.nTime = GetAdjustedTime();

    block.vtx.erase(block.vtx.begin() + 1, block.vtx.end());


    QtumDGP qtumDGP(globalState.get(), fGettingValuesDGP);
    uint64_t blockGasLimit = qtumDGP.getBlockGasLimit(chainActive.Tip()->nHeight + 1);

    if (gasLimit == 0) {
        gasLimit = blockGasLimit - 1;
    }
    dev::Address senderAddress = sender == dev::Address() ? dev::Address("ffffffffffffffffffffffffffffffffffffffff") : sender;
    tx.vout.push_back(CTxOut(0, CTxOut::NORMAL, CScript() << OP_DUP << OP_HASH160 << senderAddress.asBytes() << OP_EQUALVERIFY << OP_CHECKSIG));
    block.vtx.push_back(MakeTransactionRef(CTransaction(tx)));

    QtumTransaction callTransaction(0, 1, dev::u256(gasLimit), addrContract, opcode, dev::u256(0));
    callTransaction.forceSender(senderAddress);
    callTransaction.setVersion(VersionVM::GetEVMDefault());


    ByteCodeExec exec(block, std::vector<QtumTransaction>(1, callTransaction), blockGasLimit);
    exec.performByteCode(dev::eth::Permanence::Reverted);
    return exec.getResult();
}

bool CheckMinGasPrice(std::vector<EthTransactionParams>& etps, const uint64_t& minGasPrice)
{
    for (EthTransactionParams& etp : etps) {
        if (etp.gasPrice < dev::u256(minGasPrice))
            return false;
    }
    return true;
}

bool CheckReward(const CBlock& block, CValidationState& state, CBlockIndex* pindex, const std::vector<CTxOut>& vouts, CAmount toMiner, CAmount toMasterNode, const CAmount toVibPool, const bool fPaidTandia, CAmount toTandia, const CAmount nToMasterNodeAll)
{
    size_t offset = 0;
    CAmount toMinerPaid = 0;
    CAmount toMasterNodePaid = 0;
    CAmount toVibPoolPaid = 0;
    CAmount toVibPaid = 0;
    bool fPaidTandiaPaid = false;
    CAmount toTandiaPaid = 0;

    std::vector<CTxOut> vTempVouts = block.vtx[offset]->vout;
    std::vector<CTxOut>::iterator it;
    std::vector<CScript>::iterator mit;

    const Consensus::Params& consensus = Params().GetConsensus();
    GetCoinBasePaidOut(pindex, block, toMinerPaid, toMasterNodePaid, toVibPoolPaid, fPaidTandiaPaid, toTandiaPaid, toVibPaid);

    CScript mnscript;
    bool bGetList = mnpayments.GetBlockPayee(pindex->nHeight, mnscript);
    bool fMnPaid = false;

    /* Caution: this vouts only conract refunds */
    for (size_t i = 0; i < vouts.size(); i++) {
        it = std::find(vTempVouts.begin(), vTempVouts.end(), vouts[i]);
        if (it == vTempVouts.end()) {
            return state.DoS(100, error("CheckReward(): Gas refund missing"));
        } else {
            vTempVouts.erase(it);
        }
    }

    for (size_t i = 0; i < block.vtx[0]->vout.size(); i++) {
        const CTxOut& vout = block.vtx[0]->vout[i];

        if (!IsInitialBlockDownload() && !fReindex && !fImporting && bGetList) {
            if (vout.nFlag == CTxOut::MASTERNODE) {
                fMnPaid = true;
                if (!mnpayments.IsPayeeValid(vout.scriptPubKey, pindex->nHeight))
                    return state.DoS(50, error("CheckReward(): masternode paid to unknonw masternode."));
            }
        }

        if (vout.nFlag == CTxOut::TANDIA) {
            CScript tandiascript = GetTandiaScript(pindex->nHeight, pindex->pprev->nLastPaidTandia + 1);
            if (vout.scriptPubKey != tandiascript)
                return state.DoS(100, error("CheckReward(): tandia paid to incorrect script."));
        }

        if (vout.nFlag == CTxOut::NORMAL && pindex->nHeight == consensus.nFounderPayHeight) {
            const CScript founderScript = CScript(consensus.nFounderScript.begin(), consensus.nFounderScript.end());
            if (vout.scriptPubKey != founderScript || vout.nValue != consensus.nFounderAmount )
                return state.DoS(100, error("CheckReward(): founder payment invalid."));
        }
    }

    if (toMasterNodePaid == 0) {
        toMiner += (nToMasterNodeAll * 14 / 20);
        toTandia += (nToMasterNodeAll - nToMasterNodeAll * 14 / 20);
    } else {
        toMasterNode += nToMasterNodeAll;
    }


    if (fPaidTandia != fPaidTandiaPaid)
        return state.DoS(100,
                         error("CheckReward(): coinbase paid tandia mismatch (actual=%s vs limit=%s",
                               fPaidTandiaPaid ? "true" : "false", fPaidTandia ? "true" : "false"),
                         REJECT_INVALID, "bad-cb-tandia");

    if (fPaidTandia && toTandiaPaid != toTandia)
        return state.DoS(100,
                         error("CheckReward(): coinbase paid tandia mismatch (actual=%d vs limit=%d",
                               toTandiaPaid, toTandia),
                         REJECT_INVALID, "bad-cb-tandia-amount");

    LogPrint("validation", "Block: %s, CBlockIndex: %d\n", block.GetHash().GetHex(), pindex->nHeight);
    if (!fPaidTandiaPaid) {
        pindex->nDebtTandia = toTandia;
        pindex->nHeightTandiaPaid = pindex->pprev->nHeightTandiaPaid;
        pindex->nLastPaidTandia = pindex->pprev->nLastPaidTandia;
    } else {
        pindex->nDebtTandia = toTandia - toTandiaPaid;
        pindex->nHeightTandiaPaid = pindex->nHeight;
        pindex->nLastPaidTandia = pindex->pprev->nLastPaidTandia + 1;
    }


    if (!IsInitialBlockDownload() && !fReindex && !fImporting && fMnPaid) {
        if (toMinerPaid != toMiner)
            return state.DoS(100,
                             error("CheckReward(): coinbase paid miner mismatch (actual=%d vs limit=%d",
                                   toMinerPaid, toMiner),
                             REJECT_INVALID, "bad-cb-miner");

        if (toMasterNodePaid != toMasterNode)
            return state.DoS(100,
                             error("CheckReward(): coinbase paid masternode mismatch (actual=%d vs limit=%d",
                                   toMasterNodePaid, toMasterNode),
                             REJECT_INVALID, "bad-cb-masternode");
    }

    if (toMinerPaid + toMasterNodePaid != toMiner + toMasterNode)
        return state.DoS(100,
                         error("CheckReward(): coinbase paid miner or masternode mismatch (actual=%d vs limit=%d",
                               toMinerPaid + toMasterNodePaid, toMiner + toMasterNode),
                         REJECT_INVALID, "bad-cb-miner-masternode");

    if (toVibPoolPaid != toVibPool)
        return state.DoS(100,
                         error("CheckReward(): coinbase paid vibpool mismatch (actual=%d vs limit=%d",
                               toVibPoolPaid, toVibPool),
                         REJECT_INVALID, "bad-cb-vib");
    return true;
}

valtype GetSenderAddress(const CTransaction& tx, const CCoinsViewCache* coinsView, const std::vector<CTransactionRef>* blockTxs)
{
    CScript script;
    bool scriptFilled = false; //can't use script.empty() because an empty script is technically valid

    // First check the current (or in-progress) block for zero-confirmation change spending that won't yet be in txindex
    if (blockTxs) {
        for (auto btx : *blockTxs) {
            if (!btx)
                continue;
            if (btx->GetHash() == tx.vin[0].prevout.hash) {
                script = btx->vout[tx.vin[0].prevout.n].scriptPubKey;
                scriptFilled = true;
                break;
            }
        }
    }
    if (!scriptFilled && coinsView) {
        script = coinsView->AccessCoin(tx.vin[0].prevout).out.scriptPubKey;
        scriptFilled = true;
    }
    if (!scriptFilled) {
        CTransactionRef txPrevout;
        uint256 hashBlock;
        if (GetTransaction(tx.vin[0].prevout.hash, txPrevout, Params().GetConsensus(), hashBlock, true)) {
            script = txPrevout->vout[tx.vin[0].prevout.n].scriptPubKey;
        } else {
            LogPrintf("Error fetching transaction details of tx %s. This will probably cause more errors", tx.vin[0].prevout.hash.ToString());
            return valtype();
        }
    }

    CTxDestination addressBit;
    txnouttype txType = TX_NONSTANDARD;
    if (ExtractDestination(script, addressBit, &txType)) {
        if ((txType == TX_PUBKEY || txType == TX_PUBKEYHASH) &&
                addressBit.type() == typeid (CKeyID)) {
            CKeyID senderAddress(boost::get<CKeyID>(addressBit));
            return valtype(senderAddress.begin(), senderAddress.end());
        }
    }
    //prevout is not a standard transaction format, so just return 0
    return valtype();
}

UniValue vmLogToJSON(const ResultExecute& execRes, const CTransaction& tx, const CBlock& block)
{
    UniValue result(UniValue::VOBJ);
    if (tx != CTransaction())
        result.push_back(Pair("txid", tx.GetHash().GetHex()));
    result.push_back(Pair("address", execRes.execRes.newAddress.hex()));
    if (block.GetHash() != CBlock().GetHash()) {
        result.push_back(Pair("time", block.GetBlockTime()));
        result.push_back(Pair("blockhash", block.GetHash().GetHex()));
        result.push_back(Pair("blockheight", chainActive.Tip()->nHeight + 1));
    } else {
        result.push_back(Pair("time", GetAdjustedTime()));
        result.push_back(Pair("blockheight", chainActive.Tip()->nHeight));
    }
    UniValue logEntries(UniValue::VARR);
    dev::eth::LogEntries logs = execRes.txRec.log();
    for (dev::eth::LogEntry log : logs) {
        UniValue logEntrie(UniValue::VOBJ);
        logEntrie.push_back(Pair("address", log.address.hex()));
        UniValue topics(UniValue::VARR);
        for (dev::h256 l : log.topics) {
            UniValue topicPair(UniValue::VOBJ);
            topicPair.push_back(Pair("raw", l.hex()));
            topics.push_back(topicPair);
            //TODO add "pretty" field for human readable data
        }
        UniValue dataPair(UniValue::VOBJ);
        dataPair.push_back(Pair("raw", HexStr(log.data)));
        logEntrie.push_back(Pair("data", dataPair));
        logEntrie.push_back(Pair("topics", topics));
        logEntries.push_back(logEntrie);
    }
    result.push_back(Pair("entries", logEntries));
    return result;
}

void writeVMlog(const std::vector<ResultExecute>& res, const CTransaction& tx, const CBlock& block)
{
    boost::filesystem::path qtumDir = GetDataDir() / "vmExecLogs.json";
    std::stringstream ss;
    if (fIsVMlogFile) {
        ss << ",";
    } else {
        std::ofstream file(qtumDir.string(), std::ios::out | std::ios::app);
        file << "{\"logs\":[]}";
        file.close();
    }

    for (size_t i = 0; i < res.size(); i++) {
        ss << vmLogToJSON(res[i], tx, block).write();
        if (i != res.size() - 1) {
            ss << ",";
        } else {
            ss << "]}";
        }
    }

    std::ofstream file(qtumDir.string(), std::ios::in | std::ios::out);
    file.seekp(-2, std::ios::end);
    file << ss.str();
    file.close();
    fIsVMlogFile = true;
}

CTxDestination getAddressForVin(const CTransaction& tx, bool& found)
{
    found = false;
    CTransactionRef preTx;
    uint256 blockHash;
    if (!GetTransaction(tx.vin[0].prevout.hash, preTx, Params().GetConsensus(), blockHash, false)) {
        return CNoDestination();
    }
    CTxOut ptxout = preTx->vout[tx.vin[0].prevout.n];
    CTxDestination addressIn;
    if (!ExtractDestination(ptxout.scriptPubKey, addressIn))
        return CNoDestination();

    found = true;
    return addressIn;
}

bool ByteCodeExec::performByteCode(dev::eth::Permanence type)
{
    for (QtumTransaction& tx : txs) {
        //validate VM version
        if (tx.getVersion().toRaw() != VersionVM::GetEVMDefault().toRaw()) {
            return false;
        }
        dev::eth::EnvInfo envInfo(BuildEVMEnvironment());
        if (!tx.isCreation() && !globalState->addressInUse(tx.receiveAddress())) {
            dev::eth::ExecutionResult execRes;
            execRes.excepted = dev::eth::TransactionException::Unknown;
            result.push_back(ResultExecute{execRes, dev::eth::TransactionReceipt(dev::h256(), dev::u256(), dev::eth::LogEntries()), CTransaction()});
            continue;
        }
        result.push_back(globalState->execute(envInfo, *globalSealEngine.get(), tx, type, OnOpFunc()));
    }
    globalState->db().commit();
    globalState->dbUtxo().commit();
    globalSealEngine.get()->deleteAddresses.clear();
    return true;
}

bool ByteCodeExec::processingResults(ByteCodeExecResult& resultBCE)
{
    for (size_t i = 0; i < result.size(); i++) {
        uint64_t gasUsed = (uint64_t) result[i].execRes.gasUsed;
        if (result[i].execRes.excepted != dev::eth::TransactionException::None) {
            if (txs[i].value() > 0) {
                CMutableTransaction tx;
                tx.vin.push_back(CTxIn(h256Touint(txs[i].getHashWith()), txs[i].getNVout(), CScript() << OP_SPEND));
                CScript script(CScript() << OP_DUP << OP_HASH160 << txs[i].sender().asBytes() << OP_EQUALVERIFY << OP_CHECKSIG);
                tx.vout.push_back(CTxOut(CAmount(txs[i].value()), CTxOut::NORMAL, script));
                resultBCE.valueTransfers.push_back(CTransaction(tx));
            }
            resultBCE.usedGas += gasUsed;
        } else {
            if (txs[i].gas() > UINT64_MAX ||
                    result[i].execRes.gasUsed > UINT64_MAX ||
                    txs[i].gasPrice() > UINT64_MAX) {
                return false;
            }
            uint64_t gas = (uint64_t) txs[i].gas();
            uint64_t gasPrice = (uint64_t) txs[i].gasPrice();

            resultBCE.usedGas += gasUsed;
            int64_t amount = (gas - gasUsed) * gasPrice;
            if (amount < 0) {
                return false;
            }
            if (amount > 0) {
                CScript script(CScript() << OP_DUP << OP_HASH160 << txs[i].sender().asBytes() << OP_EQUALVERIFY << OP_CHECKSIG);
                resultBCE.refundOutputs.push_back(CTxOut(amount, CTxOut::REFUND, script));
                resultBCE.refundSender += amount;
            }
        }
        if (result[i].tx != CTransaction()) {
            resultBCE.valueTransfers.push_back(result[i].tx);
        }
    }
    return true;
}

dev::eth::EnvInfo ByteCodeExec::BuildEVMEnvironment()
{
    dev::eth::EnvInfo env;
    CBlockIndex* tip = chainActive.Tip();
    env.setNumber(dev::u256(tip->nHeight + 1));
    env.setTimestamp(dev::u256(block.nTime));
    env.setDifficulty(dev::u256(block.nBits));

    dev::eth::LastHashes lh;
    lh.resize(256);
    for (int i = 0; i < 256; i++) {
        if (!tip)
            break;
        lh[i] = uintToh256(*tip->phashBlock);
        tip = tip->pprev;
    }
    env.setLastHashes(std::move(lh));
    env.setGasLimit(blockGasLimit);
    env.setAuthor(EthAddrFromScript(block.vtx[0]->vout[0].scriptPubKey));
    return env;
}

dev::Address ByteCodeExec::EthAddrFromScript(const CScript& script)
{
    CTxDestination addressBit;
    txnouttype txType = TX_NONSTANDARD;
    if (ExtractDestination(script, addressBit, &txType)) {
        if ((txType == TX_PUBKEY || txType == TX_PUBKEYHASH) &&
                addressBit.type() == typeid (CKeyID)) {
            CKeyID addressKey(boost::get<CKeyID>(addressBit));
            std::vector<unsigned char> addr(addressKey.begin(), addressKey.end());
            return dev::Address(addr);
        }
    }
    //if not standard or not a pubkey or pubkeyhash output, then return 0
    return dev::Address();
}

bool QtumTxConverter::extractionQtumTransactions(ExtractQtumTX& qtumtx)
{
    std::vector<QtumTransaction> resultTX;
    std::vector<EthTransactionParams> resultETP;
    for (size_t i = 0; i < txBit.vout.size(); i++) {
        if (txBit.vout[i].scriptPubKey.HasOpCreate() || txBit.vout[i].scriptPubKey.HasOpCall()) {
            if (receiveStack(txBit.vout[i].scriptPubKey)) {
                EthTransactionParams params;
                if (parseEthTXParams(params)) {
                    resultTX.push_back(createEthTX(params, i));
                    resultETP.push_back(params);
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
    }
    qtumtx = std::make_pair(resultTX, resultETP);
    return true;
}

bool QtumTxConverter::receiveStack(const CScript& scriptPubKey)
{
    EvalScript(stack, scriptPubKey, SCRIPT_EXEC_BYTE_CODE, BaseSignatureChecker(), SIGVERSION_BASE, nullptr);
    if (stack.empty())
        return false;

    CScript scriptRest(stack.back().begin(), stack.back().end());
    stack.pop_back();

    opcode = (opcodetype) (*scriptRest.begin());
    if ((opcode == OP_CREATE && stack.size() < 4) || (opcode == OP_CALL && stack.size() < 5)) {
        stack.clear();
        return false;
    }

    return true;
}

bool QtumTxConverter::parseEthTXParams(EthTransactionParams& params)
{
    try {
        dev::Address receiveAddress;
        valtype vecAddr;
        if (opcode == OP_CALL) {
            vecAddr = stack.back();
            stack.pop_back();
            receiveAddress = dev::Address(vecAddr);
        }
        if (stack.size() < 4)
            return false;

        if (stack.back().size() < 1) {
            return false;
        }
        valtype code(stack.back());
        stack.pop_back();
        uint64_t gasPrice = CScriptNum::vch_to_uint64(stack.back());
        stack.pop_back();
        uint64_t gasLimit = CScriptNum::vch_to_uint64(stack.back());
        stack.pop_back();
        if (gasPrice > INT64_MAX || gasLimit > INT64_MAX) {
            return false;
        }
        //we track this as CAmount in some places, which is an int64_t, so constrain to INT64_MAX
        if (gasPrice != 0 && gasLimit > INT64_MAX / gasPrice) {
            //overflows past 64bits, reject this tx
            return false;
        }
        if (stack.back().size() > 4) {
            return false;
        }
        VersionVM version = VersionVM::fromRaw((uint32_t) CScriptNum::vch_to_uint64(stack.back()));
        stack.pop_back();
        params.version = version;
        params.gasPrice = dev::u256(gasPrice);
        params.receiveAddress = receiveAddress;
        params.code = code;
        params.gasLimit = dev::u256(gasLimit);
        return true;
    }    catch (const scriptnum_error& err) {
        LogPrintf("Incorrect parameters to VM.");
        return false;
    }
}

QtumTransaction QtumTxConverter::createEthTX(const EthTransactionParams& etp, uint32_t nOut)
{
    QtumTransaction txEth;
    if (etp.receiveAddress == dev::Address() && opcode != OP_CALL) {
        txEth = QtumTransaction(txBit.vout[nOut].nValue, etp.gasPrice, etp.gasLimit, etp.code, dev::u256(0));
    } else {
        txEth = QtumTransaction(txBit.vout[nOut].nValue, etp.gasPrice, etp.gasLimit, etp.receiveAddress, etp.code, dev::u256(0));
    }
    dev::Address sender(GetSenderAddress(txBit, view, blockTransactions));
    txEth.forceSender(sender);
    txEth.setHashWith(uintToh256(txBit.GetHash()));
    txEth.setNVout(nOut);
    txEth.setVersion(etp.version);

    return txEth;
}
///////////////////////////////////////////////////////////////////////

bool ConnectBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex, CCoinsViewCache& view, CClueViewCache& clueview, bool fJustCheck)
{
    const CChainParams& chainparams = Params();
    const Consensus::Params& params = chainparams.GetConsensus();
    AssertLockHeld(cs_main);

    uint256 blockhash = block.GetHash();
    bool fExpensiveChecks = true;

    auto verifier = libzcash::ProofVerifier::Strict();
    auto disabledVerifier = libzcash::ProofVerifier::Disabled();

    // Check it again to verify JoinSplit proofs, and in case a previous version let a bad block in
    if (!CheckBlock(block, state, fExpensiveChecks ? verifier : disabledVerifier, !fJustCheck, !fJustCheck))
        return false;

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == nullptr ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());
    assert(hashPrevBlock == clueview.GetBestBlock());

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    for (const auto& tx : block.vtx) {
        for (size_t o = 0; o < tx->vout.size(); o++) {
            if (view.HaveCoin(COutPoint(tx->GetHash(), o))) {
                return state.DoS(100, error("ConnectBlock(): tried to overwrite transaction"),
                                 REJECT_INVALID, "bad-txns-BIP30");
            }
        }
    }

    unsigned int flags = SCRIPT_VERIFY_P2SH;

    if (block.nVersion >= 4) {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    CBlockUndo blockundo;

    CCheckQueueControl<CScriptCheck> control(fExpensiveChecks && nScriptCheckThreads ? &scriptcheckqueue : nullptr);

    int64_t nTimeStart = GetTimeMicros();

    ///////////////////////////////////////////////// // qtum
    QtumDGP qtumDGP(globalState.get(), fGettingValuesDGP);
    globalSealEngine->setQtumSchedule(qtumDGP.getGasSchedule(pindex->nHeight + 1));
    uint64_t minGasPrice = qtumDGP.getMinGasPrice(pindex->nHeight + 1);
    uint64_t blockGasLimit = qtumDGP.getBlockGasLimit(pindex->nHeight + 1);
    CBlock checkBlock(block.GetBlockHeader());
    std::vector<CTxOut> checkVouts; // here must coinbase, masternodes, free heart, refundgas

    uint64_t countCumulativeGasUsed = 0;
    /////////////////////////////////////////////////

    CAmount nFees = 0;
    int nInputs = 0;
    unsigned int nSigOps = 0;
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(block.vtx.size());
    blockundo.vtxundo.reserve(block.vtx.size() - 1);
    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > addressUnspentIndex;
    std::vector<std::pair<CSpentIndexKey, CSpentIndexValue> > spentIndex;

    SaplingMerkleTree sapling_tree;
    assert(view.GetSaplingAnchorAt(view.GetBestAnchor(SAPLING), sapling_tree));

    std::vector<PrecomputedTransactionData> txdata;
    txdata.reserve(block.vtx.size()); // Required so that pointers to individual PrecomputedTransactionData don't get invalidated

    ///////////////////////////////////////////////////////// // qtum
    std::map<dev::Address, std::pair<CHeightTxIndexKey, std::vector < uint256>>> heightIndexes;
    /////////////////////////////////////////////////////////
    uint64_t blockGasUsed = 0;
    CAmount gasRefunds = 0;
    CAmount toMiner = 0;
    CAmount toMasterNode = 0;
    CAmount nToMasterNodeAll = 0;
    CAmount toVibPool = 0;
    CAmount toVibPay = 0;
    bool fPaidTandia = false;
    CAmount toTandia = pindex->pprev ? pindex->pprev->nDebtTandia : 0;

    AnonymousBlock anonymousBlock;
    for (unsigned int i = 0; i < block.vtx.size(); i++) {
        const CTransaction& tx = *(block.vtx[i]);
        const uint256 txhash = tx.GetHash();

        nInputs += tx.vin.size();
        nSigOps += GetLegacySigOpCount(tx);
        if (nSigOps > MAX_BLOCK_SIGOPS)
            return state.DoS(100, error("ConnectBlock(): too many sigops"),
                             REJECT_INVALID, "bad-blk-sigops");

        bool hasOpSpend = tx.HasOpSpend();

        txdata.emplace_back(tx);

        if (!tx.IsCoinBase()) {
            if (!view.HaveInputs(tx))
                return state.DoS(100, error("ConnectBlock(): inputs missing/spent"),
                                 REJECT_INVALID, "bad-txns-inputs-missingorspent");

            // are the JoinSplit's requirements met?
            if (!view.HaveShieldedRequirements(tx))
                return state.DoS(100, error("ConnectBlock(): JoinSplit requirements not met"),
                                 REJECT_INVALID, "bad-txns-joinsplit-requirements-not-met");

            // Add in sigops done by pay-to-script-hash inputs;
            // this is to prevent a "rogue miner" from creating
            // an incredibly-expensive-to-validate block.
            nSigOps += GetP2SHSigOpCount(tx, view);
            if (nSigOps > MAX_BLOCK_SIGOPS)
                return state.DoS(100, error("ConnectBlock(): too many sigops"),
                                 REJECT_INVALID, "bad-blk-sigops");

            std::vector<CScriptCheck> vChecks;
            if (!ContextualCheckInputs(tx, state, view, clueview, fExpensiveChecks, flags, false, txdata[i], params, nScriptCheckThreads ? &vChecks : nullptr))
                return false;

            if (tx.IsCoinClue()) {
                // Clue Transaction total 0.5 Fee, 0.1 to miner, 0.1 to masternode, 0.3 to tandia
                if (!ContextualCheckClueTransaction(tx, state, view, clueview, Params().GetConsensus(), pindex->nHeight))
                    return false;
                CAmount clueAmount = 0;
                for (const auto& out : tx.vout) {
                    if (out.nFlag == CTxOut::CLUE)
                        clueAmount += out.nValue;
                }
                toMiner += CLUE_COST_MINER;
                toMasterNode += CLUE_COST_MASTER_NODE;
                toTandia += CLUE_COST_TANDIA;

                if (CLUE_TOTAL - clueAmount - CLUE_COST_FEE > 0) {
                    toVibPool += CLUE_TOTAL - clueAmount - CLUE_COST_FEE;
                }
            } else {
                if (tx.nFlag == CTransaction::BID_TX) {
                    for (const auto& out : tx.vout) {
                        if (out.nFlag == CTxOut::BID)
                            nToMasterNodeAll += out.nValue;
                    }
                }
                nFees += view.GetValueIn(tx) - tx.GetValueOut();
                for (const auto& out : tx.vout) {
                    if (out.scriptPubKey == feeAddress) {
                        toTandia += out.nValue / 2;
                        nToMasterNodeAll += out.nValue - (out.nValue / 2);
                    }
                }
            }

            if (tx.nFlag == CTransaction::TANDIA_TX) {
                for (auto out : tx.vout) {
                    if (out.nFlag == CTxOut::TANDIA) {
                        const Coin& coin = view.AccessCoin(tx.vin[0].prevout);
                        const CTxOut& prevout = coin.out;
                        if (!pTandia->AcceptVote(pindex->nHeight, prevout.scriptPubKey, out.scriptPubKey, txhash))
                            return state.DoS(100, error("ConnectBlock(): Tandia vote accept failed"),
                                             REJECT_INVALID, "bad-txns-tandia-vote-not-accept");
                    }
                }
            }

            if (tx.nFlag == CTransaction::BID_TX) {
                CAd adlocal;
                if (paddb->HaveAd(tx.GetHash())) {
                    paddb->ReadAd(tx.GetHash(), adlocal);
                }
                for (auto& out : tx.vout) {
                    if (out.nFlag == CTxOut::BID) {
                        const Coin& coin = view.AccessCoin(tx.vin[0].prevout);
                        if (coin.IsSpent()) {
                            return state.DoS(100, error("bad prevout in bid transaction"), REJECT_INVALID, "bad-bid-prevout");
                        }
                        CTxDestination dest;
                        if (!ExtractDestination(coin.out.scriptPubKey, dest)) {
                            return state.DoS(100, error("bad prevout in bid transaction"), REJECT_INVALID, "bad-bid-prevout-scriptpubkey");
                        }

                        // write current ad.
                        CAd ad(tx.GetHash(), pindex->nHeight, dest, "", out.nValue);
                        if (adlocal.admsg != "") {
                            ad.admsg = adlocal.admsg;
                        }
                        paddb->WriteAd(ad);
                        GetMainSignals().NotifyAdReceived(tx.GetHash(), ad);
                        uiInterface.NotifyAdReceived(tx.GetHash(), ad);
                    }
                }
            }


            for (size_t j = 0; j < tx.vin.size(); j++) {
                const CTxIn input = tx.vin[j];
                const Coin& coin = view.AccessCoin(tx.vin[j].prevout);
                const CTxOut& prevout = coin.out;
                uint160 hashBytes;
                txnouttype addressType = TX_NONSTANDARD;

                if (GetIndexKey(prevout.scriptPubKey, hashBytes, addressType)) {
                    // record spending activity
                    addressIndex.push_back(std::make_pair(CAddressIndexKey(addressType, hashBytes, pindex->nHeight, i, txhash, j, true), prevout.nValue * -1));

                    // remove address from unspent index
                    addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(addressType, hashBytes, input.prevout.hash, input.prevout.n), CAddressUnspentValue()));
                }


                // add the spent index to determine the txid and input that spent an output
                // and to find the amount and address from an input
                spentIndex.push_back(std::make_pair(CSpentIndexKey(input.prevout.hash, input.prevout.n), CSpentIndexValue(txhash, j, pindex->nHeight, prevout.nValue, addressType, hashBytes)));

            }


            control.Add(vChecks);
        }

        // update adking for last bid period.
        if (((pindex->nHeight % params.nBidPeriod) == 0) && (pindex->nHeight > 0)) {
            CAd lastad;
            if (paddb->ReadAd(pindex->nHeight - params.nBidPeriod, lastad)) {
                if (lastad.adValue > g_AdKing.adValue) {
                    UpdateAdKing(lastad);
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////////////////////// qtum
        if (!tx.HasOpSpend()) {
            checkBlock.vtx.push_back(block.vtx[i]);
        }
        if (tx.HasCreateOrCall() && !hasOpSpend) {

            if (!CheckSenderScript(view, tx)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-invalid-sender-script");
            }

            QtumTxConverter convert(tx, &view, &block.vtx);

            ExtractQtumTX resultConvertQtumTX;
            if (!convert.extractionQtumTransactions(resultConvertQtumTX)) {
                return state.DoS(100, error("ConnectBlock(): Contract transaction of the wrong format"), REJECT_INVALID, "bad-tx-bad-contract-format");
            }
            if (!CheckMinGasPrice(resultConvertQtumTX.second, minGasPrice))
                return state.DoS(100, error("ConnectBlock(): Contract execution has lower gas price than allowed"), REJECT_INVALID, "bad-tx-low-gas-price");


            dev::u256 gasAllTxs = dev::u256(0);
            ByteCodeExec exec(block, resultConvertQtumTX.first, blockGasLimit);
            //validate VM version and other ETH params before execution
            //Reject anything unknown (could be changed later by DGP)
            //TODO evaluate if this should be relaxed for soft-fork purposes
            bool nonZeroVersion = false;
            dev::u256 sumGas = dev::u256(0);
            CAmount nTxFee = view.GetValueIn(tx) - tx.GetValueOut();
            for (QtumTransaction& qtx : resultConvertQtumTX.first) {
                sumGas += qtx.gas() * qtx.gasPrice();

                if (sumGas > dev::u256(INT64_MAX)) {
                    return state.DoS(100, error("ConnectBlock(): Transaction's gas stipend overflows"), REJECT_INVALID, "bad-tx-gas-stipend-overflow");
                }

                if (sumGas > dev::u256(nTxFee)) {
                    return state.DoS(100, error("ConnectBlock(): Transaction fee does not cover the gas stipend"), REJECT_INVALID, "bad-txns-fee-notenough");
                }

                VersionVM v = qtx.getVersion();
                if (v.format != 0)
                    return state.DoS(100, error("ConnectBlock(): Contract execution uses unknown version format"), REJECT_INVALID, "bad-tx-version-format");
                if (v.rootVM != 0) {
                    nonZeroVersion = true;
                } else {
                    if (nonZeroVersion) {
                        //If an output is version 0, then do not allow any other versions in the same tx
                        return state.DoS(100, error("ConnectBlock(): Contract tx has mixed version 0 and non-0 VM executions"), REJECT_INVALID, "bad-tx-mixed-zero-versions");
                    }
                }
                if (!(v.rootVM == 0 || v.rootVM == 1))
                    return state.DoS(100, error("ConnectBlock(): Contract execution uses unknown root VM"), REJECT_INVALID, "bad-tx-version-rootvm");
                if (v.vmVersion != 0)
                    return state.DoS(100, error("ConnectBlock(): Contract execution uses unknown VM version"), REJECT_INVALID, "bad-tx-version-vmversion");
                if (v.flagOptions != 0)
                    return state.DoS(100, error("ConnectBlock(): Contract execution uses unknown flag options"), REJECT_INVALID, "bad-tx-version-flags");

                //check gas limit is not less than minimum gas limit (unless it is a no-exec tx)
                if (qtx.gas() < MINIMUM_GAS_LIMIT && v.rootVM != 0)
                    return state.DoS(100, error("ConnectBlock(): Contract execution has lower gas limit than allowed"), REJECT_INVALID, "bad-tx-too-little-gas");

                if (qtx.gas() > UINT32_MAX)
                    return state.DoS(100, error("ConnectBlock(): Contract execution can not specify greater gas limit than can fit in 32-bits"), REJECT_INVALID, "bad-tx-too-much-gas");

                gasAllTxs += qtx.gas();
                if (gasAllTxs > dev::u256(blockGasLimit))
                    return state.DoS(1, false, REJECT_INVALID, "bad-txns-gas-exceeds-blockgaslimit");

                //don't allow less than DGP set minimum gas price to prevent MPoS greedy mining/spammers
                if (v.rootVM != 0 && (uint64_t) qtx.gasPrice() < minGasPrice)
                    return state.DoS(100, error("ConnectBlock(): Contract execution has lower gas price than allowed"), REJECT_INVALID, "bad-tx-low-gas-price");
            }

            if (!nonZeroVersion) {
                //if tx is 0 version, then the tx must already have been added by a previous contract execution
                if (!tx.HasOpSpend()) {
                    return state.DoS(100, error("ConnectBlock(): Version 0 contract executions are not allowed unless created by the AAL "), REJECT_INVALID, "bad-tx-improper-version-0");
                }
            }

            if (!exec.performByteCode()) {
                return state.DoS(100, error("ConnectBlock(): Unknown error during contract execution"), REJECT_INVALID, "bad-tx-unknown-error");
            }

            std::vector<ResultExecute> resultExec(exec.getResult());
            ByteCodeExecResult bcer;
            if (!exec.processingResults(bcer)) {
                return state.DoS(100, error("ConnectBlock(): Error processing VM execution results"), REJECT_INVALID, "bad-vm-exec-processing");
            }

            countCumulativeGasUsed += bcer.usedGas;
            std::vector<TransactionReceiptInfo> tri;
            if (fLogEvents) {
                for (size_t k = 0; k < resultConvertQtumTX.first.size(); k++) {
                    dev::Address key = resultExec[k].execRes.newAddress;
                    if (!heightIndexes.count(key)) {
                        heightIndexes[key].first = CHeightTxIndexKey(pindex->nHeight, resultExec[k].execRes.newAddress);
                    }
                    heightIndexes[key].second.push_back(tx.GetHash());
                    tri.push_back(TransactionReceiptInfo{blockhash, uint32_t(pindex->nHeight), tx.GetHash(), uint32_t(i), resultConvertQtumTX.first[k].from(), resultConvertQtumTX.first[k].to(),
                                                         countCumulativeGasUsed, uint64_t(resultExec[k].execRes.gasUsed), resultExec[k].execRes.newAddress, resultExec[k].txRec.log(), resultExec[k].execRes.excepted});
                }

                pstorageresult->addResult(uintToh256(tx.GetHash()), tri);
            }

            bool ifSuccess = true;
            for (size_t n = 0; n < resultConvertQtumTX.first.size(); n++) {
                if (resultExec[n].execRes.excepted != dev::eth::TransactionException::None)
                    ifSuccess = false;
            }

            blockGasUsed += bcer.usedGas;
            if (blockGasUsed > blockGasLimit) {
                return state.DoS(1000, error("ConnectBlock(): Block exceeds gas limit"), REJECT_INVALID, "bad-blk-gaslimit");
            }
            for (CTxOut refundVout : bcer.refundOutputs) {
                gasRefunds += refundVout.nValue;
            }
            checkVouts.insert(checkVouts.end(), bcer.refundOutputs.begin(), bcer.refundOutputs.end());
            for (CTransaction& t : bcer.valueTransfers) {
                checkBlock.vtx.push_back(MakeTransactionRef(std::move(t)));
            }
            if (fRecordLogOpcodes && !fJustCheck) {
                writeVMlog(resultExec, tx, block);
            }

            for (ResultExecute& re : resultExec) {
                if (re.execRes.newAddress != dev::Address() && !fJustCheck)
                    dev::g_logPost(std::string("Address : " + re.execRes.newAddress.hex()), nullptr);
            }
        }
        /////////////////////////////////////////////////////////////////////////////////////////

        for (unsigned int k = 0; k < tx.vout.size(); k++) {
            const CTxOut& out = tx.vout[k];

            uint160 hashBytes;
            txnouttype addressType = TX_NONSTANDARD;

            if (GetIndexKey(out.scriptPubKey, hashBytes, addressType)) {
                // record receiving activity
                addressIndex.push_back(std::make_pair(CAddressIndexKey(addressType, uint160(hashBytes), pindex->nHeight, i, txhash, k, false), out.nValue));

                // record unspent output
                addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(addressType, uint160(hashBytes), txhash, k), CAddressUnspentValue(out.nValue, out.scriptPubKey, pindex->nHeight)));

            } else {
                continue;
            }

        }

        CTxUndo undoDummy;
        if (i > 0) {
            blockundo.vtxundo.push_back(CTxUndo());
        }
        if (tx.IsCoinClue()) {
            UpdateClue(tx, state, view, clueview, pindex->nHeight, blockhash);
        }

        if (tx.vShieldedSpend.size() || tx.vShieldedOutput.size()) {
            AnonymousTxInfo anonymousTx(tx.GetHash(), sapling_tree);
            anonymousBlock.txs.push_back(anonymousTx);
        }

        UpdateCoins(tx, state, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight);
        if (tx.vShieldedOutput.size()) {
            for (const OutputDescription& outputDescription : tx.vShieldedOutput) {
                sapling_tree.append(outputDescription.cm);
            }
        }

        vPos.push_back(std::make_pair(tx.GetHash(), pos));
        pos.nTxOffset += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
    }

    view.PushAnchor(sapling_tree);

    if (blockhash == params.hashGenesisBlock) {
        if (!fJustCheck) {
            view.SetBestBlock(blockhash);
            // Before the genesis block, there was an empty tree
            clueview.SetBestBlock(blockhash);
        }
        return true;
    }
    // block.hashFinalSaplingRoot must be the
    // same as the root of the Sapling tree
    if (block.hashFinalSaplingRoot != sapling_tree.root()) {
        return state.DoS(100,
                         error("ConnectBlock(): block's hashFinalSaplingRoot is incorrect"),
                         REJECT_INVALID, "bad-sapling-root-in-block");
    }

    int64_t nTime1 = GetTimeMicros();
    nTimeConnect += nTime1 - nTimeStart;
    LogPrint("bench", "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs]\n", (unsigned) block.vtx.size(), 0.001 * (nTime1 - nTimeStart), 0.001 * (nTime1 - nTimeStart) / block.vtx.size(), nInputs <= 1 ? 0 : 0.001 * (nTime1 - nTimeStart) / (nInputs - 1), nTimeConnect * 0.000001);

    CAmount nBlockReward = GetBlockClueSubsidy(pindex->nHeight, params);
    toVibPool += GetBlockSubsidy(pindex->nHeight, params) - GetBlockClueSubsidy(pindex->nHeight, params);
    toMiner += (nBlockReward / 2);
    toMasterNode += (nBlockReward - nBlockReward / 2);

    if (nFees < gasRefunds) { //make sure it won't overflow
        return state.DoS(1000, error("ConnectBlock(): Less total fees than gas refund fees"), REJECT_INVALID, "bad-blk-fees-greater-gasrefund");
    }

    nFees -= gasRefunds;

    toMiner += (nFees * 7 / 20);
    toMasterNode += (nFees * 7 / 20);

    toTandia += (nFees - (nFees * 7 / 20) - (nFees * 7 / 20));

    if (pindex->nHeight - pindex->pprev->nHeightTandiaPaid >= params.nTandiaPayPeriod)
        fPaidTandia = (toTandia >= TANDIA_AMOUNT_LIMIT);
    if (pindex->nHeight + 1 == params.nTandiaBallotStart  || (pindex->nHeight + 1) % params.nBlockCountOfWeek == 0)
        fPaidTandia = (toTandia > 0);

    if (!CheckReward(block, state, pindex, checkVouts, toMiner, toMasterNode, toVibPool, fPaidTandia, toTandia, nToMasterNodeAll))
        return state.DoS(100, error("ConnectBlock(): Reward check failed %s", FormatStateMessage(state)));


    for (auto txout : block.vtx[0]->vout) {
        if (CTxOut::VIB == txout.nFlag) {
            if (txout.dataHash.IsNull())
                return state.DoS(100, error("ConnectBlock(): vib met null hash %s\n", blockhash.GetHex()), REJECT_INVALID, "bad-vib-paid-out");
            int nSeason = chainparams.SeasonOfBlock(pindex->nHeight);
            int nStartHeight = chainparams.StartBlockForSeason(nSeason);
            if ((pindex->nHeight - nStartHeight) < params.nBlockCountPerDay)
                return state.DoS(100, error("ConnectBlock(): vib start too early.", REJECT_INVALID, "bad-vib-block"));
        }
    }

    nBlockReward = (toMiner + toMasterNode + gasRefunds + nToMasterNodeAll);
    if (fPaidTandia)
        nBlockReward += toTandia;
    if (pindex->nHeight == params.nFounderPayHeight)
        nBlockReward += params.nFounderAmount;
    std::string strError = "";
    if (!IsBlockValueValid(block, pindex->nHeight, nBlockReward, strError)) {
        return state.DoS(0, error("ConnectBlock(MN): %s", strError), REJECT_INVALID, "bad-cb-amount");
    }

    if (!IsBlockPayeeValid(*(block.vtx[0]), pindex->nHeight, nBlockReward)) {
        mapRejectedBlocks.insert(make_pair(blockhash, GetTime()));
        return state.DoS(0, error("ConnectBlock(MN): couldn't find masternode or superblock payments"),
                         REJECT_INVALID, "bad-cb-payee");
    }

    if (!control.Wait())
        return state.DoS(100, false);
    int64_t nTime2 = GetTimeMicros();
    nTimeVerify += nTime2 - nTimeStart;
    LogPrint("bench", "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs]\n", nInputs - 1, 0.001 * (nTime2 - nTimeStart), nInputs <= 1 ? 0 : 0.001 * (nTime2 - nTimeStart) / (nInputs - 1), nTimeVerify * 0.000001);

    ////////////////////////////////////////////////////////////////// // qtum
    checkBlock.hashMerkleRoot = BlockMerkleRoot(checkBlock);
    checkBlock.hashStateRoot = h256Touint(globalState->rootHash());
    checkBlock.hashUTXORoot = h256Touint(globalState->rootHashUTXO());

    //If this error happens, it probably means that something with AAL created transactions didn't match up to what is expected
    if ((checkBlock.GetHash() != blockhash) && !fJustCheck) {
        LogPrintf("Actual block data does not match block expected by AAL\n");
        LogPrintf("ActualBlock: %s\n\nExpected: %s\n", block.ToString(), checkBlock.ToString());
        //Something went wrong with AAL, compare different elements and determine what the problem is
        if (checkBlock.hashMerkleRoot != block.hashMerkleRoot) {
            //there is a mismatched tx, so go through and determine which txs
            if (block.vtx.size() > checkBlock.vtx.size()) {
                LogPrintf("Unexpected AAL transactions in block. Actual txs: %i, expected txs: %i\n", block.vtx.size(), checkBlock.vtx.size());
                for (size_t i = 0; i < block.vtx.size(); i++) {
                    if (i > checkBlock.vtx.size() - 1) {
                        LogPrintf("Unexpected transaction: %s\n", block.vtx[i]->ToString());
                    } else {
                        if (block.vtx[i]->GetHash() != checkBlock.vtx[i]->GetHash()) {
                            LogPrintf("Mismatched transaction at entry %i\n", i);
                            LogPrintf("Actual: %s\n", block.vtx[i]->ToString());
                            LogPrintf("Expected: %s\n", checkBlock.vtx[i]->ToString());
                        }
                    }
                }
            } else if (block.vtx.size() < checkBlock.vtx.size()) {
                LogPrintf("Actual block is missing AAL transactions. Actual txs: %i, expected txs: %i\n", block.vtx.size(), checkBlock.vtx.size());
                for (size_t i = 0; i < checkBlock.vtx.size(); i++) {
                    if (i > block.vtx.size() - 1) {
                        LogPrintf("Missing transaction: %s\n", checkBlock.vtx[i]->ToString());
                    } else {
                        if (block.vtx[i]->GetHash() != checkBlock.vtx[i]->GetHash()) {
                            LogPrintf("Mismatched transaction at entry %i\n", i);
                            LogPrintf("Actual: %s\n", block.vtx[i]->ToString());
                            LogPrintf("Expected: %s\n", checkBlock.vtx[i]->ToString());
                        }
                    }
                }
            } else {
                //count is correct, but a tx is wrong
                for (size_t i = 0; i < checkBlock.vtx.size(); i++) {
                    if (block.vtx[i]->GetHash() != checkBlock.vtx[i]->GetHash()) {
                        LogPrintf("Mismatched transaction at entry %i\n", i);
                        LogPrintf("Actual: %s\n", block.vtx[i]->ToString());
                        LogPrintf("Expected: %s\n", checkBlock.vtx[i]->ToString());
                    }
                }
            }
        }
        if (checkBlock.hashUTXORoot != block.hashUTXORoot) {
            LogPrintf("Actual block data does not match hashUTXORoot expected by AAL block\n");
        }
        if (checkBlock.hashStateRoot != block.hashStateRoot) {
            LogPrintf("Actual block data does not match hashStateRoot expected by AAL block\n");
        }

        return state.DoS(100, error("ConnectBlock(): Incorrect AAL transactions or hashes (hashStateRoot, hashUTXORoot)"),
                         REJECT_INVALID, "incorrect-transactions-or-hashes-block");
    }

    if (fJustCheck) {
        dev::h256 prevHashStateRoot(dev::sha3(dev::rlp("")));
        dev::h256 prevHashUTXORoot(dev::sha3(dev::rlp("")));
        if (pindex->pprev->hashStateRoot != uint256() && pindex->pprev->hashUTXORoot != uint256()) {
            prevHashStateRoot = uintToh256(pindex->pprev->hashStateRoot);
            prevHashUTXORoot = uintToh256(pindex->pprev->hashUTXORoot);
        }
        globalState->setRoot(prevHashStateRoot);
        globalState->setRootUTXO(prevHashUTXORoot);
        return true;
    }
    //////////////////////////////////////////////////////////////////

    // Write undo information to disk
    if ((pindex->GetUndoPos().IsNull() || !pindex->IsValid(BLOCK_VALID_SCRIPTS)) && pindex->nHeight > 0) {
        if (pindex->GetUndoPos().IsNull()) {
            CDiskBlockPos pos;
            if (!FindUndoPos(state, pindex->nFile, pos, ::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 40))
                return error("ConnectBlock(): FindUndoPos failed");
            if (!UndoWriteToDisk(blockundo, pos, pindex->pprev->GetBlockHash(), chainparams.MessageStart()))
                return AbortNode(state, "Failed to write undo data");

            // update nUndoPos in block index
            pindex->nUndoPos = pos.nPos;
            pindex->nStatus |= BLOCK_HAVE_UNDO;
        }

        pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
        setDirtyBlockIndex.insert(pindex);
    }

    if (fLogEvents) {
        for (const auto& e : heightIndexes) {
            if (!pblocktree->WriteHeightIndex(e.second.first, e.second.second))
                return AbortNode(state, "Failed to write height index");
        }
    }

    if (!pblocktree->WriteTxIndex(vPos))
        return AbortNode(state, "Failed to write transaction index");

    if (!pblocktree->WriteAddressIndex(addressIndex)) {
        return AbortNode(state, "Failed to write address index");
    }

    if (!pblocktree->UpdateAddressUnspentIndex(addressUnspentIndex)) {
        return AbortNode(state, "Failed to write address unspent index");
    }

    if (!pblocktree->UpdateSpentIndex(spentIndex))
        return AbortNode(state, "Failed to write transaction index");

    if (!pblocktree->WriteAnonymousBlock(blockhash, anonymousBlock))
        return AbortNode(state, "Failed to write anonymous block index");

    // add this block to the view's block chain
    view.SetBestBlock(blockhash);
    clueview.SetBestBlock(blockhash);

    int64_t nTime3 = GetTimeMicros();
    nTimeIndex += nTime3 - nTime2;
    LogPrint("bench", "    - Index writing: %.2fms [%.2fs]\n", 0.001 * (nTime3 - nTime2), nTimeIndex * 0.000001);

    // Watch for changes to the previous coinbase transaction.
    static uint256 hashPrevBestCoinBase;
    GetMainSignals().UpdatedTransaction(hashPrevBestCoinBase);
    hashPrevBestCoinBase = block.vtx[0]->GetHash();

    int64_t nTime4 = GetTimeMicros();
    nTimeCallbacks += nTime4 - nTime3;
    LogPrint("bench", "    - Callbacks: %.2fms [%.2fs]\n", 0.001 * (nTime4 - nTime3), nTimeCallbacks * 0.000001);

    if (fLogEvents)
        pstorageresult->commitResults();

    return true;
}

enum FlushStateMode {
    FLUSH_STATE_NONE,
    FLUSH_STATE_IF_NEEDED,
    FLUSH_STATE_PERIODIC,
    FLUSH_STATE_ALWAYS
};

/**
 * Update the on-disk chain state.
 * The caches and indexes are flushed depending on the mode we're called with
 * if they're too large, if it's been a while since the last write,
 * or always and in all cases if we're in prune mode and are deleting files.
 */
bool static FlushStateToDisk(CValidationState& state, FlushStateMode mode)
{
    LOCK2(cs_main, cs_LastBlockFile);
    const CChainParams& chainparams = Params();
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    static int64_t nLastSetChain = 0;
    std::set<int> setFilesToPrune;
    bool fFlushForPrune = false;
    try {
        if (fPruneMode && fCheckForPruning && !fReindex) {
            FindFilesToPrune(setFilesToPrune, chainparams.PruneAfterHeight());
            fCheckForPruning = false;
            if (!setFilesToPrune.empty()) {
                fFlushForPrune = true;
                if (!fHavePruned) {
                    pblocktree->WriteFlag("prunedblockfiles", true);
                    fHavePruned = true;
                }
            }
        }
        int64_t nNow = GetTimeMicros();
        // Avoid writing/flushing immediately after startup.
        if (nLastWrite == 0) {
            nLastWrite = nNow;
        }
        if (nLastFlush == 0) {
            nLastFlush = nNow;
        }
        if (nLastSetChain == 0) {
            nLastSetChain = nNow;
        }
        size_t cacheSize = pcoinsTip->DynamicMemoryUsage();
        // The cache is large and close to the limit, but we have time now (not in the middle of a block processing).
        bool fCacheLarge = mode == FLUSH_STATE_PERIODIC && cacheSize * (10.0 / 9) > nCoinCacheUsage;
        // The cache is over the limit, we have to write now.
        bool fCacheCritical = mode == FLUSH_STATE_IF_NEEDED && cacheSize > nCoinCacheUsage;
        // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload after a crash.
        bool fPeriodicWrite = mode == FLUSH_STATE_PERIODIC && nNow > nLastWrite + (int64_t) DATABASE_WRITE_INTERVAL * 1000000;
        // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
        bool fPeriodicFlush = mode == FLUSH_STATE_PERIODIC && nNow > nLastFlush + (int64_t) DATABASE_FLUSH_INTERVAL * 1000000;
        // Combine all conditions that result in a full cache flush.
        bool fDoFullFlush = (mode == FLUSH_STATE_ALWAYS) || fCacheLarge || fCacheCritical || fPeriodicFlush || fFlushForPrune;
        // Write blocks and block index to disk.
        if (fDoFullFlush || fPeriodicWrite) {
            // Depend on nMinDiskSpace to ensure we can write block index
            if (!CheckDiskSpace(0))
                return state.Error("out of disk space");
            // First make sure all block and undo data is flushed to disk.
            FlushBlockFile();
            // Then update all block file information (which may refer to block and undo files).
            {
                std::vector<std::pair<int, const CBlockFileInfo*> > vFiles;
                vFiles.reserve(setDirtyFileInfo.size());
                for (set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end();) {
                    vFiles.push_back(make_pair(*it, &vinfoBlockFile[*it]));
                    setDirtyFileInfo.erase(it++);
                }
                std::vector<const CBlockIndex*> vBlocks;
                vBlocks.reserve(setDirtyBlockIndex.size());
                for (set<CBlockIndex*>::iterator it = setDirtyBlockIndex.begin(); it != setDirtyBlockIndex.end();) {
                    vBlocks.push_back(*it);
                    setDirtyBlockIndex.erase(it++);
                }
                if (!pblocktree->WriteBatchSync(vFiles, nLastBlockFile, vBlocks)) {
                    return AbortNode(state, "Files to write to block index database");
                }
            }
            // Finally remove any pruned files
            if (fFlushForPrune)
                UnlinkPrunedFiles(setFilesToPrune);
            nLastWrite = nNow;
        }
        // Flush best chain related state. This can only be done if the blocks / block index write was also done.
        if (fDoFullFlush) {
            // Typical CCoins structures on disk are around 128 bytes in size.
            // Pushing a new one to the database can cause it to be written
            // twice (once in the log, and once in the tables). This is already
            // an overestimation, as most will delete an existing entry or
            // overwrite one. Still, use a conservative safety factor of 2.
            if (!CheckDiskSpace(128 * 2 * 2 * pcoinsTip->GetCacheSize()))
                return state.Error("out of disk space");
            // Flush the chainstate (which may refer to block index entries).
            if (!pcoinsTip->Flush())
                return AbortNode(state, "Failed to write to coin database");

            if (!pclueTip->Flush())
                return AbortNode(state, "Failed to write to clue database");

            nLastFlush = nNow;
        }
        if ((mode == FLUSH_STATE_ALWAYS || mode == FLUSH_STATE_PERIODIC) && nNow > nLastSetChain + (int64_t) DATABASE_WRITE_INTERVAL * 1000000) {
            // Update best block in wallet (so we can detect restored wallets).
            GetMainSignals().SetBestChain(chainActive.GetLocator());
            nLastSetChain = nNow;
        }
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

void FlushStateToDisk()
{
    CValidationState state;
    FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
}

void PruneAndFlush()
{
    CValidationState state;
    fCheckForPruning = true;
    FlushStateToDisk(state, FLUSH_STATE_NONE);
}

/** Update chainActive and related internal data structures. */
void static UpdateTip(CBlockIndex* pindexNew)
{
    const CChainParams& chainParams = Params();
    chainActive.SetTip(pindexNew);

    // New best block
    mempool.AddTransactionsUpdated(1);

    cvBlockChange.notify_all();

    // Check the version of the last 100 blocks to see if we need to upgrade:
    static bool fWarned = false;
    if (!IsInitialBlockDownload() && !fWarned) {
        int nUpgraded = 0;
        const CBlockIndex* pindex = chainActive.Tip();
        for (int bit = 0; bit < VERSIONBITS_NUM_BITS; bit++) {
            WarningBitsConditionChecker checker(bit);
            ThresholdState state = checker.GetStateFor(pindex, chainParams.GetConsensus(), warningcache[bit]);
            if (state == THRESHOLD_ACTIVE || state == THRESHOLD_LOCKED_IN) {
                const std::string strWarning = strprintf(_("Warning: unknown new rules activated (versionbit %i)"), bit);
                if (state == THRESHOLD_ACTIVE) {
                    CAlert::Notify(strWarning, true);
                    fWarned = true;
                }
            }
        }
        for (int i = 0; i < 100 && pindex != nullptr; i++) {
            int32_t nExpectedVersion = ComputeBlockVersion(pindex->pprev, chainParams.GetConsensus());
            if (pindex->nVersion > VERSIONBITS_LAST_OLD_BLOCK_VERSION && (pindex->nVersion & ~nExpectedVersion) != 0)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            LogPrintf("%s: %d of last 100 blocks above version %d\n", __func__, nUpgraded, (int) CBlock::CURRENT_VERSION);
        if (nUpgraded > 100 / 2) {
            // strMiscWarning is read by GetWarnings(), called by the JSON-RPC code to warn the user:
            strMiscWarning = _("Warning: This version is obsolete; upgrade required!");
            CAlert::Notify(strMiscWarning, true);
            fWarned = true;
        }
    }
    LogPrintf("%s: new best=%s height=%d version=0x%08x log2_work=%.8g tx=%lu date='%s' cache=%.1fMiB(%utxo)\n", __func__,
              pindexNew->GetBlockHash().ToString(), pindexNew->nHeight, pindexNew->nVersion,
              log(pindexNew->nChainWork.getdouble()) / log(2.0), (unsigned long)pindexNew->nChainTx,
              DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexNew->GetBlockTime()),
              pcoinsTip->DynamicMemoryUsage() * (1.0 / (1 << 20)), pcoinsTip->GetCacheSize());
}

/** Disconnect chainActive's tip. */
bool static DisconnectTip(CValidationState& state, const Consensus::Params& consensusParams, DisconnectedBlockTransactions* disconnectpool)
{
    CBlockIndex* pindexDelete = chainActive.Tip();
    assert(pindexDelete);
    // Read block from disk.
    CBlock block;
    if (!ReadBlockFromDisk(block, pindexDelete, consensusParams))
        return AbortNode(state, "Failed to read block");
    // Apply the block atomically to the chain state.
    uint256 saplingAnchorBeforeDisconnect = pcoinsTip->GetBestAnchor(SAPLING);
    int64_t nStart = GetTimeMicros();
    {
        CCoinsViewCache view(pcoinsTip);
        CClueViewCache clueview(pclueTip);
        if (DisconnectBlock(block, state, pindexDelete, view, clueview) != DISCONNECT_OK)
            return error("DisconnectTip(): DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString());

        assert(view.Flush());
        assert(clueview.Flush());
    }
    LogPrint("bench", "- Disconnect block: %.2fms\n", (GetTimeMicros() - nStart) * 0.001);
    uint256 saplingAnchorAfterDisconnect = pcoinsTip->GetBestAnchor(SAPLING);    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        return false;
    if (disconnectpool) {
        // Save transactions to re-add to mempool at end of reorg
        for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
            disconnectpool->addTransaction(*it);
        }

        if (saplingAnchorBeforeDisconnect != saplingAnchorAfterDisconnect) {
            disconnectpool->saplingAnchorToRemove = saplingAnchorBeforeDisconnect;
        }

        while (disconnectpool->DynamicMemoryUsage() > MAX_DISCONNECTED_TX_POOL_SIZE * 1000) {
            // Drop the earliest entry, and remove its children from the mempool.
            auto it = disconnectpool->queuedTx.get<insertion_order>().begin();
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
            disconnectpool->removeEntry(it);
        }
    }

    // Update chainActive and related variables.
    UpdateTip(pindexDelete->pprev);
    // Get the current commitment tree
    SaplingMerkleTree newSaplingTree;
    assert(pcoinsTip->GetSaplingAnchorAt(pcoinsTip->GetBestAnchor(SAPLING), newSaplingTree));
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    for (int i = 0; i < block.vtx.size(); i++) {
        GetMainSignals().SyncTransaction(block.vtx[i], pindexDelete, i);
    }

    // Update cached incremental witnesses
    GetMainSignals().ChainTip(pindexDelete, &block, newSaplingTree, false);
    return true;
}

static int64_t nTimeReadFromDisk = 0;
static int64_t nTimeConnectTotal = 0;
static int64_t nTimeFlush = 0;
static int64_t nTimeChainState = 0;
static int64_t nTimePostConnect = 0;

/**
 * Used to track blocks whose transactions were applied to the UTXO state as a
 * part of a single ActivateBestChainStep call.
 */
struct ConnectTrace {
    std::vector<std::pair<CBlockIndex*, std::shared_ptr<const CBlock> > > blocksConnected;
};

/**
 * Connect a new block to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool static ConnectTip(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace, DisconnectedBlockTransactions& disconnectpool)
{
    assert(pindexNew->pprev == chainActive.Tip());
    // Read block from disk.
    int64_t nTime1 = GetTimeMicros();
    if (!pblock) {
        std::shared_ptr<CBlock> pblockNew = std::make_shared<CBlock>();
        connectTrace.blocksConnected.emplace_back(pindexNew, pblockNew);
        if (!ReadBlockFromDisk(*pblockNew, pindexNew, chainparams.GetConsensus()))
            return AbortNode(state, "Failed to read block");
    } else {
        connectTrace.blocksConnected.emplace_back(pindexNew, pblock);
    }
    const CBlock& block = *connectTrace.blocksConnected.back().second;

    // Get the current commitment tree
    SaplingMerkleTree oldSaplingTree;
    assert(pcoinsTip->GetSaplingAnchorAt(pcoinsTip->GetBestAnchor(SAPLING), oldSaplingTree));
    // Apply the block atomically to the chain state.
    int64_t nTime2 = GetTimeMicros();
    nTimeReadFromDisk += nTime2 - nTime1;
    int64_t nTime3;
    LogPrint("bench", "  - Load block from disk: %.2fms [%.2fs]\n", (nTime2 - nTime1) * 0.001, nTimeReadFromDisk * 0.000001);
    {
        CCoinsViewCache view(pcoinsTip);
        CClueViewCache clueview(pclueTip);

        dev::h256 oldHashStateRoot(globalState->rootHash()); // qtum
        dev::h256 oldHashUTXORoot(globalState->rootHashUTXO()); // qtum

        bool rv = ConnectBlock(block, state, pindexNew, view, clueview);

        GetMainSignals().BlockChecked(block, state);
        if (!rv) {
            if (state.IsInvalid())
                InvalidBlockFound(pindexNew, state);

            globalState->setRoot(oldHashStateRoot); // qtum
            globalState->setRootUTXO(oldHashUTXORoot); // qtum

            return error("ConnectTip(): ConnectBlock %s failed", pindexNew->GetBlockHash().ToString());
        }

        nTime3 = GetTimeMicros();
        nTimeConnectTotal += nTime3 - nTime2;
        LogPrint("bench", "  - Connect total: %.2fms [%.2fs]\n", (nTime3 - nTime2) * 0.001, nTimeConnectTotal * 0.000001);
        assert(view.Flush());
        assert(clueview.Flush());
    }
    int64_t nTime4 = GetTimeMicros();
    nTimeFlush += nTime4 - nTime3;
    LogPrint("bench", "  - Flush: %.2fms [%.2fs]\n", (nTime4 - nTime3) * 0.001, nTimeFlush * 0.000001);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        return false;
    int64_t nTime5 = GetTimeMicros();
    nTimeChainState += nTime5 - nTime4;
    LogPrint("bench", "  - Writing chainstate: %.2fms [%.2fs]\n", (nTime5 - nTime4) * 0.001, nTimeChainState * 0.000001);
    // Remove conflicting transactions from the mempool.
    list<CTransaction> txConflicted;
    mempool.removeForBlock(block.vtx, pindexNew->nHeight);
    disconnectpool.removeForBlock(block.vtx);
    // Update chainActive & related variables.
    UpdateTip(pindexNew);

    // Update cached incremental witnesses
    GetMainSignals().ChainTip(pindexNew, &block, oldSaplingTree, true);

    EnforceNodeDeprecation(pindexNew->nHeight);

    int64_t nTime6 = GetTimeMicros();
    nTimePostConnect += nTime6 - nTime5;
    nTimeTotal += nTime6 - nTime1;
    LogPrint("bench", "  - Connect postprocess: %.2fms [%.2fs]\n", (nTime6 - nTime5) * 0.001, nTimePostConnect * 0.000001);
    LogPrint("bench", "- Connect block: %.2fms [%.2fs]\n", (nTime6 - nTime1) * 0.001, nTimeTotal * 0.000001);
    return true;
}

/**
 * Return the tip of the chain with the most work in it, that isn't
 * known to be invalid (it's however far from certain to be valid).
 */
static CBlockIndex* FindMostWorkChain()
{
    do {
        CBlockIndex* pindexNew = nullptr;

        // Find the best candidate header.
        {
            std::set<CBlockIndex*, CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend())
                return nullptr;
            pindexNew = *it;
        }

        // Check whether all blocks on the path between the currently active chain and the candidate are valid.
        // Just going until the active chain is an optimization, as we know all blocks in it are valid already.
        CBlockIndex* pindexTest = pindexNew;
        bool fInvalidAncestor = false;
        while (pindexTest && !chainActive.Contains(pindexTest)) {
            assert(pindexTest->nChainTx || pindexTest->nHeight == 0);

            // Pruned nodes may have entries in setBlockIndexCandidates for
            // which block files have been deleted.  Remove those as candidates
            // for the most work chain if we come across them; we can't switch
            // to a chain unless we have all the non-active-chain parent blocks.
            bool fFailedChain = pindexTest->nStatus & BLOCK_FAILED_MASK;
            bool fMissingData = !(pindexTest->nStatus & BLOCK_HAVE_DATA);
            if (fFailedChain || fMissingData) {
                // Candidate chain is not usable (either invalid or missing data)
                if (fFailedChain && (pindexBestInvalid == nullptr || pindexNew->nChainWork > pindexBestInvalid->nChainWork))
                    pindexBestInvalid = pindexNew;
                CBlockIndex* pindexFailed = pindexNew;
                // Remove the entire chain from the set.
                while (pindexTest != pindexFailed) {
                    if (fFailedChain) {
                        pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    } else if (fMissingData) {
                        // If we're missing data, then add back to mapBlocksUnlinked,
                        // so that if the block arrives in the future we can try adding
                        // to setBlockIndexCandidates again.
                        mapBlocksUnlinked.insert(std::make_pair(pindexFailed->pprev, pindexFailed));
                    }
                    setBlockIndexCandidates.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                setBlockIndexCandidates.erase(pindexTest);
                fInvalidAncestor = true;
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (!fInvalidAncestor)
            return pindexNew;
    } while (true);
}

/** Delete all entries in setBlockIndexCandidates that are worse than the current tip. */
static void PruneBlockIndexCandidates()
{
    // Note that we can't delete the current block itself, as we may need to return to it later in case a
    // reorganization to a better block fails.
    std::set<CBlockIndex*, CBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() && setBlockIndexCandidates.value_comp()(*it, chainActive.Tip())) {
        setBlockIndexCandidates.erase(it++);
    }
    // Either the current tip or a successor of it we're working towards is left in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

/**
 * Try to make some progress towards making pindexMostWork the active block.
 * pblock is either NULL or a pointer to a CBlock corresponding to pindexMostWork.
 */
static bool ActivateBestChainStep(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace)
{
    AssertLockHeld(cs_main);
    const CBlockIndex* pindexOldTip = chainActive.Tip();
    const CBlockIndex* pindexFork = chainActive.FindFork(pindexMostWork);

    bool fBlocksDisconnected = false;
    DisconnectedBlockTransactions disconnectpool;
    // Disconnect active blocks which are no longer in the best chain.
    while (chainActive.Tip() && chainActive.Tip() != pindexFork) {
        if (!DisconnectTip(state, chainparams.GetConsensus(), &disconnectpool)) {
            // This is likely a fatal error, but keep the mempool consistent,
            // just in case. Only remove from the mempool in this case.
            UpdateMempoolForReorg(disconnectpool, false);
            return false;
        }
        fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect.
    std::vector<CBlockIndex*> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight) {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBlockIndex* pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight) {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new blocks.

        BOOST_REVERSE_FOREACH(CBlockIndex * pindexConnect, vpindexToConnect) {
            if (!ConnectTip(state, chainparams, pindexConnect, pindexConnect == pindexMostWork ? pblock : nullptr, connectTrace, disconnectpool)) {
                if (state.IsInvalid()) {
                    // The block violates a consensus rule.
                    if (!state.CorruptionPossible())
                        InvalidChainFound(vpindexToConnect.back());
                    state = CValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    // If we didn't actually connect the block, don't notify listeners about it
                    connectTrace.blocksConnected.pop_back();
                    break;
                } else {
                    // A system error occurred (disk space, database error, ...).
                    // Make the mempool consistent with the current tip, just in case
                    // any observers try to use it before shutdown.
                    UpdateMempoolForReorg(disconnectpool, false);
                    return false;
                }
            } else {
                PruneBlockIndexCandidates();
                if (!pindexOldTip || chainActive.Tip()->nChainWork > pindexOldTip->nChainWork) {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }
    if (fBlocksDisconnected) {
        // If any blocks were disconnected, disconnectpool may be non empty.  Add
        // any disconnected transactions back to the mempool.
        UpdateMempoolForReorg(disconnectpool, true);
    }
    mempool.check(pcoinsTip);

    // Callbacks/notifications for a new best chain.
    if (fInvalidFound)
        CheckForkWarningConditionsOnNewFork(vpindexToConnect.back());
    else
        CheckForkWarningConditions();

    return true;
}

static void NotifyHeaderTip()
{
    bool fNotify = false;
    bool fInitialBlockDownload = false;
    static CBlockIndex* pindexHeaderOld = nullptr;
    CBlockIndex* pindexHeader = nullptr;
    {
        LOCK(cs_main);
        pindexHeader = pindexBestHeader;

        if (pindexHeader != pindexHeaderOld) {
            fNotify = true;
            fInitialBlockDownload = IsInitialBlockDownload();
            pindexHeaderOld = pindexHeader;
        }
    }
    // Send block tip changed notifications without cs_main
    if (fNotify) {
        uiInterface.NotifyHeaderTip(fInitialBlockDownload, pindexHeader);
        GetMainSignals().NotifyHeaderTip(pindexHeader, fInitialBlockDownload);
    }
}

/**
 * Make the best chain active, in multiple steps. The result is either failure
 * or an activated best chain. pblock is either NULL or a pointer to a block
 * that is already loaded (to avoid loading it again from disk).
 */
bool ActivateBestChain(CValidationState& state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock)
{
    // Note that while we're often called here from ProcessNewBlock, this is
    // far from a guarantee. Things in the P2P/RPC will often end up calling
    // us in the middle of ProcessNewBlock - do not assume pblock is set
    // sanely for performance or correctness!
    AssertLockNotHeld(cs_main);

    CBlockIndex* pindexNewTip = nullptr;
    CBlockIndex* pindexMostWork = nullptr;
    do {
        boost::this_thread::interruption_point();

        if (GetMainSignals().CallbacksPending() > 10) {
            // Block until the validation queue drains. This should largely
            // never happen in normal operation, however may happen during
            // reindex, causing memory blowup  if we run too far ahead.
            SyncWithValidationInterfaceQueue();
        }

        {
            LOCK(cs_main);

            const CBlockIndex* pindexFork;
            ConnectTrace connectTrace;
            bool fInitialDownload;


            CBlockIndex* pindexOldTip = chainActive.Tip();
            if (pindexMostWork == nullptr) {
                pindexMostWork = FindMostWorkChain();
            }

            // Whether we have anything to do at all.
            if (pindexMostWork == nullptr || pindexMostWork == chainActive.Tip())
                return true;

            bool fInvalidFound = false;
            if (!ActivateBestChainStep(state, chainparams, pindexMostWork, pblock && pblock->GetHash() == pindexMostWork->GetBlockHash() ? pblock : nullptr, fInvalidFound, connectTrace))
                return false;

            if (fInvalidFound) {
                // Wipe cache, we may need another branch now.
                pindexMostWork = nullptr;
            }
            pindexNewTip = chainActive.Tip();
            pindexFork = chainActive.FindFork(pindexOldTip);
            fInitialDownload = IsInitialBlockDownload();


            for (const auto& pair : connectTrace.blocksConnected) {
                assert(pair.second);
                const CBlock& block = *(pair.second);
                for (unsigned int i = 0; i < block.vtx.size(); i++)
                    GetMainSignals().SyncTransaction(block.vtx[i], pair.first, i);
            }

            // When we reach this point, we switched to a new tip (stored in pindexNewTip).

            // Notifications/callbacks that can run without cs_main
            // Transactions in the connnected block are notified

            // Notify external listeners about the new tip.
            GetMainSignals().UpdatedBlockTip(pindexNewTip, pindexFork, fInitialDownload);
            // Always notify the UI if a new block tip was connected
            if (pindexFork != pindexNewTip) {
                uiInterface.NotifyBlockTip(fInitialDownload, pindexNewTip);
            }
        }
    } while (pindexMostWork != chainActive.Tip());
    CheckBlockIndex(chainparams.GetConsensus());

    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(state, FLUSH_STATE_PERIODIC)) {
        return false;
    }

    return true;
}

bool InvalidateBlock(CValidationState& state, const Consensus::Params& consensusParams, CBlockIndex* pindex)
{
    AssertLockHeld(cs_main);

    bool pindex_was_in_chain = false;
    CBlockIndex* invalid_walk_tip = chainActive.Tip();

    DisconnectedBlockTransactions disconnectpool;
    while (chainActive.Contains(pindex)) {
        pindex_was_in_chain = true;
        // ActivateBestChain considers blocks already in chainActive
        // unconditionally valid already, so force disconnect away from it.
        if (!DisconnectTip(state, consensusParams, &disconnectpool)) {
            // It's probably hopeless to try to make the mempool consistent
            // here if DisconnectTip failed, but we can try.
            UpdateMempoolForReorg(disconnectpool, false);
            return false;
        }
    }

    while (pindex_was_in_chain && invalid_walk_tip != pindex) {
        // Mark the block itself as invalid.
        invalid_walk_tip->nStatus |= BLOCK_FAILED_CHILD;
        setDirtyBlockIndex.insert(invalid_walk_tip);
        setBlockIndexCandidates.erase(invalid_walk_tip);
        invalid_walk_tip = invalid_walk_tip->pprev;
    }

    pindex->nStatus |= BLOCK_FAILED_VALID;
    setDirtyBlockIndex.insert(pindex);
    setBlockIndexCandidates.erase(pindex);

    UpdateMempoolForReorg(disconnectpool, true);

    // The resulting new best tip may not be in setBlockIndexCandidates anymore, so
    // add it again.
    BlockMap::iterator it = mapBlockIndex.begin();
    while (it != mapBlockIndex.end()) {
        if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx && !setBlockIndexCandidates.value_comp()(it->second, chainActive.Tip())) {
            setBlockIndexCandidates.insert(it->second);
        }
        it++;
    }

    InvalidChainFound(pindex);
    return true;
}

bool ReconsiderBlock(CValidationState& state, CBlockIndex* pindex)
{
    AssertLockHeld(cs_main);

    int nHeight = pindex->nHeight;

    // Remove the invalidity flag from this block and all its descendants.
    BlockMap::iterator it = mapBlockIndex.begin();
    while (it != mapBlockIndex.end()) {
        if (!it->second->IsValid() && it->second->GetAncestor(nHeight) == pindex) {
            it->second->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(it->second);
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx && setBlockIndexCandidates.value_comp()(chainActive.Tip(), it->second)) {
                setBlockIndexCandidates.insert(it->second);
            }
            if (it->second == pindexBestInvalid) {
                // Reset invalid block marker if it was pointing to one of those.
                pindexBestInvalid = nullptr;
            }
        }
        it++;
    }

    // Remove the invalidity flag from all ancestors too.
    while (pindex != nullptr) {
        if (pindex->nStatus & BLOCK_FAILED_MASK) {
            pindex->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(pindex);
        }
        pindex = pindex->pprev;
    }
    return true;
}

CBlockIndex* AddToBlockIndex(const CBlockHeader& block)
{
    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end())
        return it->second;

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(block);
    assert(pindexNew);
    // We assign the sequence id to blocks only when the full data is available,
    // to avoid miners withholding blocks but broadcasting headers, to get a
    // competitive advantage.
    pindexNew->nSequenceId = 0;
    BlockMap::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    BlockMap::iterator miPrev = mapBlockIndex.find(block.hashPrevBlock);
    if (miPrev != mapBlockIndex.end()) {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
        pindexNew->BuildSkip();
    }
    pindexNew->nChainWork = (pindexNew->pprev ? pindexNew->pprev->nChainWork : 0) + GetBlockProof(*pindexNew);
    pindexNew->RaiseValidity(BLOCK_VALID_TREE);
    if (pindexBestHeader == nullptr || pindexBestHeader->nChainWork < pindexNew->nChainWork)
        pindexBestHeader = pindexNew;

    setDirtyBlockIndex.insert(pindexNew);

    return pindexNew;
}

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
bool ReceivedBlockTransactions(const CBlock& block, CValidationState& state, CBlockIndex* pindexNew, const CDiskBlockPos& pos)
{
    pindexNew->nTx = block.vtx.size();
    pindexNew->nClueTx = 0; // TODO: count clue transactions.
    pindexNew->nChainTx = 0;
    CAmount saplingValue = 0;
    for (auto tx : block.vtx) {
        // Negative valueBalance "takes" money from the transparent value pool
        // and adds it to the Sapling value pool. Positive valueBalance "gives"
        // money to the transparent value pool, removing from the Sapling value
        // pool. So we invert the sign here.
        saplingValue += -tx->valueBalance;
        if (tx->IsCoinClue())
            pindexNew->nClueTx += 1;
    }

    pindexNew->nClueLeft = 0;
    pindexNew->nSaplingValue = saplingValue;
    pindexNew->nChainSaplingValue = boost::none;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus |= BLOCK_HAVE_DATA;
    pindexNew->nLastPaidTandia = 0;
    pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    setDirtyBlockIndex.insert(pindexNew);

    const Consensus::Params& consensus = Params().GetConsensus();
    if (pindexNew->pprev == nullptr || pindexNew->pprev->nChainTx) {
        // If pindexNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        deque<CBlockIndex*> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty()) {
            CBlockIndex* pindex = queue.front();
            queue.pop_front();

            if (pindex->nHeight % consensus.nBlockCountOfWeek == 0) {
                if (pindex->nHeight >= consensus.nBlockCountOf1stSeason) {
                    CAmount nLeft = GetBlockClueSubsidy(pindex->nHeight, consensus, false) - GetBlockSubsidy(pindex->nHeight, consensus);
                    if ( nLeft > 0) {
                        pindex->nClueLeft = nLeft;
                    }
                } else {
                    pindex->nClueLeft = 0;
                }
            } else {
                pindex->nClueLeft = (pindex->pprev ? pindex->pprev->nClueLeft : 0);
            }
            pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
            pindex->nChainClueTx = (pindex->pprev ? pindex->pprev->nChainClueTx : 0) + pindex->nClueTx;
            pindex->nLastPaidTandia = (pindex->pprev ? pindex->pprev->nLastPaidTandia : 0);
            {
                LOCK(cs_nBlockSequenceId);
                pindex->nSequenceId = nBlockSequenceId++;
            }
            if (chainActive.Tip() == nullptr || !setBlockIndexCandidates.value_comp()(pindex, chainActive.Tip())) {
                setBlockIndexCandidates.insert(pindex);
            }
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex);
            while (range.first != range.second) {
                std::multimap<CBlockIndex*, CBlockIndex*>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                mapBlocksUnlinked.erase(it);
            }
        }
    } else {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE)) {
            mapBlocksUnlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
    }

    return true;
}

bool DisconnectBlocks(int blocks)
{
    LOCK(cs_main);

    CValidationState state;
    const CChainParams& chainparams = Params();

    LogPrintf("DisconnectBlocks -- Got command to replay %d blocks\n", blocks);
    for (int i = 0; i < blocks; i++) {
        if (!DisconnectTip(state, chainparams.GetConsensus(), nullptr) || !state.IsValid()) {
            return false;
        }
    }

    return true;
}

void ReprocessBlocks(int nBlocks)
{
    {
        LOCK(cs_main);

        std::map<uint256, int64_t>::iterator it = mapRejectedBlocks.begin();
        while (it != mapRejectedBlocks.end()) {
            //use a window twice as large as is usual for the nBlocks we want to reset
            if ((*it).second > GetTime() - (nBlocks * 60 * 2)) {
                BlockMap::iterator mi = mapBlockIndex.find((*it).first);
                if (mi != mapBlockIndex.end() && (*mi).second) {

                    CBlockIndex* pindex = (*mi).second;
                    LogPrintf("ReprocessBlocks -- %s\n", (*it).first.ToString());

                    CValidationState state;
                    ReconsiderBlock(state, pindex);
                }
            }
            ++it;
        }

        DisconnectBlocks(nBlocks);
    }
    CValidationState state;
    ActivateBestChain(state, Params());
}

bool FindBlockPos(CValidationState& state, CDiskBlockPos& pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, bool fKnown = false)
{
    LOCK(cs_LastBlockFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBlockFile;
    if (vinfoBlockFile.size() <= nFile) {
        vinfoBlockFile.resize(nFile + 1);
    }

    if (!fKnown) {
        while (vinfoBlockFile[nFile].nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
            nFile++;
            if (vinfoBlockFile.size() <= nFile) {
                vinfoBlockFile.resize(nFile + 1);
            }
        }
        pos.nFile = nFile;
        pos.nPos = vinfoBlockFile[nFile].nSize;
    }

    if (nFile != nLastBlockFile) {
        if (!fKnown) {
            LogPrintf("Leaving block file %i: %s\n", nFile, vinfoBlockFile[nFile].ToString());
        }
        FlushBlockFile(!fKnown);
        nLastBlockFile = nFile;
    }

    vinfoBlockFile[nFile].AddBlock(nHeight, nTime);
    if (fKnown)
        vinfoBlockFile[nFile].nSize = std::max(pos.nPos + nAddSize, vinfoBlockFile[nFile].nSize);
    else
        vinfoBlockFile[nFile].nSize += nAddSize;

    if (!fKnown) {
        unsigned int nOldChunks = (pos.nPos + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        unsigned int nNewChunks = (vinfoBlockFile[nFile].nSize + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        if (nNewChunks > nOldChunks) {
            if (fPruneMode)
                fCheckForPruning = true;
            if (CheckDiskSpace(nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos)) {
                FILE* file = OpenBlockFile(pos);
                if (file) {
                    LogPrintf("Pre-allocating up to position 0x%x in blk%05u.dat\n", nNewChunks * BLOCKFILE_CHUNK_SIZE, pos.nFile);
                    AllocateFileRange(file, pos.nPos, nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos);
                    fclose(file);
                }
            } else
                return state.Error("out of disk space");
        }
    }

    setDirtyFileInfo.insert(nFile);
    return true;
}

bool FindUndoPos(CValidationState& state, int nFile, CDiskBlockPos& pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    unsigned int nNewSize;
    pos.nPos = vinfoBlockFile[nFile].nUndoSize;
    nNewSize = vinfoBlockFile[nFile].nUndoSize += nAddSize;
    setDirtyFileInfo.insert(nFile);

    unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    if (nNewChunks > nOldChunks) {
        if (fPruneMode)
            fCheckForPruning = true;
        if (CheckDiskSpace(nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos)) {
            FILE* file = OpenUndoFile(pos);
            if (file) {
                LogPrintf("Pre-allocating up to position 0x%x in rev%05u.dat\n", nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
                AllocateFileRange(file, pos.nPos, nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
                fclose(file);
            }
        } else
            return state.Error("out of disk space");
    }

    return true;
}

// Protected by cs_main
VersionBitsCache versionbitscache;

int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params, bool fAssumeMasternodeIsUpgraded)
{
    LOCK(cs_main);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int) Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        Consensus::DeploymentPos pos = Consensus::DeploymentPos(i);
        ThresholdState state = VersionBitsState(pindexPrev, params, pos, versionbitscache);
        const struct BIP9DeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
        if (vbinfo.check_mn_protocol && state == THRESHOLD_STARTED && !fAssumeMasternodeIsUpgraded) {
            CScript payee;
            masternode_info_t mnInfo;
            if (!mnpayments.GetBlockPayee(pindexPrev->nHeight + 1, payee)) {
                // no votes for this block
                continue;
            }
            if (!mnodeman.GetMasternodeInfo(payee, mnInfo)) {
                // unknown masternode
                continue;
            }
        }
        if (state == THRESHOLD_LOCKED_IN || state == THRESHOLD_STARTED) {
            nVersion |= VersionBitsMask(params, (Consensus::DeploymentPos)i);
        }
    }

    return nVersion;
}

bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, bool fCheckPOW)
{
    // Check block version
    if (block.nVersion < MIN_BLOCK_VERSION)
        return state.DoS(100, error("CheckBlockHeader(): block version too low"),
                         REJECT_INVALID, "version-too-low");

    // Check Equihash solution is valid
    if (fCheckPOW && !CheckEquihashSolution(&block, Params()))
        return state.DoS(100, error("CheckBlockHeader(): Equihash solution invalid"),
                         REJECT_INVALID, "invalid-solution");

    // Check proof of work matches claimed amount
    if (fCheckPOW && !CheckProofOfWork(block.GetPoWHash(), block.nBits, Params().GetConsensus()))
        return state.DoS(50, error("CheckBlockHeader(): proof of work failed"),
                         REJECT_INVALID, "high-hash");

    // Check block vibpool
    if (block.nVibPool < 0)
        return state.DoS(100, error("CHeckBlockHeader(): block vibpool is negative"),
                         REJECT_INVALID, "invalid-vibpool");

    // Check timestamp
    if (block.GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
        return state.Invalid(error("CheckBlockHeader(): block timestamp too far in the future"),
                             REJECT_INVALID, "time-too-new");

    return true;
}

bool CheckBlock(const CBlock& block, CValidationState& state,
                libzcash::ProofVerifier& verifier,
                bool fCheckPOW, bool fCheckMerkleRoot)
{
    // These are checks that are independent of context.

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, fCheckPOW))
        return false;

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;
        uint256 hashMerkleRoot2 = block.BuildMerkleTree(&mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.DoS(100, error("CheckBlock(): hashMerkleRoot mismatch"),
                             REJECT_INVALID, "bad-txnmrklroot", true);

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.DoS(100, error("CheckBlock(): duplicate transaction"),
                             REJECT_INVALID, "bad-txns-duplicate", true);
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.

    // Size limits
    if (block.vtx.empty() || block.vtx.size() > MAX_BLOCK_SIZE || ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return state.DoS(100, error("CheckBlock(): size limits failed"),
                         REJECT_INVALID, "bad-blk-length");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.DoS(100, error("CheckBlock(): first tx is not coinbase"),
                         REJECT_INVALID, "bad-cb-missing");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.DoS(100, error("CheckBlock(): more than one coinbase"),
                             REJECT_INVALID, "bad-cb-multiple");

    // Check transactions
    for (const auto& tx : block.vtx) {
        if (!CheckTransaction(*tx, state, verifier))
            return error("CheckBlock(): CheckTransaction failed");
    }

    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx) {
        nSigOps += GetLegacySigOpCount(*tx);
    }
    if (nSigOps > MAX_BLOCK_SIGOPS)
        return state.DoS(100, error("CheckBlock(): out-of-bounds SigOpCount"),
                         REJECT_INVALID, "bad-blk-sigops", true);

    return true;
}

static bool CheckIndexAgainstCheckpoint(const CBlockIndex* pindexPrev, CValidationState& state, const CChainParams& chainparams, const uint256& hash)
{
    if (*pindexPrev->phashBlock == chainparams.GetConsensus().hashGenesisBlock)
        return true;

    int nHeight = pindexPrev->nHeight + 1;
    // Don't accept any forks from the main chain prior to last checkpoint
    CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(chainparams.Checkpoints());
    if (pcheckpoint && nHeight < pcheckpoint->nHeight)
        return state.DoS(100, error("%s: forked chain older than last checkpoint (height %d)", __func__, nHeight));

    return true;
}

bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, CBlockIndex* const pindexPrev)
{

    uint256 hash = block.GetHash();
    if (hash == consensusParams.hashGenesisBlock)
        return true;

    assert(pindexPrev);

    int nHeight = pindexPrev->nHeight + 1;

    // Check proof of work
    if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
        return state.DoS(100, error("%s: incorrect proof of work", __func__),
                         REJECT_INVALID, "bad-diffbits");

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(error("%s: block's timestamp is too early", __func__),
                             REJECT_INVALID, "time-too-old");

    // Reject block.nVersion < 4 blocks
    if (block.nVersion < 4)
        return state.Invalid(error("%s : rejected nVersion<4 block", __func__),
                             REJECT_OBSOLETE, "bad-version");

    return true;
}

bool ContextualCheckBlock(const CBlock& block, CValidationState& state, CBlockIndex* const pindexPrev)
{
    const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;
    const CChainParams& chainParams = Params();

    // Check that all transactions are finalized
    for (const auto& tx : block.vtx) {

        // Check transaction contextually against consensus rules at block height
        if (!ContextualCheckTransaction(*tx, state, nHeight, 100)) {
            return false; // Failure reason has been set in validation state object
        }

        int nLockTimeFlags = 0;
        if (nHeight < chainParams.GetConsensus().nTandiaBallotStart && tx->nFlag == CTransaction::TANDIA_TX)
            return state.DoS(10, error("%s: contains a tandia vote transaction", __func__), REJECT_INVALID, "bad-txns-tandiavote");

        int64_t nLockTimeCutoff = (nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST)
                                  ? pindexPrev->GetMedianTimePast()
                                  : block.GetBlockTime();
        if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff)) {
            return state.DoS(10, error("%s: contains a non-final transaction %s", __func__, tx->ToString()), REJECT_INVALID, "bad-txns-nonfinal");
        }
    }

    // Enforce block.nVersion=2 rule that the coinbase starts with serialized block height
    // if 750 of the last 1,000 blocks are version 2 or greater (51/100 if testnet):
    // Since MIN_BLOCK_VERSION = 4 all blocks with nHeight > 0 should satisfy this.
    // This rule is not applied to the genesis block, which didn't include the height
    // in the coinbase.
    if (nHeight > 0) {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
                !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
            return state.DoS(100, error("%s: block height mismatch in coinbase", __func__), REJECT_INVALID, "bad-cb-height");
        }
    }

    return true;
}

static bool AcceptBlockHeader(const CBlockHeader& block, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex)
{
    AssertLockHeld(cs_main);
    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator miSelf = mapBlockIndex.find(hash);
    CBlockIndex* pindex = nullptr;
    if (hash != chainparams.GetConsensus().hashGenesisBlock) {
        if (miSelf != mapBlockIndex.end()) {
            // Block header is already known.
            pindex = miSelf->second;
            if (ppindex)
                *ppindex = pindex;
            if (pindex->nStatus & BLOCK_FAILED_MASK)
                return state.Invalid(error("%s: block is marked invalid", __func__), 0, "duplicate");
            return true;
        }

        if (!CheckBlockHeader(block, state))
            return false;

        // Get prev block index
        CBlockIndex* pindexPrev = nullptr;
        BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        if (mi == mapBlockIndex.end())
            return state.DoS(10, error("%s: prev block not found", __func__), 0, "bad-prevblk");
        pindexPrev = (*mi).second;
        if (pindexPrev->nStatus & BLOCK_FAILED_MASK)
            return state.DoS(100, error("%s: prev block invalid", __func__), REJECT_INVALID, "bad-prevblk");

        assert(pindexPrev);
        if (fCheckpointsEnabled && !CheckIndexAgainstCheckpoint(pindexPrev, state, chainparams, hash))
            return error("%s: CheckIndexAgainstCheckpoint(): %s", __func__, state.GetRejectReason().c_str());

        if (!ContextualCheckBlockHeader(block, state, chainparams.GetConsensus(), pindexPrev))
            return error("%s: Consensus::ContextualCheckBlockHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));

    }

    if (pindex == nullptr)
        pindex = AddToBlockIndex(block);

    if (ppindex)
        *ppindex = pindex;

    CheckBlockIndex(chainparams.GetConsensus());

    return true;
}

// Exposed wrapper for AcceptBlockHeader

bool ProcessNewBlockHeaders(const std::vector<CBlockHeader>& headers, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex)
{
    {
        LOCK(cs_main);
        for (const CBlockHeader& header : headers) {
            if (!AcceptBlockHeader(header, state, chainparams, ppindex)) {
                return false;
            }
        }
    }
    NotifyHeaderTip();
    return true;
}

static bool AcceptBlock(const CBlock& block, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex, bool fRequested, const CDiskBlockPos* dbp, bool* fNewBlock)
{
    if (fNewBlock) *fNewBlock = false;
    AssertLockHeld(cs_main);

    CBlockIndex* pindexDummy = nullptr;
    CBlockIndex*& pindex = ppindex ? *ppindex : pindexDummy;

    if (!AcceptBlockHeader(block, state, chainparams, &pindex))
        return false;

    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    bool fHasMoreWork = (chainActive.Tip() ? pindex->nChainWork > chainActive.Tip()->nChainWork : true);
    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead = (pindex->nHeight > int(chainActive.Height() + MIN_BLOCKS_TO_KEEP));

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave) return true;
    if (!fRequested) { // If we didn't ask for it:
        if (pindex->nTx != 0) return true; // This is a previously-processed block that was pruned
        if (!fHasMoreWork) return true; // Don't process less-work chains
        if (fTooFarAhead) return true; // Block height is too high
    }

    if (fNewBlock) *fNewBlock = true;


    // See method docstring for why this is always disabled
    auto verifier = libzcash::ProofVerifier::Disabled();
    if ((!CheckBlock(block, state, verifier)) || !ContextualCheckBlock(block, state, pindex->pprev)) {
        if (state.IsInvalid() && !state.CorruptionPossible()) {
            pindex->nStatus |= BLOCK_FAILED_VALID;
            setDirtyBlockIndex.insert(pindex);
        }
        return false;
    }

    int nHeight = pindex->nHeight;

    // Write block to history file
    try {
        unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
        CDiskBlockPos blockPos;
        if (dbp != nullptr)
            blockPos = *dbp;
        if (!FindBlockPos(state, blockPos, nBlockSize + 8, nHeight, block.GetBlockTime(), dbp != NULL))
            return error("AcceptBlock(): FindBlockPos failed");
        if (dbp == nullptr)
            if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart()))
                AbortNode(state, "Failed to write block");
        if (!ReceivedBlockTransactions(block, state, pindex, blockPos))
            return error("AcceptBlock(): ReceivedBlockTransactions failed");
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error: ") + e.what());
    }

    if (fCheckForPruning)
        FlushStateToDisk(state, FLUSH_STATE_NONE); // we just allocated more disk space for block files

    return true;
}

static bool IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned nRequired, const Consensus::Params& consensusParams)
{
    unsigned int nFound = 0;
    for (int i = 0; i < consensusParams.nMajorityWindow && nFound < nRequired && pstart != nullptr; i++) {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}

bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, const CDiskBlockPos* dbp, bool* fNewBlock)
{
    AssertLockNotHeld(cs_main);

    // Preliminary checks
    auto verifier = libzcash::ProofVerifier::Disabled();
    {
        // Store to disk
        CBlockIndex* pindex = nullptr;
        if (fNewBlock) *fNewBlock = false;
        CValidationState state;
        auto disabledVerifier = libzcash::ProofVerifier::Disabled();

        bool ret = CheckBlock(*pblock, state, disabledVerifier);

        LOCK(cs_main);

        if (ret) {
            ret = AcceptBlock(*pblock, state, chainparams, &pindex, fForceProcessing, dbp, fNewBlock);
        }

        if (!ret) {
            GetMainSignals().BlockChecked(*pblock, state);
            return error("%s: AcceptBlock FAILED", __func__);
        }
        CheckBlockIndex(chainparams.GetConsensus());
    }

    NotifyHeaderTip();

    CValidationState state; // Only used to report errors, not invalidity - ignore it
    if (!ActivateBestChain(state, chainparams, pblock))
        return error("%s: ActivateBestChain failed", __func__);

    LogPrint("validation", "%s : ACCEPTED\n", __func__);

    return true;
}

bool TestBlockValidity(CValidationState& state, const CChainParams& chainparams, const CBlock& block, CBlockIndex* pindexPrev, bool fCheckPOW, bool fCheckMerkleRoot)
{
    AssertLockHeld(cs_main);
    assert(pindexPrev == chainActive.Tip());

    CCoinsViewCache viewNew(pcoinsTip);
    CClueViewCache viewClue(pclueTip);
    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;
    // JoinSplit proofs are verified in ConnectBlock
    auto verifier = libzcash::ProofVerifier::Disabled();

    // NOTE: CheckBlockHeader is called by CheckBlock
    if (!ContextualCheckBlockHeader(block, state, chainparams.GetConsensus(), pindexPrev))
        return false;
    if (!CheckBlock(block, state, verifier, fCheckPOW, fCheckMerkleRoot))
        return false;
    if (!ContextualCheckBlock(block, state, pindexPrev))
        return false;

    dev::h256 oldHashStateRoot(globalState->rootHash()); // qtum
    dev::h256 oldHashUTXORoot(globalState->rootHashUTXO()); // qtum

    if (!ConnectBlock(block, state, &indexDummy, viewNew, viewClue, true)) {
        globalState->setRoot(oldHashStateRoot); // qtum
        globalState->setRootUTXO(oldHashUTXORoot); // qtum
        pstorageresult->clearCacheResult();
        return false;
    }
    assert(state.IsValid());
    return true;
}

/**
 * BLOCK PRUNING CODE
 */

/* Calculate the amount of disk space the block & undo files currently use */
uint64_t CalculateCurrentUsage()
{
    uint64_t retval = 0;

    BOOST_FOREACH(const CBlockFileInfo & file, vinfoBlockFile) {
        retval += file.nSize + file.nUndoSize;
    }
    return retval;
}

/* Prune a block file (modify associated database entries)*/
void PruneOneBlockFile(const int fileNumber)
{
    for (BlockMap::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); ++it) {
        CBlockIndex* pindex = it->second;
        if (pindex->nFile == fileNumber) {
            pindex->nStatus &= ~BLOCK_HAVE_DATA;
            pindex->nStatus &= ~BLOCK_HAVE_UNDO;
            pindex->nFile = 0;
            pindex->nDataPos = 0;
            pindex->nUndoPos = 0;
            setDirtyBlockIndex.insert(pindex);

            // Prune from mapBlocksUnlinked -- any block we prune would have
            // to be downloaded again in order to consider its chain, at which
            // point it would be considered as a candidate for
            // mapBlocksUnlinked or setBlockIndexCandidates.
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex->pprev);
            while (range.first != range.second) {
                std::multimap<CBlockIndex*, CBlockIndex*>::iterator it = range.first;
                range.first++;
                if (it->second == pindex) {
                    mapBlocksUnlinked.erase(it);
                }
            }
        }
    }

    vinfoBlockFile[fileNumber].SetNull();
    setDirtyFileInfo.insert(fileNumber);
}

void UnlinkPrunedFiles(std::set<int>& setFilesToPrune)
{
    for (set<int>::iterator it = setFilesToPrune.begin(); it != setFilesToPrune.end(); ++it) {
        CDiskBlockPos pos(*it, 0);
        boost::filesystem::remove(GetBlockPosFilename(pos, "blk"));
        boost::filesystem::remove(GetBlockPosFilename(pos, "rev"));
        LogPrintf("Prune: %s deleted blk/rev (%05u)\n", __func__, *it);
    }
}

/* Calculate the block/rev files that should be deleted to remain under target*/
void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight)
{
    LOCK2(cs_main, cs_LastBlockFile);
    if (chainActive.Tip() == nullptr || nPruneTarget == 0) {
        return;
    }

    if ((uint64_t) chainActive.Tip()->nHeight <= nPruneAfterHeight) {
        return;
    }

    unsigned int nLastBlockWeCanPrune = chainActive.Tip()->nHeight - MIN_BLOCKS_TO_KEEP;
    uint64_t nCurrentUsage = CalculateCurrentUsage();
    // We don't check to prune until after we've allocated new space for files
    // So we should leave a buffer under our target to account for another allocation
    // before the next pruning.
    uint64_t nBuffer = BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE;
    uint64_t nBytesToPrune;
    int count = 0;

    if (nCurrentUsage + nBuffer >= nPruneTarget) {
        for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
            nBytesToPrune = vinfoBlockFile[fileNumber].nSize + vinfoBlockFile[fileNumber].nUndoSize;

            if (vinfoBlockFile[fileNumber].nSize == 0)
                continue;

            if (nCurrentUsage + nBuffer < nPruneTarget) // are we below our target?
                break;

            // don't prune files that could have a block within MIN_BLOCKS_TO_KEEP of the main chain's tip but keep scanning
            if (vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
                continue;

            PruneOneBlockFile(fileNumber);
            // Queue up the files for removal
            setFilesToPrune.insert(fileNumber);
            nCurrentUsage -= nBytesToPrune;
            count++;
        }
    }

    LogPrint("prune", "Prune: target=%dMiB actual=%dMiB diff=%dMiB max_prune_height=%d removed %d blk/rev pairs\n",
             nPruneTarget / 1024 / 1024, nCurrentUsage / 1024 / 1024,
             ((int64_t) nPruneTarget - (int64_t) nCurrentUsage) / 1024 / 1024,
             nLastBlockWeCanPrune, count);
}

bool CheckDiskSpace(uint64_t nAdditionalBytes)
{
    uint64_t nFreeBytesAvailable = boost::filesystem::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
        return AbortNode("Disk space is low!", _("Error: Disk space is low!"));

    return true;
}

FILE* OpenDiskFile(const CDiskBlockPos& pos, const char* prefix, bool fReadOnly)
{
    if (pos.IsNull())
        return nullptr;
    boost::filesystem::path path = GetBlockPosFilename(pos, prefix);
    boost::filesystem::create_directories(path.parent_path());
    FILE* file = fopen(path.string().c_str(), "rb+");
    if (!file && !fReadOnly)
        file = fopen(path.string().c_str(), "wb+");
    if (!file) {
        LogPrintf("Unable to open file %s\n", path.string());
        return nullptr;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            LogPrintf("Unable to seek to position %u of %s\n", pos.nPos, path.string());
            fclose(file);
            return nullptr;
        }
    }
    return file;
}

FILE* OpenBlockFile(const CDiskBlockPos& pos, bool fReadOnly)
{
    return OpenDiskFile(pos, "blk", fReadOnly);
}

FILE* OpenUndoFile(const CDiskBlockPos& pos, bool fReadOnly)
{
    return OpenDiskFile(pos, "rev", fReadOnly);
}

boost::filesystem::path GetBlockPosFilename(const CDiskBlockPos& pos, const char* prefix)
{
    return GetDataDir() / "blocks" / strprintf("%s%05u.dat", prefix, pos.nFile);
}

CBlockIndex* InsertBlockIndex(uint256 hash)
{
    if (hash.IsNull())
        return nullptr;

    // Return existing
    BlockMap::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    if (!pindexNew)
        throw runtime_error("LoadBlockIndex(): new CBlockIndex failed");
    mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool static LoadBlockIndexDB()
{
    const CChainParams& chainparams = Params();
    if (!pblocktree->LoadBlockIndexGuts(InsertBlockIndex))
        return false;

    boost::this_thread::interruption_point();

    // Calculate nChainWork
    vector<pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());

    BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*) & item, mapBlockIndex) {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());

    BOOST_FOREACH(const PAIRTYPE(int, CBlockIndex*) & item, vSortedByHeight) {
        CBlockIndex* pindex = item.second;
        pindex->nChainWork = (pindex->pprev ? pindex->pprev->nChainWork : 0) + GetBlockProof(*pindex);
        // We can link the chain of blocks for which we've received transactions at some point.
        // Pruned nodes may have deleted the block.
        if (pindex->nTx > 0) {
            if (pindex->pprev) {
                if (pindex->nHeight % chainparams.BlockCountOfWeek() == 0) {
                    if (pindex->nHeight >= chainparams.BlockCountOf1stSeason()) {
                        CAmount nLeft = GetBlockClueSubsidy(pindex->nHeight, chainparams.GetConsensus(), false) - GetBlockSubsidy(pindex->nHeight, Params().GetConsensus());
                        if ( nLeft > 0) {
                            pindex->nClueLeft = nLeft;
                        }
                    } else {
                        pindex->nClueLeft = 0;
                    }
                } else {
                    pindex->nClueLeft = (pindex->pprev ? pindex->pprev->nClueLeft : 0);
                }

                if (pindex->pprev->nChainTx) {
                    pindex->nChainTx = pindex->pprev->nChainTx + pindex->nTx;
                    pindex->nChainClueTx = pindex->pprev->nChainClueTx + pindex->nClueTx;
                    if (pindex->pprev->nChainSaplingValue) {
                        pindex->nChainSaplingValue = *pindex->pprev->nChainSaplingValue + pindex->nSaplingValue;
                    } else {
                        pindex->nChainSaplingValue = boost::none;
                    }
                } else {
                    pindex->nChainTx = 0;
                    pindex->nChainClueTx = 0;
                    pindex->nChainSaplingValue = boost::none;
                    mapBlocksUnlinked.insert(std::make_pair(pindex->pprev, pindex));
                }
            } else {
                pindex->nChainTx = pindex->nTx;
                pindex->nChainSaplingValue = pindex->nSaplingValue;
                pindex->nChainClueTx = pindex->nChainClueTx;
            }
        }
        if (!(pindex->nStatus & BLOCK_FAILED_MASK) && pindex->pprev && (pindex->pprev->nStatus & BLOCK_FAILED_MASK)) {
            pindex->nStatus |= BLOCK_FAILED_CHILD;
            setDirtyBlockIndex.insert(pindex);
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && (pindex->nChainTx || pindex->pprev == nullptr))
            setBlockIndexCandidates.insert(pindex);
        if (pindex->nStatus & BLOCK_FAILED_MASK && (!pindexBestInvalid || pindex->nChainWork > pindexBestInvalid->nChainWork))
            pindexBestInvalid = pindex;
        if (pindex->pprev)
            pindex->BuildSkip();
        if (pindex->IsValid(BLOCK_VALID_TREE) && (pindexBestHeader == nullptr || CBlockIndexWorkComparator()(pindexBestHeader, pindex)))
            pindexBestHeader = pindex;
    }

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    vinfoBlockFile.resize(nLastBlockFile + 1);
    LogPrintf("%s: last block file = %i\n", __func__, nLastBlockFile);
    for (int nFile = 0; nFile <= nLastBlockFile; nFile++) {
        pblocktree->ReadBlockFileInfo(nFile, vinfoBlockFile[nFile]);
    }
    LogPrintf("%s: last block file info: %s\n", __func__, vinfoBlockFile[nLastBlockFile].ToString());
    for (int nFile = nLastBlockFile + 1; true; nFile++) {
        CBlockFileInfo info;
        if (pblocktree->ReadBlockFileInfo(nFile, info)) {
            vinfoBlockFile.push_back(info);
        } else {
            break;
        }
    }

    // Check presence of blk files
    LogPrintf("Checking all blk files are present...\n");
    set<int> setBlkDataFiles;

    BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*) & item, mapBlockIndex) {
        CBlockIndex* pindex = item.second;
        if (pindex->nStatus & BLOCK_HAVE_DATA) {
            setBlkDataFiles.insert(pindex->nFile);
        }
    }
    for (std::set<int>::iterator it = setBlkDataFiles.begin(); it != setBlkDataFiles.end(); it++) {
        CDiskBlockPos pos(*it, 0);
        if (CAutoFile(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION).IsNull()) {
            return false;
        }
    }

    // Check whether we have ever pruned block & undo files
    pblocktree->ReadFlag("prunedblockfiles", fHavePruned);
    if (fHavePruned)
        LogPrintf("LoadBlockIndexDB(): Block files have previously been pruned\n");

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pblocktree->ReadReindexing(fReindexing);
    fReindex |= fReindexing;

    // Check whether we have a transaction index
    pblocktree->ReadFlag("txindex", fTxIndex);
    LogPrintf("%s: transaction index %s\n", __func__, fTxIndex ? "enabled" : "disabled");

    // Fill in-memory data

    // Load pointer to end of best chain
    BlockMap::iterator it = mapBlockIndex.find(pcoinsTip->GetBestBlock());
    if (it == mapBlockIndex.end())
        return true;

    chainActive.SetTip(it->second);

    PruneBlockIndexCandidates();

    LogPrintf("%s: hashBestChain=%s height=%d date=%s progress=%f\n", __func__,
              chainActive.Tip()->GetBlockHash().ToString(), chainActive.Height(),
              DateTimeStrFormat("%Y-%m-%d %H:%M:%S", chainActive.Tip()->GetBlockTime()),
              Checkpoints::GuessVerificationProgress(chainparams.Checkpoints(), chainActive.Tip()));

    EnforceNodeDeprecation(chainActive.Height(), true);

    return true;
}

CVerifyDB::CVerifyDB()
{
    uiInterface.ShowProgress(_("Verifying Blocks..."), 0);
}

CVerifyDB::~CVerifyDB()
{
    uiInterface.ShowProgress("", 100);
}

bool CVerifyDB::VerifyDB(const CChainParams& chainparams, CCoinsView* coinsview, CClueView* clueview, int nCheckLevel, int nCheckDepth)
{
    LOCK(cs_main);
    if (chainActive.Tip() == nullptr || chainActive.Tip()->pprev == nullptr)
        return true;

    // Verify blocks in the best chain
    if (nCheckDepth <= 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > chainActive.Height())
        nCheckDepth = chainActive.Height();
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(coinsview);
    CClueViewCache clues(clueview);
    CBlockIndex* pindexState = chainActive.Tip();
    CBlockIndex* pindexFailure = nullptr;
    int nGoodTransactions = 0;
    CValidationState state;

    ////////////////////////////////////////////////////////////////////////// // qtum
    dev::h256 oldHashStateRoot(globalState->rootHash());
    dev::h256 oldHashUTXORoot(globalState->rootHashUTXO());
    QtumDGP qtumDGP(globalState.get(), fGettingValuesDGP);
    //////////////////////////////////////////////////////////////////////////

    // No need to verify JoinSplits twice
    auto verifier = libzcash::ProofVerifier::Disabled();
    for (CBlockIndex* pindex = chainActive.Tip(); pindex && pindex->pprev; pindex = pindex->pprev) {
        boost::this_thread::interruption_point();
        uiInterface.ShowProgress(_("Verifying Blocks..."), std::max(1, std::min(99, (int) (((double) (chainActive.Height() - pindex->nHeight)) / (double) nCheckDepth * (nCheckLevel >= 4 ? 50 : 100)))));
        if (pindex->nHeight < chainActive.Height() - nCheckDepth)
            break;
        CBlock block;
        // check level 0: read from disk
        if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
            return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state, verifier))
            return error("VerifyDB(): *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            CDiskBlockPos pos = pindex->GetUndoPos();
            if (!pos.IsNull()) {
                if (!UndoReadFromDisk(undo, pos, pindex->pprev->GetBlockHash()))
                    return error("VerifyDB(): *** found bad undo data at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        if (nCheckLevel >= 3 && pindex == pindexState && (coins.DynamicMemoryUsage() + pcoinsTip->DynamicMemoryUsage()) <= nCoinCacheUsage) {
            DisconnectResult res = DisconnectBlock(block, state, pindex, coins, clues);
            if (res == DISCONNECT_FAILED) {
                return error("VerifyDB(): *** irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            }

            pindexState = pindex->pprev;
            if (res == DISCONNECT_UNCLEAN) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } else {
                nGoodTransactions += block.vtx.size();
            }
        }
        if (ShutdownRequested())
            return true;
    }

    if (pindexFailure)
        return error("VerifyDB(): *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", chainActive.Height() - pindexFailure->nHeight + 1, nGoodTransactions);

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        CBlockIndex* pindex = pindexState;
        while (pindex != chainActive.Tip()) {
            boost::this_thread::interruption_point();
            uiInterface.ShowProgress(_("Verifying Blocks..."), std::max(1, std::min(99, 100 - (int) (((double) (chainActive.Height() - pindex->nHeight)) / (double) nCheckDepth * 50))));
            pindex = chainActive.Next(pindex);
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
                return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());

            dev::h256 oldHashStateRoot(globalState->rootHash()); // qtum
            dev::h256 oldHashUTXORoot(globalState->rootHashUTXO()); // qtum

            if (!ConnectBlock(block, state, pindex, coins, clues)) {
                globalState->setRoot(oldHashStateRoot); // qtum
                globalState->setRootUTXO(oldHashUTXORoot); // qtum
                pstorageresult->clearCacheResult();
                return error("VerifyDB(): *** found unconnectable block at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            }
        }
    } else {
        globalState->setRoot(oldHashStateRoot); // qtum
        globalState->setRootUTXO(oldHashUTXORoot); // qtum
    }

    LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n", chainActive.Height() - pindexState->nHeight, nGoodTransactions);

    return true;
}

bool RewindBlockIndex(const CChainParams& params, bool& clearWitnessCaches)
{
    LOCK(cs_main);

    int nHeight = chainActive.Height() + 1;
    if (nHeight <= 0) return true;

    clearWitnessCaches = false;

    CValidationState state;
    CBlockIndex* pindex = chainActive.Tip();
    while (chainActive.Height() >= nHeight) {
        if (fPruneMode && !(chainActive.Tip()->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, don't try rewinding past the HAVE_DATA point;
            // since older blocks can't be served anyway, there's
            // no need to walk further, and trying to DisconnectTip()
            // will fail (and require a needless reindex/redownload
            // of the blockchain).
            break;
        }
        if (!DisconnectTip(state, params.GetConsensus(), nullptr)) {
            return error("RewindBlockIndex: unable to disconnect block at height %i", pindex->nHeight);
        }
        // Occasionally flush state to disk.
        if (!FlushStateToDisk(state, FLUSH_STATE_PERIODIC))
            return false;
    }

    LogPrintf("mapBlockIndex Size: %d, chainActive.Height: %d\n", mapBlockIndex.size(), chainActive.Height());
    // Collect blocks to be removed (blocks in mapBlockIndex must be at least BLOCK_VALID_TREE).
    // We do this after actual disconnecting, otherwise we'll end up writing the lack of data
    // to disk before writing the chainstate, resulting in a failure to continue if interrupted.
    for (BlockMap::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); it++) {
        CBlockIndex* pindexIter = it->second;
        // Note: If we encounter an insufficiently validated block that
        // is on chainActive, it must be because we are a pruning node, and
        // this block or some successor doesn't HAVE_DATA, so we were unable to
        // rewind all the way.  Blocks remaining on chainActive at this point
        // must not have their validity reduced.
        if (!chainActive.Contains(pindexIter)) {
            // Add to the list of blocks to remove
            if (pindexIter == pindexBestInvalid) {
                // Reset invalid block marker if it was pointing to this block
                pindexBestInvalid = nullptr;
            }
            // Update indices
            setBlockIndexCandidates.erase(pindexIter);
            auto ret = mapBlocksUnlinked.equal_range(pindexIter->pprev);
            while (ret.first != ret.second) {
                if (ret.first->second == pindexIter) {
                    mapBlocksUnlinked.erase(ret.first++);
                } else {
                    ++ret.first;
                }
            }
        } else if (pindexIter->IsValid(BLOCK_VALID_TRANSACTIONS) && pindexIter->nChainTx) {
            setBlockIndexCandidates.insert(pindexIter);
        }
    }

    // Set pindexBestHeader to the current chain tip
    // (since we are about to delete the block it is pointing to)
    pindexBestHeader = chainActive.Tip();

    if (chainActive.Tip() != nullptr) {

        PruneBlockIndexCandidates();

        CheckBlockIndex(params.GetConsensus());
    }
    if (!FlushStateToDisk(state, FLUSH_STATE_ALWAYS)) {
        return false;
    }

    return true;
}


void UnloadBlockIndex()
{
    LOCK(cs_main);
    setBlockIndexCandidates.clear();
    chainActive.SetTip(nullptr);
    pindexBestInvalid = nullptr;
    pindexBestHeader = nullptr;
    mempool.clear();
    nSyncStarted = 0;
    mapBlocksUnlinked.clear();
    vinfoBlockFile.clear();
    nLastBlockFile = 0;
    nBlockSequenceId = 1;
    setDirtyBlockIndex.clear();
    setDirtyFileInfo.clear();

    BOOST_FOREACH(BlockMap::value_type & entry, mapBlockIndex) {
        delete entry.second;
    }
    mapBlockIndex.clear();
    fHavePruned = false;
}

bool LoadBlockIndex()
{
    // Load block index from databases
    if (!fReindex && !LoadBlockIndexDB())
        return false;
    return true;
}

bool InitBlockIndex(const CChainParams& chainparams)
{
    LOCK(cs_main);

    // Check whether we're already initialized
    if (chainActive.Genesis() != nullptr)
        return true;

    // Use the provided setting for -txindex in the new database
    fTxIndex = GetBoolArg("-txindex", DEFAULT_TXINDEX);
    pblocktree->WriteFlag("txindex", fTxIndex);

    // Use the provided setting for -addressindex in the new database
    fAddressIndex = GetBoolArg("-addressindex", DEFAULT_ADDRESSINDEX);
    pblocktree->WriteFlag("addressindex", fAddressIndex);


    // Only add the genesis block if not reindexing (in which case we reuse the one already on disk)
    if (!fReindex) {
        try {
            CBlock& block = const_cast<CBlock&> (Params().GenesisBlock());
            // Start new block file
            unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
            CDiskBlockPos blockPos;
            CValidationState state;
            if (!FindBlockPos(state, blockPos, nBlockSize + 8, 0, block.GetBlockTime()))
                return error("LoadBlockIndex(): FindBlockPos failed");
            if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart()))
                return error("LoadBlockIndex(): writing genesis block to disk failed");
            CBlockIndex* pindex = AddToBlockIndex(block);
            if (!ReceivedBlockTransactions(block, state, pindex, blockPos))
                return error("LoadBlockIndex(): genesis block not accepted");
            // Force a chainstate write so that when we VerifyDB in a moment, it doesn't check stale data
            return FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
        } catch (const std::runtime_error& e) {
            return error("LoadBlockIndex(): failed to initialize block database: %s", e.what());
        }
    }

    return true;
}

bool LoadExternalBlockFile(const CChainParams& chainparams, FILE* fileIn, CDiskBlockPos* dbp)
{
    // Map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, CDiskBlockPos> mapBlocksUnknownParent;
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2 * MAX_BLOCK_SIZE, MAX_BLOCK_SIZE + 8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) {
            boost::this_thread::interruption_point();

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[MESSAGE_START_SIZE];
                blkdat.FindByte(Params().MessageStart()[0]);
                nRewind = blkdat.GetPos() + 1;
                blkdat >> FLATDATA(buf);
                if (memcmp(buf, Params().MessageStart(), MESSAGE_START_SIZE))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BLOCK_SIZE)
                    continue;
            } catch (const std::exception&) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                blkdat.SetPos(nBlockPos);
                CBlock block;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                // detect out of order blocks, and store them for later
                uint256 hash = block.GetHash();
                if (hash != chainparams.GetConsensus().hashGenesisBlock && mapBlockIndex.find(block.hashPrevBlock) == mapBlockIndex.end()) {
                    LogPrint("reindex", "%s: Out of order block %s, parent %s not known\n", __func__, hash.ToString(),
                             block.hashPrevBlock.ToString());
                    if (dbp)
                        mapBlocksUnknownParent.insert(std::make_pair(block.hashPrevBlock, *dbp));
                    continue;
                }

                // process in case the block isn't known yet
                if (mapBlockIndex.count(hash) == 0 || (mapBlockIndex[hash]->nStatus & BLOCK_HAVE_DATA) == 0) {
                    LOCK(cs_main);
                    CValidationState state;
                    if (AcceptBlock(block, state, chainparams, nullptr, true, dbp, nullptr))
                        nLoaded++;
                    if (state.IsError())
                        break;
                } else if (hash != chainparams.GetConsensus().hashGenesisBlock && mapBlockIndex[hash]->nHeight % 1000 == 0) {
                    LogPrint("reindex", "Block Import: already had block %s at height %d\n", hash.ToString(), mapBlockIndex[hash]->nHeight);
                }

                {
                    CValidationState state;
                    if (!ActivateBestChain(state, chainparams)) {
                        break;
                    }
                }

                NotifyHeaderTip();

                // Recursively process earlier encountered successors of this block
                deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, CDiskBlockPos>::iterator, std::multimap<uint256, CDiskBlockPos>::iterator> range = mapBlocksUnknownParent.equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<uint256, CDiskBlockPos>::iterator it = range.first;
                        if (ReadBlockFromDisk(block, it->second, chainparams.GetConsensus())) {
                            LogPrintf("%s: Processing out of order child %s of %s\n", __func__, block.GetHash().ToString(),
                                      head.ToString());
                            CValidationState dummy;
                            LOCK(cs_main);
                            if (AcceptBlock(block, dummy, chainparams, nullptr, true, &it->second, nullptr)) {
                                nLoaded++;
                                queue.push_back(block.GetHash());
                            }
                        }
                        range.first++;
                        mapBlocksUnknownParent.erase(it);
                        NotifyHeaderTip();
                    }
                }
            } catch (const std::exception& e) {
                LogPrintf("%s: Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    } catch (const std::runtime_error& e) {
        AbortNode(std::string("System error: ") + e.what());
    }
    if (nLoaded > 0)
        LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

void static CheckBlockIndex(const Consensus::Params& consensusParams)
{
    if (!fCheckBlockIndex) {
        return;
    }

    LOCK(cs_main);

    // During a reindex, we read the genesis block and call CheckBlockIndex before ActivateBestChain,
    // so we have the genesis block in mapBlockIndex but no active chain.  (A few of the tests when
    // iterating the block tree require that chainActive has been initialized.)
    if (chainActive.Height() < 0) {
        assert(mapBlockIndex.size() <= 1);
        return;
    }

    // Build forward-pointing map of the entire block tree.
    std::multimap<CBlockIndex*, CBlockIndex*> forward;
    for (BlockMap::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); it++) {
        assert(it->second != nullptr);
        forward.insert(std::make_pair(it->second->pprev, it->second));
    }

    assert(forward.size() == mapBlockIndex.size());

    std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> rangeGenesis = forward.equal_range(nullptr);
    CBlockIndex* pindex = rangeGenesis.first->second;
    rangeGenesis.first++;
    assert(rangeGenesis.first == rangeGenesis.second); // There is only one index entry with parent NULL.

    // Iterate over the entire block tree, using depth-first search.
    // Along the way, remember whether there are blocks on the path from genesis
    // block being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    CBlockIndex* pindexFirstInvalid = nullptr; // Oldest ancestor of pindex which is invalid.
    CBlockIndex* pindexFirstMissing = nullptr; // Oldest ancestor of pindex which does not have BLOCK_HAVE_DATA.
    CBlockIndex* pindexFirstNeverProcessed = nullptr; // Oldest ancestor of pindex for which nTx == 0.
    CBlockIndex* pindexFirstNotTreeValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TREE (regardless of being valid or not).
    CBlockIndex* pindexFirstNotTransactionsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TRANSACTIONS (regardless of being valid or not).
    CBlockIndex* pindexFirstNotChainValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_CHAIN (regardless of being valid or not).
    CBlockIndex* pindexFirstNotScriptsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_SCRIPTS (regardless of being valid or not).
    while (pindex != nullptr) {
        nNodes++;
        if (pindexFirstInvalid == nullptr && pindex->nStatus & BLOCK_FAILED_VALID) pindexFirstInvalid = pindex;
        if (pindexFirstMissing == nullptr && !(pindex->nStatus & BLOCK_HAVE_DATA)) pindexFirstMissing = pindex;
        if (pindexFirstNeverProcessed == nullptr && pindex->nTx == 0) pindexFirstNeverProcessed = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotTreeValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE) pindexFirstNotTreeValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotTransactionsValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS) pindexFirstNotTransactionsValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotChainValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_CHAIN) pindexFirstNotChainValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotScriptsValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) pindexFirstNotScriptsValid = pindex;

        // Begin: actual consistency checks.
        if (pindex->pprev == nullptr) {
            // Genesis block checks.
            assert(pindex->GetBlockHash() == consensusParams.hashGenesisBlock); // Genesis block's hash must match.
            assert(pindex == chainActive.Genesis()); // The current active chain's genesis block must be this block.
        }
        if (pindex->nChainTx == 0) assert(pindex->nSequenceId == 0); // nSequenceId can't be set for blocks that aren't linked
        // VALID_TRANSACTIONS is equivalent to nTx > 0 for all nodes (whether or not pruning has occurred).
        // HAVE_DATA is only equivalent to nTx > 0 (or VALID_TRANSACTIONS) if no pruning has occurred.
        if (!fHavePruned) {
            // If we've never pruned, then HAVE_DATA should be equivalent to nTx > 0
            assert(!(pindex->nStatus & BLOCK_HAVE_DATA) == (pindex->nTx == 0));
            assert(pindexFirstMissing == pindexFirstNeverProcessed);
        } else {
            // If we have pruned, then we can only say that HAVE_DATA implies nTx > 0
            if (pindex->nStatus & BLOCK_HAVE_DATA) assert(pindex->nTx > 0);
        }
        if (pindex->nStatus & BLOCK_HAVE_UNDO) assert(pindex->nStatus & BLOCK_HAVE_DATA);
        assert(((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS) == (pindex->nTx > 0)); // This is pruning-independent.
        // All parents having had data (at some point) is equivalent to all parents being VALID_TRANSACTIONS, which is equivalent to nChainTx being set.
        assert((pindexFirstNeverProcessed != nullptr) == (pindex->nChainTx == 0)); // nChainTx != 0 is used to signal that all parent blocks have been processed (but may have been pruned).
        assert((pindexFirstNotTransactionsValid != nullptr) == (pindex->nChainTx == 0));
        assert(pindex->nHeight == nHeight); // nHeight must be consistent.
        assert(pindex->pprev == nullptr || pindex->nChainWork >= pindex->pprev->nChainWork); // For every block except the genesis block, the chainwork must be larger than the parent's.
        assert(nHeight < 2 || (pindex->pskip && (pindex->pskip->nHeight < nHeight))); // The pskip pointer must point back for all but the first 2 blocks.
        assert(pindexFirstNotTreeValid == nullptr); // All mapBlockIndex entries must at least be TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE) assert(pindexFirstNotTreeValid == nullptr); // TREE valid implies all parents are TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_CHAIN) assert(pindexFirstNotChainValid == nullptr); // CHAIN valid implies all parents are CHAIN valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS) assert(pindexFirstNotScriptsValid == nullptr); // SCRIPTS valid implies all parents are SCRIPTS valid
        if (pindexFirstInvalid == nullptr) {
            // Checks for not-invalid blocks.
            assert((pindex->nStatus & BLOCK_FAILED_MASK) == 0); // The failed mask cannot be set for blocks without invalid parents.
        }
        if (!CBlockIndexWorkComparator()(pindex, chainActive.Tip()) && pindexFirstNeverProcessed == nullptr) {
            if (pindexFirstInvalid == nullptr) {
                // If this block sorts at least as good as the current tip and
                // is valid and we have all data for its parents, it must be in
                // setBlockIndexCandidates.  chainActive.Tip() must also be there
                // even if some data has been pruned.
                if (pindexFirstMissing == nullptr || pindex == chainActive.Tip()) {
                    assert(setBlockIndexCandidates.count(pindex));
                }
                // If some parent is missing, then it could be that this block was in
                // setBlockIndexCandidates but had to be removed because of the missing data.
                // In this case it must be in mapBlocksUnlinked -- see test below.
            }
        } else { // If this block sorts worse than the current tip or some ancestor's block has never been seen, it cannot be in setBlockIndexCandidates.
            assert(setBlockIndexCandidates.count(pindex) == 0);
        }
        // Check whether this block is in mapBlocksUnlinked.
        std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> rangeUnlinked = mapBlocksUnlinked.equal_range(pindex->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second) {
            assert(rangeUnlinked.first->first == pindex->pprev);
            if (rangeUnlinked.first->second == pindex) {
                foundInUnlinked = true;
                break;
            }
            rangeUnlinked.first++;
        }
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed != nullptr && pindexFirstInvalid == nullptr) {
            // If this block has block data available, some parent was never received, and has no invalid parents, it must be in mapBlocksUnlinked.
            assert(foundInUnlinked);
        }
        if (!(pindex->nStatus & BLOCK_HAVE_DATA)) assert(!foundInUnlinked); // Can't be in mapBlocksUnlinked if we don't HAVE_DATA
        if (pindexFirstMissing == nullptr) assert(!foundInUnlinked); // We aren't missing data for any parent -- cannot be in mapBlocksUnlinked.
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed == nullptr && pindexFirstMissing != nullptr) {
            // We HAVE_DATA for this block, have received data for all parents at some point, but we're currently missing data for some parent.
            assert(fHavePruned); // We must have pruned.
            // This block may have entered mapBlocksUnlinked if:
            //  - it has a descendant that at some point had more work than the
            //    tip, and
            //  - we tried switching to that descendant but were missing
            //    data for some intermediate block between chainActive and the
            //    tip.
            // So if this block is itself better than chainActive.Tip() and it wasn't in
            // setBlockIndexCandidates, then it must be in mapBlocksUnlinked.
            if (!CBlockIndexWorkComparator()(pindex, chainActive.Tip()) && setBlockIndexCandidates.count(pindex) == 0) {
                if (pindexFirstInvalid == nullptr) {
                    assert(foundInUnlinked);
                }
            }
        }
        // assert(pindex->GetBlockHash() == pindex->GetBlockHeader().GetHash()); // Perhaps too slow
        // End: actual consistency checks.

        // Try descending into the first subnode.
        std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = forward.equal_range(pindex);
        if (range.first != range.second) {
            // A subnode was found.
            pindex = range.first->second;
            nHeight++;
            continue;
        }
        // This is a leaf node.
        // Move upwards until we reach a node of which we have not yet visited the last child.
        while (pindex) {
            // We are going to either move to a parent or a sibling of pindex.
            // If pindex was the first with a certain property, unset the corresponding variable.
            if (pindex == pindexFirstInvalid) pindexFirstInvalid = nullptr;
            if (pindex == pindexFirstMissing) pindexFirstMissing = nullptr;
            if (pindex == pindexFirstNeverProcessed) pindexFirstNeverProcessed = nullptr;
            if (pindex == pindexFirstNotTreeValid) pindexFirstNotTreeValid = nullptr;
            if (pindex == pindexFirstNotTransactionsValid) pindexFirstNotTransactionsValid = nullptr;
            if (pindex == pindexFirstNotChainValid) pindexFirstNotChainValid = nullptr;
            if (pindex == pindexFirstNotScriptsValid) pindexFirstNotScriptsValid = nullptr;
            // Find our parent.
            CBlockIndex* pindexPar = pindex->pprev;
            // Find which child we just visited.
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> rangePar = forward.equal_range(pindexPar);
            while (rangePar.first->second != pindex) {
                assert(rangePar.first != rangePar.second); // Our parent must have at least the node we're coming from as child.
                rangePar.first++;
            }
            // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second) {
                // Move to the sibling.
                pindex = rangePar.first->second;
                break;
            } else {
                // Move up further.
                pindex = pindexPar;
                nHeight--;
                continue;
            }
        }
    }

    // Check that we actually traversed the entire map.
    assert(nNodes == forward.size());
}

/**
 * Calculates the block height and previous block's median time past at
 * which the transaction will be considered final in the context of BIP 68.
 * Also removes from the vector of input heights any entries which did not
 * correspond to sequence locked inputs as they do not affect the calculation.
 */
static std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction& tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t> (tx.nVersion) >= 2
                         && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight - 1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t) ((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int) (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

static bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction& tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

bool TestLockPointValidity(const LockPoints* lp)
{
    AssertLockHeld(cs_main);
    assert(lp);
    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp->maxInputBlock) {
        // Check whether chainActive is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!chainActive.Contains(lp->maxInputBlock)) {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

bool CheckSequenceLocks(const CTransaction& tx, int flags, LockPoints* lp, bool useExistingLockPoints)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(mempool.cs);

    CBlockIndex* tip = chainActive.Tip();
    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses chainActive.Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than chainActive.Height()
    index.nHeight = tip->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints) {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    } else {
        // pcoinsTip contains the UTXO set for chainActive.Tip()
        CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());
        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
            const CTxIn& txin = tx.vin[txinIndex];
            Coin coin;
            if (!viewMemPool.GetCoin(txin.prevout, coin)) {
                return error("%s: Missing input", __func__);
            }
            if (coin.nHeight == MEMPOOL_HEIGHT) {
                // Assume all mempool transaction confirm in the next block
                prevheights[txinIndex] = tip->nHeight + 1;
            } else {
                prevheights[txinIndex] = coin.nHeight;
            }
        }
        lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
        if (lp) {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for mempool txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a mempool input, so we can use the return value of
            // CheckSequenceLocks to indicate the LockPoints validity
            int maxInputHeight = 0;

            BOOST_FOREACH(int height, prevheights) {
                // Can ignore mempool inputs since we'll fail if they had non-zero locks
                if (height != tip->nHeight + 1) {
                    maxInputHeight = std::max(maxInputHeight, height);
                }
            }
            lp->maxInputBlock = tip->GetAncestor(maxInputHeight);
        }
    }
    return EvaluateSequenceLocks(index, lockPair);
}


//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

std::string GetWarnings(const std::string& strFor)
{
    int nPriority = 0;
    string strStatusBar;
    string strRPC;
    std::string strGUI;
    const std::string uiAlertSeperator = "<hr />";

    if (!CLIENT_VERSION_IS_RELEASE) {
        strStatusBar = _("This is a pre-release test build - use at your own risk - do not use for mining or merchant applications");
        strGUI = _("This is a pre-release test build - use at your own risk - do not use for mining or merchant applications");
    }

    if (GetBoolArg("-testsafemode", false))
        strStatusBar = strRPC = strGUI = "testsafemode enabled";

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "") {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
        strGUI += (strGUI.empty() ? "" : uiAlertSeperator) + strMiscWarning;
    }

    if (fLargeWorkForkFound) {
        nPriority = 2000;
        strStatusBar = strRPC = _("Warning: The network does not appear to fully agree! Some miners appear to be experiencing issues.");
        strGUI += (strGUI.empty() ? "" : uiAlertSeperator) + _("Warning: The network does not appear to fully agree! Some miners appear to be experiencing issues.");
    } else if (fLargeWorkInvalidChainFound) {
        nPriority = 2000;
        strStatusBar = strRPC = _("Warning: We do not appear to fully agree with our peers! You may need to upgrade, or other nodes may need to upgrade.");
        strGUI += (strGUI.empty() ? "" : uiAlertSeperator) + _("Warning: We do not appear to fully agree with our peers! You may need to upgrade, or other nodes may need to upgrade.");
    }

    // Alerts
    {
        LOCK(cs_mapAlerts);

        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert) & item, mapAlerts) {
            const CAlert& alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority) {
                nPriority = alert.nPriority;
                strStatusBar = strGUI = alert.strStatusBar;
            }
        }
    }

    if (strFor == "gui")
        return strGUI;
    else if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    assert(!"GetWarnings(): invalid parameter");
    return "error";
}

std::string CBlockFileInfo::ToString() const
{
    return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, DateTimeStrFormat("%Y-%m-%d", nTimeFirst), DateTimeStrFormat("%Y-%m-%d", nTimeLast));
}


static const uint64_t MEMPOOL_DUMP_VERSION = 1;

bool LoadMempool(void)
{
    const CChainParams& chainparams = Params();
    int64_t nExpiryTimeout = GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60;
    FILE* filestr = fsbridge::fopen(GetDataDir() / "mempool.dat", "rb");
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        LogPrintf("Failed to open mempool file from disk. Continuing anyway.\n");
        return false;
    }

    int64_t count = 0;
    int64_t expired = 0;
    int64_t failed = 0;
    int64_t already_there = 0;
    int64_t nNow = GetTime();

    try {
        uint64_t version;
        file >> version;
        if (version != MEMPOOL_DUMP_VERSION) {
            return false;
        }
        uint64_t num;
        file >> num;
        while (num--) {
            CTransactionRef tx;
            int64_t nTime;
            int64_t nFeeDelta;
            file >> tx;
            file >> nTime;
            file >> nFeeDelta;

            CAmount amountdelta = nFeeDelta;
            if (amountdelta) {
                mempool.PrioritiseTransaction(tx->GetHash(), amountdelta);
            }
            CValidationState state;
            if (nTime + nExpiryTimeout > nNow) {
                LOCK(cs_main);
                AcceptToMemoryPoolWithTime(mempool, state, tx, true, nullptr /* pfMissingInputs */, nTime,
                                           nullptr /* plTxnReplaced */);
                if (state.IsValid()) {
                    ++count;
                } else {
                    // mempool may contain the transaction already, e.g. from
                    // wallet(s) having loaded it while we were processing
                    // mempool transactions; consider these as valid, instead of
                    // failed, but mark them as 'already there'
                    if (mempool.exists(tx->GetHash())) {
                        ++already_there;
                    } else {
                        ++failed;
                    }
                }
            } else {
                ++expired;
            }
            if (ShutdownRequested())
                return false;
        }
        std::map<uint256, CAmount> mapDeltas;
        file >> mapDeltas;

        for (const auto& i : mapDeltas) {
            mempool.PrioritiseTransaction(i.first, i.second);
        }
    } catch (const std::exception& e) {
        LogPrintf("Failed to deserialize mempool data on disk: %s. Continuing anyway.\n", e.what());
        return false;
    }

    LogPrintf("Imported mempool transactions from disk: %i succeeded, %i failed, %i expired, %i already there\n", count, failed, expired, already_there);
    return true;
}

bool DumpMempool(void)
{
    int64_t start = GetTimeMicros();

    std::map<uint256, CAmount> mapDeltas;
    std::vector<TxMempoolInfo> vinfo;

    {
        LOCK(mempool.cs);
        for (const auto& i : mempool.mapDeltas) {
            mapDeltas[i.first] = i.second;
        }
        vinfo = mempool.infoAll();
    }

    int64_t mid = GetTimeMicros();

    try {
        FILE* filestr = fsbridge::fopen(GetDataDir() / "mempool.dat.new", "wb");
        if (!filestr) {
            return false;
        }

        CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);

        uint64_t version = MEMPOOL_DUMP_VERSION;
        file << version;

        file << (uint64_t)vinfo.size();
        for (const auto& i : vinfo) {
            file << *(i.tx);
            file << (int64_t)i.nTime;
            file << (int64_t)i.nFeeDelta;
            mapDeltas.erase(i.tx->GetHash());
        }

        file << mapDeltas;
        FileCommit(file.Get());
        file.fclose();
        RenameOver(GetDataDir() / "mempool.dat.new", GetDataDir() / "mempool.dat");
        int64_t last = GetTimeMicros();
        LogPrintf("Dumped mempool: %gs to copy, %gs to dump\n", (mid - start)*MICRO, (last - mid)*MICRO);
    } catch (const std::exception& e) {
        LogPrintf("Failed to dump mempool: %s. Continuing anyway.\n", e.what());
        return false;
    }
    return true;
}

class CMainCleanup
{
public:

    CMainCleanup()
    {
    }

    ~CMainCleanup()
    {
        // block headers
        BlockMap::iterator it1 = mapBlockIndex.begin();
        for (; it1 != mapBlockIndex.end(); it1++)
            delete (*it1).second;
        mapBlockIndex.clear();

    }
} instance_of_cmaincleanup;


bool GetUTXOAtHeight(const CTxDestination& dest, const int nHeight, std::vector<CUtxo>& vTxOut, const CAmount& valueLimit)
{
    CScript script = GetScriptForDestination(dest);
    return GetUTXOAtHeight(script, nHeight, vTxOut, valueLimit);
}
