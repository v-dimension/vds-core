// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VDS_VALIDATION_H
#define VDS_VALIDATION_H

#if defined(HAVE_CONFIG_H)
#include "config/vds-config.h"
#endif

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "net.h"
#include "cluedb.h"
#include "addb.h"
#include "policy/fees.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/sigcache.h"
#include "script/standard.h"
#include "sync.h"
#include "tinyformat.h"
#include "txmempool.h"
#include "uint256.h"
#include "versionbits.h"

#include <algorithm>
#include <exception>
#include <map>
#include <set>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <atomic>

#include <boost/unordered_map.hpp>
#include <boost/filesystem/path.hpp>

/////////////////////////////////////////// qtum
#include <qtum/qtumstate.h>
#include <qtum/qtumDGP.h>
#include <libethereum/ChainParams.h>
#include <libethashseal/Ethash.h>
#include <libethashseal/GenesisInfo.h>
#include <script/standard.h>
#include <qtum/storageresults.h>
#include "merkleblock.h"

const int BID_COUNT_PRECISION = 2;
const int COUNT_CHAIN_RANDOM_INIT = 10;

extern std::unique_ptr<QtumState> globalState;
extern std::shared_ptr<dev::eth::SealEngineFace> globalSealEngine;
extern bool fRecordLogOpcodes;
extern bool fIsVMlogFile;
extern bool fGettingValuesDGP;

struct EthTransactionParams;
using valtype = std::vector<unsigned char>;
using ExtractQtumTX = std::pair<std::vector<QtumTransaction>, std::vector<EthTransactionParams>>;
///////////////////////////////////////////

class CBlockIndex;
class CBlockTreeDB;
class CBloomFilter;
class CChainParams;
class CCoinsViewDB;
class CInv;
class CConnman;
class CScriptCheck;
class CTxMemPool;
class CValidationInterface;
class CValidationState;
class CMerkleTransaction;
class CAnonymousMerkleTx;

struct LockPoints;

/** Minimum gas limit that is allowed in a transaction within a block - prevent various types of tx and mempool spam **/
static const uint64_t MINIMUM_GAS_LIMIT = 10000;

static const uint64_t MEMPOOL_MIN_GAS_LIMIT = 22000;
/** Default for accepting alerts from the P2P network. */
static const bool DEFAULT_ALERTS = true;
/** Maximum reorg length we will accept before we shut down and alert the user. */
static const unsigned int MAX_REORG_LENGTH = COINBASE_MATURITY - 1;
/** Default for DEFAULT_WHITELISTRELAY. */
static const bool DEFAULT_WHITELISTRELAY = true;
/** Default for DEFAULT_WHITELISTFORCERELAY. */
static const bool DEFAULT_WHITELISTFORCERELAY = true;
/** Default for -minrelaytxfee, minimum relay fee for transactions */
static const unsigned int DEFAULT_MIN_RELAY_TX_FEE = 1000;
/** Default for -maxorphantx, maximum number of orphan transactions kept in memory */
static const unsigned int DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100;
/** Default for -limitancestorcount, max number of in-mempool ancestors */
static const unsigned int DEFAULT_ANCESTOR_LIMIT = 25;
/** Default for -limitancestorsize, maximum kilobytes of tx + all in-mempool ancestors */
static const unsigned int DEFAULT_ANCESTOR_SIZE_LIMIT = 101;
/** Default for -limitdescendantcount, max number of in-mempool descendants */
static const unsigned int DEFAULT_DESCENDANT_LIMIT = 25;
/** Default for -limitdescendantsize, maximum kilobytes of in-mempool descendants */
static const unsigned int DEFAULT_DESCENDANT_SIZE_LIMIT = 101;
/** Default for -mempoolexpiry, expiration time for mempool transactions in hours */
static const unsigned int DEFAULT_MEMPOOL_EXPIRY = 72;
/** Maximum kilobytes for transactions to store for processing during reorg */
static const unsigned int MAX_DISCONNECTED_TX_POOL_SIZE = 20000;
/** The maximum size of a blk?????.dat file (since 0.8) */
static const unsigned int MAX_BLOCKFILE_SIZE = 0x8000000; // 128 MiB
/** The pre-allocation chunk size for blk?????.dat files (since 0.8) */
static const unsigned int BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 MiB
/** The pre-allocation chunk size for rev?????.dat files (since 0.8) */
static const unsigned int UNDOFILE_CHUNK_SIZE = 0x100000; // 1 MiB

/** Maximum number of script-checking threads allowed */
static const int MAX_SCRIPTCHECK_THREADS = 16;
/** -par default (number of script-checking threads, 0 = auto) */
static const int DEFAULT_SCRIPTCHECK_THREADS = 0;
/** Number of blocks that can be requested at any given time from a single peer. */
static const int MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16;
/** Timeout in seconds during which a peer must stall block download progress before being disconnected. */
static const unsigned int BLOCK_STALLING_TIMEOUT = 8;
/** Number of headers sent in one getheaders result. We rely on the assumption that if a peer sends
 *  less than this number, we reached its tip. Changing this value is a protocol upgrade. */
static const unsigned int MAX_HEADERS_RESULTS = 2000;
/** Size of the "block download window": how far ahead of our current height do we fetch?
 *  Larger windows tolerate larger download speed differences between peer, but increase the potential
 *  degree of disordering of blocks on disk (which make reindexing and in the future perhaps pruning
 *  harder). We'll probably want to make this a per-peer adaptive value at some point. */
static const unsigned int BLOCK_DOWNLOAD_WINDOW = 1024;
/** Time to wait (in seconds) between writing blocks/block index to disk. */
static const unsigned int DATABASE_WRITE_INTERVAL = 60 * 60;
/** Time to wait (in seconds) between flushing chainstate to disk. */
static const unsigned int DATABASE_FLUSH_INTERVAL = 24 * 60 * 60;
/** Maximum length of reject messages. */
static const unsigned int MAX_REJECT_MESSAGE_LENGTH = 111;
/** Average delay between local address broadcasts in seconds. */
static const unsigned int AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL = 24 * 24 * 60;
/** Average delay between peer address broadcasts in seconds. */
static const unsigned int AVG_ADDRESS_BROADCAST_INTERVAL = 30;
/** Average delay between trickled inventory broadcasts in seconds.
 *  Blocks, whitelisted receivers, and a random 25% of transactions bypass this. */
static const unsigned int AVG_INVENTORY_BROADCAST_INTERVAL = 5;
/** Block download timeout base, expressed in millionths of the block interval (i.e. 1 min) */
static const int64_t BLOCK_DOWNLOAD_TIMEOUT_BASE = 1000000;
/** Additional block download timeout per parallel downloading peer (i.e. 0.25 min) */
static const int64_t BLOCK_DOWNLOAD_TIMEOUT_PER_PEER = 500000;

static const unsigned int DEFAULT_LIMITFREERELAY = 15;
static const bool DEFAULT_RELAYPRIORITY = true;

/** Default for -permitbaremultisig */
static const bool DEFAULT_PERMIT_BAREMULTISIG = true;
static const bool DEFAULT_CHECKPOINTS_ENABLED = true;
static const bool DEFAULT_TXINDEX = true;
static const bool DEFAULT_ADDRESSINDEX = true;
static const bool DEFAULT_TIMESTAMPINDEX = true;
static const bool DEFAULT_SPENTINDEX = true;
static const unsigned int DEFAULT_BANSCORE_THRESHOLD = 100;
/** Default for -persistmempool */
static const bool DEFAULT_PERSIST_MEMPOOL = true;

static const bool DEFAULT_TESTSAFEMODE = false;
/** Default for -mempoolreplacement */
static const bool DEFAULT_ENABLE_REPLACEMENT = false;

/** Maximum number of headers to announce when relaying blocks with headers message.*/
static const unsigned int MAX_BLOCKS_TO_ANNOUNCE = 8;

static const uint64_t DEFAULT_GAS_LIMIT_OP_CREATE = 2500000;
static const uint64_t DEFAULT_GAS_LIMIT_OP_SEND = 250000;
static const CAmount DEFAULT_GAS_PRICE = 0.00000040 * COIN;
static const CAmount MAX_RPC_GAS_PRICE = 0.00000100 * COIN;

static const size_t MAX_CONTRACT_VOUTS = 1000; // qtum

static const CAmount CLUE_COST_PARENT_TOP   =   4 * COIN;
static const CAmount CLUE_COST_PARENT_NOAWARWD =   3.5 * COIN;
static const CAmount CLUE_COST_PARENT       =   0.5 * COIN;
static const CAmount CLUE_COST_TANDIA       =   0.3 * COIN;
static const CAmount CLUE_COST_MASTER_NODE  =   0.1 * COIN;
static const CAmount CLUE_COST_MINER        =   0.1 * COIN;
static const CAmount CLUE_COST_FEE          =   0.5 * COIN;
static const CAmount CLUE_TOTAL             =   10 * COIN;
static const CAmount CLUE_FEE_NO_PARENT     =   CLUE_COST_FEE;

static const CAmount TANDIA_AMOUNT_LIMIT    = 33 * COIN;
static const CAmount TANDIA_BLOCK_LIMIT     = 1000; // pay at least one week.
static const size_t MAX_TANDIA_LIMIT = 33;

#define equihash_parameters_acceptable(N, K) \
    ((CBlockHeader::HEADER_SIZE + equihash_solution_size(N, K))*MAX_HEADERS_RESULTS < \
     MAX_PROTOCOL_MESSAGE_LENGTH-1000)

struct BlockHasher {
    size_t operator()(const uint256& hash) const
    {
        return hash.GetCheapHash();
    }
};

extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_main;
extern CBlockPolicyEstimator feeEstimator;
extern CTxMemPool mempool;
extern CClueViewMemPool cluepool;
extern std::atomic_bool g_is_mempool_loaded;
typedef boost::unordered_map<uint256, CBlockIndex*, BlockHasher> BlockMap;
extern BlockMap mapBlockIndex;
extern uint64_t nLastBlockTx;
extern uint64_t nLastBlockWeight;
extern const std::string strMessageMagic;
extern CWaitableCriticalSection csBestBlock;
extern CConditionVariable cvBlockChange;
extern bool fExperimentalMode;
extern bool fImporting;
extern bool fReindex;
extern int nScriptCheckThreads;
extern bool fTxIndex;
extern bool fLogEvents;
extern bool fIsBareMultisigStd;
extern bool fRequireStandard;
extern unsigned int nBytesPerSigOp;
extern bool fCheckBlockIndex;
extern bool fCheckpointsEnabled;
// TODO: remove this flag by structuring our code such that
// it is unneeded for testing
extern bool fCoinbaseEnforcedProtectionEnabled;
extern size_t nCoinCacheUsage;
extern CFeeRate minRelayTxFee;
extern bool fAlerts;
extern bool fEnableReplacement;

extern std::map<uint256, int64_t> mapRejectedBlocks;

/** Best header we've seen so far (used for getheaders queries' starting points). */
extern CBlockIndex* pindexBestHeader;

/** Minimum disk space required - used in CheckDiskSpace() */
static const uint64_t nMinDiskSpace = 52428800;

/** Pruning-related variables and constants */
/** True if any block files have ever been pruned. */
extern bool fHavePruned;
/** True if we're running in -prune mode. */
extern bool fPruneMode;
/** Number of MiB of block files that we're trying to stay below. */
extern uint64_t nPruneTarget;
/** Block files containing a block-height within MIN_BLOCKS_TO_KEEP of chainActive.Tip() will not be pruned. */
static const unsigned int MIN_BLOCKS_TO_KEEP = 288;

static const signed int DEFAULT_CHECKBLOCKS = 60;
static const unsigned int DEFAULT_CHECKLEVEL = 3;

// Require that user allocate at least 945MB for block & undo files (blk???.dat and rev???.dat)
// At 2MB per block, 288 blocks = 576MB.
// Add 15% for Undo data = 662MB
// Add 20% for Orphan block rate = 794MB
// We want the low water mark after pruning to be at least 794 MB and since we prune in
// full block file chunks, we need the high water mark which triggers the prune to be
// one 128MB block file + added 15% undo data = 147MB greater for a total of 941MB
// Setting the target to > than 945MB will make it likely we can respect the target.
static const uint64_t MIN_DISK_SPACE_FOR_BLOCK_FILES = 945 * 1024 * 1024;

/**
 * Brief cal chain random that is be validated
 * @param[in]   nRandomT    The block count offset the chain tip.
 * @param[in]   nRange      The random range to generate .
 * @param[out]  nRandomCal  The random value of calculate.
 * @return True if get the random value
 */
bool CalChainRandom(const int& nRandomT, const uint32_t& nRange, uint32_t& nRandomCal, int nHeight);
/**
 * Process an incoming block. This only returns after the best known valid
 * block is made active. Note that it does not, however, guarantee that the
 * specific block passed to it has been checked for validity!
 *
 * If you want to *possibly* get feedback on whether pblock is valid, you must
 * install a CValidationInterface (see validationinterface.h) - this will have
 * its BlockChecked method called whenever *any* block completes validation.
 *
 * Note that we guarantee that either the proof-of-work is valid on pblock, or
 * (and possibly also) BlockChecked will have been called.
 *
 * @param[in]   pblock  The block we want to process.
 * @param[in]   fForceProcessing Process this block even if unrequested; used for non-network block sources and whitelisted peers.
 * @param[out]  dbp     The already known disk position of pblock, or NULL if not yet stored.
 * @param[out]  fNewBlock A boolean which is set to indicate if the block was first received via this call
 * @return True if state.IsValid()
 */
bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, const CDiskBlockPos* dbp, bool* fNewBlock);

/**
 * Process incoming block headers.
 *
 * @param[in]  block The block headers themselves
 * @param[out] state This may be set to an Error state if any error occurred processing them
 * @param[in]  chainparams The params for the chain we want to connect to
 * @param[out] ppindex If set, the pointer will be set to point to the last new block index object for the given headers
 */
bool ProcessNewBlockHeaders(const std::vector<CBlockHeader>& block, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex = NULL);

int GetTandiaPeriod(const int nHeight);
CScript GetTandiaScript(int nHeight, int nIndex);
/**/
void GetCoinBaseShouldPay(const CBlockIndex* pindex, const std::vector<CTransactionRef>& vtx, CAmount& nToMasterNodeAll, CAmount& toMiner, CAmount& toMasterNode, CAmount& toVibPool, bool& fPaidTandia, CAmount& toTandia);
/** Check whether enough disk space is available for an incoming block */
bool CheckDiskSpace(uint64_t nAdditionalBytes = 0);
/** Open a block file (blk?????.dat) */
FILE* OpenBlockFile(const CDiskBlockPos& pos, bool fReadOnly = false);
/** Open an undo file (rev?????.dat) */
FILE* OpenUndoFile(const CDiskBlockPos& pos, bool fReadOnly = false);
/** Translation to a filesystem path */
boost::filesystem::path GetBlockPosFilename(const CDiskBlockPos& pos, const char* prefix);
/** Import blocks from an external file */
bool LoadExternalBlockFile(const CChainParams& chainparams, FILE* fileIn, CDiskBlockPos* dbp = NULL);
/** Initialize a new block tree database + block data on disk */
bool InitBlockIndex(const CChainParams& chainparams);
/** Load the block tree and coins database from disk */
bool LoadBlockIndex();
/** Unload database information */
void UnloadBlockIndex();
/** Run an instance of the script checking thread */
void ThreadScriptCheck();
/** Check whether we are doing an initial block download (synchronizing from disk or network) */
bool IsInitialBlockDownload();
/** Format a string that describes several potential problems detected by the core.
 * strFor can have three values:
 * - "rpc": get critical warnings, which should put the client in safe mode if non-empty
 * - "statusbar": get all warnings
 * - "gui": get all warnings, translated (where possible) for GUI
 * This function only returns the highest priority warning of the set selected by strFor.
 */
std::string GetWarnings(const std::string& strFor);
/** Retrieve a transaction (from memory pool, or from disk, if possible) */
bool GetTransaction(const uint256& hash, CTransactionRef& tx, const Consensus::Params& params, uint256& hashBlock, bool fAllowSlow = false);
bool GetMerkleTransaction(const uint256& hash, CMerkleTransaction& txOut, const Consensus::Params& consensusParams);
bool GetMerkleTransactionWithAnonymous(const int blockHeight, std::map<int, std::map<uint256, char>>& filterdTxids, std::vector<CMerkleTxBlock>& output);
bool GetSampleMerkleTransactionWithAnonymous(const int blockHeight, std::map<int, std::map<uint256, char>>& filterdTxids, std::vector<CMerkleTxBlockSample>& output);

/** Find the best known block, and make it the tip of the block chain */
bool ActivateBestChain(CValidationState& state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock = std::shared_ptr<const CBlock>());

double ConvertBitsToDouble(unsigned int nBits);
CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams);
CAmount GetBlockClueSubsidy(int nHeight, const Consensus::Params& consensusParams, bool fLimit = true);
CAmount GetMasternodePayment(int nHeight, CAmount blockValue);
int GetAdHeight(int nBlockHeight, int nIndexPeroidBidLock = 0);
bool CheckIndexBidLockTimePeroid(const int nBlockHeight, const int& nHeightCheck);
double ClueAwardWeight(uint32_t level);
bool CheckTxBid(const CTransaction& tx, const int& nHeightCheck, std::string& strError);
bool UpdateAdKing(const CAd& ad);
bool UpdateAdKing();
bool ValidateAd(const CAd& ad);
bool GetAdValueOut(uint256 txBidHash, CAmount& valueAd);
int64_t GetLastSeasonClues(int nHeight, const Consensus::Params& consensusParams);

//group op type = 0 connectBlock , 1 accepttomempool , 2 disconnectBlock
bool RecordGroupId(const CCoinsViewCache& view, const CTransaction& tx, CClueViewCache& clueview, CValidationState& state, int _type = 0);
bool AnalysisTxCreate(const CScript& scriptPubKey, std::string& hexScript);
bool AnalysisTxCall(const CScript& scriptPubKey, std::string& opcall, std::string& hexScript);

/**
 * Prune block and undo files (blk???.dat and undo???.dat) so that the disk space used is less than a user-defined target.
 * The user sets the target (in MB) on the command line or in config file.  This will be run on startup and whenever new
 * space is allocated in a block or undo file, staying below the target. Changing back to unpruned requires a reindex
 * (which in this case means the blockchain must be re-downloaded.)
 *
 * Pruning functions are called from FlushStateToDisk when the global fCheckForPruning flag has been set.
 * Block and undo files are deleted in lock-step (when blk00003.dat is deleted, so is rev00003.dat.)
 * Pruning cannot take place until the longest chain is at least a certain length (100000 on mainnet, 1000 on testnet, 1000 on regtest).
 * Pruning will never delete a block within a defined distance (currently 288) from the active chain's tip.
 * The block index is updated by unsetting HAVE_DATA and HAVE_UNDO for any blocks that were stored in the deleted files.
 * A db flag records the fact that at least some block files have been pruned.
 *
 * @param[out]   setFilesToPrune   The set of file indices that can be unlinked will be returned
 */
void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight);

/**
 *  Actually unlink the specified files
 */
void UnlinkPrunedFiles(std::set<int>& setFilesToPrune);

/** Create a new block index entry for a given block hash */
CBlockIndex* InsertBlockIndex(uint256 hash);
/** Flush all state, indexes and buffers to disk. */
void FlushStateToDisk();
/** Prune block files and flush state to disk. */
void PruneAndFlush();

/** (try to) add transaction to memory pool **/
bool AcceptToMemoryPoolWithTime(CTxMemPool& pool, CValidationState& state, const CTransactionRef& tx, bool fLimitFree,
                                bool* pfMissingInputs, int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced = NULL,
                                bool fOverrideMempoolLimit = false, bool fRejectAbsurdFee = false, bool fDryRun = false);

bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState& state, const CTransactionRef& tx, bool fLimitFree,
                        bool* pfMissingInputs, std::list<CTransactionRef>* plTxnReplaced = NULL, bool fOverrideMempoolLimit = false,
                        bool fRejectAbsurdFee = false, bool fDryRun = false);
bool GetUTXOCoin(const COutPoint& outpoint, Coin& coin);
int GetUTXOHeight(const COutPoint& outpoint);
int GetUTXOConfirmations(const COutPoint& outpoint);
bool IsClueRoot(const CTxDestination& dest, const int nCurHeight = 0);

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState& state);

/** Get the BIP9 state for a given deployment at the current tip. */
ThresholdState VersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos);

//////////////////////////////////////////////////////////// // qtum
struct CHeightTxIndexIteratorKey {
    unsigned int height;

    size_t GetSerializeSize(int nType, int nVersion) const
    {
        return 4;
    }
    template<typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata32be(s, height);
    }
    template<typename Stream>
    void Unserialize(Stream& s)
    {
        height = ser_readdata32be(s);
    }

    CHeightTxIndexIteratorKey(unsigned int _height)
    {
        height = _height;
    }

    CHeightTxIndexIteratorKey()
    {
        SetNull();
    }

    void SetNull()
    {
        height = 0;
    }
};

struct CHeightTxIndexKey {
    unsigned int height;
    dev::h160 address;

    size_t GetSerializeSize(int nType, int nVersion) const
    {
        return 24;
    }
    template<typename Stream>
    void Serialize(Stream& s) const
    {
        ser_writedata32be(s, height);
        s << address.asBytes();
    }
    template<typename Stream>
    void Unserialize(Stream& s)
    {
        height = ser_readdata32be(s);
        valtype tmp;
        s >> tmp;
        address = dev::h160(tmp);
    }

    CHeightTxIndexKey(unsigned int _height, dev::h160 _address)
    {
        height = _height;
        address = _address;
    }

    CHeightTxIndexKey()
    {
        SetNull();
    }

    void SetNull()
    {
        height = 0;
        address.clear();
    }
};

////////////////////////////////////////////////////////////

/**
 * Count ECDSA signature operations the old-fashioned (pre-0.6) way
 * @return number of sigops this transaction's outputs will produce when spent
 * @see CTransaction::FetchInputs
 */
unsigned int GetLegacySigOpCount(const CTransaction& tx);

/**
 * Count ECDSA signature operations in pay-to-script-hash inputs.
 *
 * @param[in] mapInputs Map of previous transactions that have outputs we're spending
 * @return maximum number of sigops required to validate this transaction's inputs
 * @see CTransaction::FetchInputs
 */
unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& mapInputs);


/**
 * Check whether all inputs of this transaction are valid (no double spends, scripts & sigs, amounts)
 * This does not modify the UTXO set. If pvChecks is not NULL, script checks are pushed onto it
 * instead of being performed inline.
 */
bool CheckInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& view, bool fScriptChecks,
                 unsigned int flags, bool cacheStore, std::vector<CScriptCheck>* pvChecks = NULL);
bool CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs,
                   int nSpendHeight, const Consensus::Params& consensusParams);

void UpdateClue(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& view, CClueViewCache& clueinputs, int nHeight = 0x7FFFFFFF, const uint256& hash = uint256());

/** Apply the effects of this transaction on the UTXO set represented by view */
void UpdateCoins(const CTransaction& tx, CValidationState& state, CCoinsViewCache& inputs, int nHeight);

/** Context-independent validity checks */
bool CheckTransaction(const CTransaction& tx, CValidationState& state, libzcash::ProofVerifier& verifier);
bool CheckTransactionWithoutProofVerification(const CTransaction& tx, CValidationState& state);

namespace Consensus
{

/**
 * Check whether all inputs of this transaction are valid (no double spends and amounts)
 * This does not modify the UTXO set. This does not check scripts and sigs.
 * Preconditions: tx.IsCoinBase() is false.
 */
bool CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, const CClueViewCache& clueinputs, int nSpendHeight, const Consensus::Params& consensusParams, CAmount& txfee);

} // namespace Consensus

/** Check for standard transaction types
 * @return True if all outputs (scriptPubKeys) use only standard transaction forms
 */
bool IsStandardTx(const CTransaction& tx, std::string& reason);

/**
 * Check if transaction is final and can be included in a block with the
 * specified height and time. Consensus critical.
 */
bool IsFinalTx(const CTransaction& tx, int nBlockHeight, int64_t nBlockTime);

/**
 * Check if transaction is final and can be accpeted to mempool with the
 * specified height and time. Consensus critical.
 */
bool IsFinalTxMempool(const CTransaction& tx, int nBlockHeight, int64_t nBlockTime);


/**
 * Check if transaction will be final in the next block to be created.
 *
 * Calls IsFinalTx() with current block height and appropriate block time.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckFinalTx(const CTransaction& tx, int flags = -1);

/**
 * Test whether the LockPoints height and time are still valid on the current chain
 */
bool TestLockPointValidity(const LockPoints* lp);

/**
 * Check if transaction is final per BIP 68 sequence numbers and can be included in a block.
 * Consensus critical. Takes as input a list of heights at which tx's inputs (in order) confirmed.
 */
bool SequenceLocks(const CTransaction& tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block);

/**
 * Check if transaction will be BIP 68 final in the next block to be created.
 *
 * Simulates calling SequenceLocks() with data from the tip of the current active chain.
 * Optionally stores in LockPoints the resulting height and time calculated and the hash
 * of the block needed for calculation or skips the calculation and uses the LockPoints
 * passed in for evaluation.
 * The LockPoints should not be considered valid if CheckSequenceLocks returns false.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckSequenceLocks(const CTransaction& tx, int flags, LockPoints* lp = NULL, bool useExistingLockPoints = false);

/**
 * Closure representing one script verification
 * Note that this stores references to the spending transaction
 */
class CScriptCheck
{
private:
    CScript scriptPubKey;
    CAmount amount;
    const CTransaction* ptxTo;
    unsigned int nIn;
    unsigned int nFlags;
    bool cacheStore;
    ScriptError error;
    PrecomputedTransactionData* txdata;

public:
    CScriptCheck(): amount(0), ptxTo(0), nIn(0), nFlags(0), cacheStore(false), error(SCRIPT_ERR_UNKNOWN_ERROR) {}
    CScriptCheck(const CScript& scriptPubKeyIn, const CAmount amountIn, const CTransaction& txToIn, unsigned int nInIn, unsigned int nFlagsIn, bool cacheIn, PrecomputedTransactionData* txdataIn) :
        scriptPubKey(scriptPubKeyIn),
        amount(amountIn),
        ptxTo(&txToIn), nIn(nInIn), nFlags(nFlagsIn), cacheStore(cacheIn), error(SCRIPT_ERR_UNKNOWN_ERROR), txdata(txdataIn) { }

    bool operator()();

    void swap(CScriptCheck& check)
    {
        scriptPubKey.swap(check.scriptPubKey);
        std::swap(ptxTo, check.ptxTo);
        std::swap(amount, check.amount);
        std::swap(nIn, check.nIn);
        std::swap(nFlags, check.nFlags);
        std::swap(cacheStore, check.cacheStore);
        std::swap(error, check.error);
        std::swap(txdata, check.txdata);
    }

    ScriptError GetScriptError() const
    {
        return error;
    }
};

bool GetIndexKey(const CScript& scritPubKey, uint160& hashBytes, txnouttype& type);
bool GetSpentIndex(CSpentIndexKey& key, CSpentIndexValue& value);
bool GetAddressIndex(uint160 addressHash, int type,
                     std::vector<std::pair<CAddressIndexKey, CAmount> >& addressIndex,
                     int start = 0, int end = 0);

struct CUtxo {
    uint256 txid;
    size_t n;
    CAmount nValue;
    int nHeight;

    CUtxo() {}
};

bool GetUTXOAtHeight(const CTxDestination& dest, const int nHeight, std::vector<CUtxo>& vTxOut, const CAmount& valueLimit = 0);
bool GetUTXOAtHeight(const CScript& script, const int nHeight, std::vector<CUtxo>& vTxOut, const CAmount& valueLimit = 0);
/** Functions for disk access for blocks */
bool WriteBlockToDisk(const CBlock& block, CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& messageStart);
bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos, const Consensus::Params& consensusParams);
bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams);

/** Functions for validating blocks and updating the block tree */

/** Reprocess a number of blocks to try and get on the correct chain again **/
bool DisconnectBlocks(int blocks);
void ReprocessBlocks(int nBlocks);

/** Context-independent validity checks */
bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, bool fCheckPOW = true);
bool CheckBlock(const CBlock& block, CValidationState& state,
                libzcash::ProofVerifier& verifier,
                bool fCheckPOW = true, bool fCheckMerkleRoot = true);

/** Context-dependent validity checks */
bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, CBlockIndex* pindexPrev);
bool ContextualCheckBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindexPrev);
bool ContextualCheckInputs(const CTransaction& tx, CValidationState& state,
                           const CCoinsViewCache& inputs,
                           const CClueViewCache& clueinputs,
                           bool fScriptChecks, unsigned int flags,
                           bool cacheStore, PrecomputedTransactionData& txdata, const Consensus::Params& consensusParams,
                           std::vector<CScriptCheck>* pvChecks);

/** Check a transaction contextually against a set of consensus rules */
bool ContextualCheckTransaction(const CTransaction& tx, CValidationState& state, int nHeight, int dosLevel,
                                bool (*isInitBlockDownload)() = IsInitialBlockDownload);

bool CheckClueParentsRelationship(const CClueFamilyTree& tree, const std::vector<CTxDestination>& parents, CValidationState& state);
bool ContextualCheckClueTransaction(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, const CClueViewCache& clueinputs, const Consensus::Params& consensusParams, const int nHeight);

/** Check a block is completely valid from start to finish (only works on top of our current best block, with cs_main held) */
bool TestBlockValidity(CValidationState& state, const CChainParams& chainparams, const CBlock& block, CBlockIndex* pindexPrev, bool fCheckPOW = true, bool fCheckMerkleRoot = true);

/** RAII wrapper for VerifyDB: Verify consistency of the block and coin databases */
class CVerifyDB
{
public:
    CVerifyDB();
    ~CVerifyDB();
    bool VerifyDB(const CChainParams& chainparams, CCoinsView* coinsview, CClueView* clueview, int nCheckLevel, int nCheckDepth);
};


/**
 * When there are blocks in the active chain with missing data (e.g. if the
 * activation height and branch ID of a particular upgrade have been altered),
 * rewind the chainstate and remove them from the block index.
 *
 * clearWitnessCaches is an output parameter that will be set to true iff
 * witness caches should be cleared in order to handle an intended long rewind.
 */
bool RewindBlockIndex(const CChainParams& params, bool& clearWitnessCaches);

bool ConnectBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex, CCoinsViewCache& view, CClueViewCache& clueview, bool fJustCheck = false);

/** Find the last common block between the parameter chain and a locator. */
CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator);

/** Mark a block as invalid. */
bool InvalidateBlock(CValidationState& state, const Consensus::Params& consensusParams, CBlockIndex* pindex);

/** Remove invalidity status from a block and its descendants. */
bool ReconsiderBlock(CValidationState& state, CBlockIndex* pindex);

/** The currently-connected chain of blocks (protected by cs_main). */
extern CChain chainActive;

/** Global variable that points to the coins database (protected by cs_main) */
extern CCoinsViewDB* pcoinsdbview;

/** Global variable that points to the active CCoinsView (protected by cs_main) */
extern CCoinsViewCache* pcoinsTip;

/** Global variable that points to the active block tree (protected by cs_main) */
extern CBlockTreeDB* pblocktree;
extern CClueViewDB* pcluedbview;
extern CClueViewCache* pclueTip;
extern CAdDB* paddb;

extern StorageResults* pstorageresult;

/**
 * Return the spend height, which is one more than the inputs.GetBestBlock().
 * While checking, GetBestBlock() refers to the parent block. (protected by cs_main)
 * This is also true for mempool checks.
 */
int GetSpendHeight(const CCoinsViewCache& inputs);

extern VersionBitsCache versionbitscache;

/**
 * Determine what nVersion a new block should use.
 */
int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params, bool fAssumeMasternodeIsUpgraded = false);

/**
 * Return true if hash can be found in chainActive at nBlockHeight height.
 * Fills hashRet with found hash, if no nBlockHeight is specified - chainActive.Height() is used.
 */
bool GetBlockHash(uint256& hashRet, int nBlockHeight = -1);

bool IsBlockInMainChain(const uint256& blockhash, int& nBlockHeight);
/** Dump the mempool to disk. */
bool DumpMempool();

/** Load the mempool from disk. */
bool LoadMempool();

/** Reject codes greater or equal to this can be returned by AcceptToMemPool
 * for transactions, to signal internal conditions. They cannot and should not
 * be sent over the P2P network.
 */
static const unsigned int REJECT_INTERNAL = 0x100;
/** Too high fee. Can not be triggered by P2P transactions */
static const unsigned int REJECT_HIGHFEE = 0x100;
/** Transaction is already known (either in mempool or blockchain) */
static const unsigned int REJECT_ALREADY_KNOWN = 0x101;
/** Transaction conflicts with a transaction already known */
static const unsigned int REJECT_CONFLICT = 0x102;
//////////////////////////////////////////////////////// qtum
std::vector<ResultExecute> CallContract(const dev::Address& addrContract, std::vector<unsigned char> opcode, const dev::Address& sender = dev::Address(), uint64_t gasLimit = 0);

bool CheckSenderScript(const CCoinsViewCache& view, const CTransaction& tx);

bool CheckMinGasPrice(std::vector<EthTransactionParams>& etps, const uint64_t& minGasPrice);

struct ByteCodeExecResult;

void EnforceContractVoutLimit(ByteCodeExecResult& bcer, ByteCodeExecResult& bcerOut, const dev::h256& oldHashQtumRoot,
                              const dev::h256& oldHashStateRoot, const std::vector<QtumTransaction>& transactions);

void writeVMlog(const std::vector<ResultExecute>& res, const CTransaction& tx = CTransaction(), const CBlock& block = CBlock());

CTxDestination getAddressForVin(const CTransaction& tx, bool& found);

struct EthTransactionParams {
    VersionVM version;
    dev::u256 gasLimit;
    dev::u256 gasPrice;
    valtype code;
    dev::Address receiveAddress;

    bool operator!=(EthTransactionParams etp)
    {
        if (this->version.toRaw() != etp.version.toRaw() || this->gasLimit != etp.gasLimit ||
                this->gasPrice != etp.gasPrice || this->code != etp.code ||
                this->receiveAddress != etp.receiveAddress)
            return true;
        return false;
    }
};

struct ByteCodeExecResult {
    uint64_t usedGas = 0;
    CAmount refundSender = 0;
    std::vector<CTxOut> refundOutputs;
    std::vector<CTransaction> valueTransfers;
};

class QtumTxConverter
{

public:

    QtumTxConverter(CTransaction tx, CCoinsViewCache* v = NULL, const std::vector<CTransactionRef>* blockTxs = NULL) : txBit(tx), view(v), blockTransactions(blockTxs) {}

    bool extractionQtumTransactions(ExtractQtumTX& qtumTx);

private:

    bool receiveStack(const CScript& scriptPubKey);

    bool parseEthTXParams(EthTransactionParams& params);

    QtumTransaction createEthTX(const EthTransactionParams& etp, const uint32_t nOut);

    const CTransaction txBit;
    const CCoinsViewCache* view;
    std::vector<valtype> stack;
    opcodetype opcode;
    const std::vector<CTransactionRef>* blockTransactions;

};

class ByteCodeExec
{

public:

    ByteCodeExec(const CBlock& _block, std::vector<QtumTransaction> _txs, const uint64_t _blockGasLimit) : txs(_txs), block(_block), blockGasLimit(_blockGasLimit) {}

    bool performByteCode(dev::eth::Permanence type = dev::eth::Permanence::Committed);

    bool processingResults(ByteCodeExecResult& result);

    std::vector<ResultExecute>& getResult()
    {
        return result;
    }

private:

    dev::eth::EnvInfo BuildEVMEnvironment();

    dev::Address EthAddrFromScript(const CScript& scriptIn);

    std::vector<QtumTransaction> txs;

    std::vector<ResultExecute> result;

    const CBlock& block;

    const uint64_t blockGasLimit;

};

////////////////////////////////////////////////////////

#endif // VDS_VALIDATION_H
