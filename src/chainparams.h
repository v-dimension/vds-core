// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VDS_CHAINPARAMS_H
#define VDS_CHAINPARAMS_H

#include "chainparamsbase.h"
#include "checkpoints.h"
#include "consensus/params.h"
#include "primitives/block.h"
#include "protocol.h"

#include <vector>

struct CDNSSeedData {
    std::string name, host;
    CDNSSeedData(const std::string& strName, const std::string& strHost) : name(strName), host(strHost) {}
};

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 */
class CChainParams
{
public:
    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,

        ZCPAYMENT_ADDRRESS,
        ZCSPENDING_KEY,
        ZCVIEWING_KEY,

        MAX_BASE58_TYPES
    };

    enum Bech32Type {
        SAPLING_PAYMENT_ADDRESS,
        SAPLING_FULL_VIEWING_KEY,
        SAPLING_INCOMING_VIEWING_KEY,
        SAPLING_EXTENDED_SPEND_KEY,

        WITNESS_KEY,

        MAX_BECH32_TYPES
    };

    const Consensus::Params& GetConsensus() const
    {
        return consensus;
    }
    const CMessageHeader::MessageStartChars& MessageStart() const
    {
        return pchMessageStart;
    }
    const std::vector<unsigned char>& AlertKey() const
    {
        return vAlertPubKey;
    }
    int GetDefaultPort() const
    {
        return nDefaultPort;
    }

    /** Used if GenerateBitcoins is called with a negative number of threads */
    int DefaultMinerThreads() const
    {
        return nMinerThreads;
    }
    const CBlock& GenesisBlock() const
    {
        return genesis;
    }

    /** Make miner wait to have peers to avoid wasting work */
    bool MiningRequiresPeers() const
    {
        return fMiningRequiresPeers;
    }
    /** Default value for -checkmempool and -checkblockindex argument */
    bool DefaultConsistencyChecks() const
    {
        return fDefaultConsistencyChecks;
    }
    /** Policy: Filter transactions that do not match well-defined patterns */
    bool RequireStandard() const
    {
        return fRequireStandard;
    }
    int64_t MaxTipAge() const
    {
        return nMaxTipAge;
    }
    int64_t DelayGetHeadersTime() const
    {
        return nDelayGetHeadersTime;
    }
    int64_t PruneAfterHeight() const
    {
        return nPruneAfterHeight;
    }
    unsigned int EquihashN() const
    {
        return nEquihashN;
    }
    unsigned int EquihashK() const
    {
        return nEquihashK;
    }
    std::string CurrencyUnits() const
    {
        return strCurrencyUnits;
    }
    uint32_t BIP44CoinType() const
    {
        return bip44CoinType;
    }
    /** Make miner stop after a block is found. In RPC, don't return until nGenProcLimit blocks are generated */
    bool MineBlocksOnDemand() const
    {
        return fMineBlocksOnDemand;
    }
    /** In the future use NetworkIDString() for RPC fields */
    bool TestnetToBeDeprecatedFieldRPC() const
    {
        return fTestnetToBeDeprecatedFieldRPC;
    }
    /** Return the BIP70 network string (main, test or regtest) */
    std::string NetworkIDString() const
    {
        return strNetworkID;
    }
    const std::vector<CDNSSeedData>& DNSSeeds() const
    {
        return vSeeds;
    }
    const std::vector<unsigned char>& Base58Prefix(Base58Type type) const
    {
        return base58Prefixes[type];
    }
    const std::vector<unsigned char>& Base58BTCPrefix(Base58Type type) const
    {
        return base58BTCPrefixes[type];
    }
    const std::string& Bech32HRP(Bech32Type type) const
    {
        return bech32HRPs[type];
    }
    const std::vector<SeedSpec6>& FixedSeeds() const
    {
        return vFixedSeeds;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return checkpointData;
    }
    int PoolMaxTransactions() const
    {
        return nPoolMaxTransactions;
    }
    /** Return the founder's reward address and script for a given block height */
    std::string GetFoundersRewardAddressAtHeight(int height) const;
    CScript GetFoundersRewardScriptAtHeight(int height) const;
    CScript GetFoundersRewardScriptAtIndex(int nIndex) const;
    std::string GetFoundersRewardAddressAtIndex(int i) const;
    int FulfilledRequestExpireTime() const
    {
        return nFulfilledRequestExpireTime;
    }
    /** Enforce coinbase consensus rule in regtest mode */
    void SetRegTestCoinbaseMustBeProtected()
    {
        consensus.fCoinbaseMustBeProtected = true;
    }

    int GetBitcoinUTXOHeight() const
    {
        return consensus.nBitcoinUTXOHeight;
    }

    int GetBitcoinRootEnd() const
    {
        return consensus.nBitcoinRootEndHeight;
    }

    std::string SporkPubKey() const
    {
        return strSporkPubKey;
    }
    std::string MasternodePaymentPubKey() const
    {
        return strMasternodePaymentsPubKey;
    }

    std::string GetRootClueAddress() const
    {
        return rootClueAddress;
    }

    int ClueMaturity() const
    {
        return consensus.nClueMaturity;
    }

    uint32_t ClueChildrenDepth() const
    {
        return consensus.nClueChildrenDepth;
    }

    uint32_t ClueChildrenWidth() const
    {
        return consensus.nClueChildrenWidth;
    }

    int64_t BidAmountLimit() const
    {
        return consensus.nBidLimit;
    }

    const int SeasonOfBlock(const int blockNo) const
    {
        if (blockNo < consensus.nBlockCountOf1stSeason)
            return 1;
        int left = blockNo - consensus.nBlockCountOf1stSeason;
        return (2 + left / consensus.nBlockCountOfSeason);
    }

    const int StartBlockForSeason(const int season) const
    {
        if (season <= 1)
            return 0;
        return consensus.nBlockCountOf1stSeason + (season - 2) * consensus.nBlockCountOfSeason;
    }

    void BlockRangeForSeason(const int blockNo, int& beginBlock, int& endBlock) const
    {
        if (blockNo < consensus.nBlockCountOf1stSeason) {
            beginBlock = 0;
            endBlock = consensus.nBlockCountOf1stSeason - 1;
        } else {
            beginBlock = blockNo - ((blockNo - consensus.nBlockCountOf1stSeason) % consensus.nBlockCountOfSeason);
            endBlock = beginBlock + consensus.nBlockCountOfSeason - 1;
        }
    }

    int BlockCountOfSeason(const int season = 2) const
    {
        return (season < 2 ? consensus.nBlockCountOf1stSeason : consensus.nBlockCountOfSeason);
    }

    std::string GetScriptForPreICO() const
    {
        return strPubkeyVibPreIco;
    }

    int BlockCountOfWeek() const
    {
        return consensus.nBlockCountOfWeek;
    }

    int BlockCountOf1stSeason() const
    {
        return consensus.nBlockCountOf1stSeason;
    }

    int VibStartHeight() const
    {
        return consensus.nVibStartHeight;
    }

    int VibClue() const
    {
        return consensus.nVibClue;
    }

    int VibLucky() const
    {
        return consensus.nVibLucky;
    }

protected:
    CChainParams() {}

    Consensus::Params consensus;
    CMessageHeader::MessageStartChars pchMessageStart;
    //! Raw pub key bytes for the broadcast alert signing key.
    std::vector<unsigned char> vAlertPubKey;
    int nDefaultPort = 0;
    int nMinerThreads = 0;
    long nMaxTipAge = 0;
    int64_t nDelayGetHeadersTime;
    uint64_t nPruneAfterHeight = 0;
    unsigned int nEquihashN = 0;
    unsigned int nEquihashK = 0;
    std::vector<CDNSSeedData> vSeeds;
    std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];
    std::vector<unsigned char> base58BTCPrefixes[MAX_BASE58_TYPES];
    std::string bech32HRPs[MAX_BECH32_TYPES];
    std::string strNetworkID;
    std::string strCurrencyUnits;
    uint32_t bip44CoinType;
    CBlock genesis;
    std::vector<SeedSpec6> vFixedSeeds;
    bool fMiningRequiresPeers = false;
    bool fDefaultConsistencyChecks = false;
    bool fRequireStandard = false;
    bool fMineBlocksOnDemand = false;
    bool fTestnetToBeDeprecatedFieldRPC = false;
    Checkpoints::CCheckpointData checkpointData;
    int nPoolMaxTransactions;
    int nFulfilledRequestExpireTime;
    std::vector<std::string> vFoundersRewardAddress;
    std::string strSporkPubKey;
    std::string strMasternodePaymentsPubKey;
    std::string rootClueAddress;
    std::string strPubkeyVibPreIco;
};

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */
const CChainParams& Params();

/** Return parameters for the given network. */
CChainParams& Params(const std::string& chain);

/** Sets the params returned by Params() to those for the given network. */
void SelectParams(const std::string& chain);

#endif // VDS_CHAINPARAMS_H
