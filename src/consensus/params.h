// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VDS_CONSENSUS_PARAMS_H
#define VDS_CONSENSUS_PARAMS_H

#include "uint256.h"
#include <map>
#include <string>

namespace Consensus
{

enum DeploymentPos {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
    DEPLOYMENT_DIP0001, // Deployment of DIP0001 and lower transaction fees.
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;
    /** The number of past blocks (including the block under consideration) to be taken into account for locking in a fork. */
    int64_t nWindowSize;
    /** A number of blocks, in the range of 1..nWindowSize, which must signal for a fork in order to lock it in. */
    int64_t nThreshold;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;

    bool fCoinbaseMustBeProtected;

    int nMasternodePaymentsStartBlock;
    int nMasternodePaymentsIncreaseBlock;
    int nMasternodePaymentsIncreasePeriod; // in blocks
    int nBudgetPaymentsStartBlock;
    int nBudgetPaymentsCycleBlocks;
    int nBudgetPaymentsWindowBlocks;
    int nBudgetProposalEstablishingTime; // in seconds
    int nSuperblockStartBlock;
    int nSuperblockCycle; // in blocks
    int nMasternodeMinimumConfirmations;

    int nBidPeriod;
    int64_t nBidLimit;
    int nClueMaturity;

    int nSubsidyHalvingInterval;

    /** Used to check majorities for block version upgrade */
    int nMajorityEnforceBlockUpgrade;
    int nMajorityRejectBlockOutdated;
    int nMajorityWindow;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /**
     * Minimum blocks including miner confirmation of the total of nMinerConfirmationWindow blocks in a retargetting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Default BIP9Deployment::nThreshold value for deployments where it's not specified and for unknown deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    // Default BIP9Deployment::nWindowSize value for deployments where it's not specified and for unknown deployments.
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowAveragingWindow;
    int64_t nPowMaxAdjustDown;
    int64_t nPowMaxAdjustUp;
    int64_t nPowTargetSpacing;
    int64_t AveragingWindowTimespan() const
    {
        return nPowAveragingWindow * nPowTargetSpacing;
    }
    int64_t MinActualTimespan() const
    {
        return (AveragingWindowTimespan() * (100 - nPowMaxAdjustUp  )) / 100;
    }
    int64_t MaxActualTimespan() const
    {
        return (AveragingWindowTimespan() * (100 + nPowMaxAdjustDown)) / 100;
    }
    int64_t DifficultyAdjustmentInterval() const
    {
        return AveragingWindowTimespan() / nPowTargetSpacing;
    }

    int nBitcoinUTXOHeight;
    int nBitcoinRootEndHeight;
    int nFixUTXOCacheHFHeight;

    int nBlockCountPerDay;
    int nBlockCountOfWeek;
    int nBlockCountOfSeason;
    int nBlockCountOf1stSeason;
    int nWeekCount1stSeason;
    int nWeekCountOfSeason;

    uint32_t nClueChildrenDepth;
    uint32_t nClueChildrenWidth;

    int nVibStartHeight;
    int nVibClue;
    int nVibLucky;

    int nTandiaBallotPeriod;
    int nTandiaPayPeriod;
    uint32_t nTandiaBallotStart;

    int nFounderPayHeight;
    int64_t nFounderAmount;

    std::vector<unsigned char> nFounderScript;
};
} // namespace Consensus

#endif // VDS_CONSENSUS_PARAMS_H
