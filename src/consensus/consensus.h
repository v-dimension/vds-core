// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VDS_CONSENSUS_CONSENSUS_H
#define VDS_CONSENSUS_CONSENSUS_H

#include <stdlib.h>
#include <stdint.h>

/** The minimum allowed block version (network rule) */
static const int MIN_BLOCK_VERSION = 4;
/** The minimum allowed transaction version (network rule) */
static const int MIN_TX_VERSION = 1;
/** The maximum allowed size for a serialized block, in bytes (network rule) */
static const unsigned int MAX_BLOCK_SIZE = 8000000;
/** The maximum allowed size for a serialized block, in bytes (network rule) */
static const unsigned int MAX_BLOCK_WEIGHT = 32000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const unsigned int MAX_BLOCK_SIGOPS = 200000;
/** The maximum size of a transaction (network rule) */
static const unsigned int MAX_TX_SIZE = 4000000;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;
/** The minimum value which is invalid for expiry height, used by CTransaction and CMutableTransaction */
static constexpr unsigned int TX_EXPIRY_HEIGHT_THRESHOLD = 500000000;

static const int WITNESS_SCALE_FACTOR = 4;

static const int MAX_TRANSACTION_BASE_SIZE = 1000000;

static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
enum {
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

#endif // VDS_CONSENSUS_CONSENSUS_H
