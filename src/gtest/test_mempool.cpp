#include <gtest/gtest.h>
#include <gtest/gtest-spi.h>

#include "consensus/validation.h"
#include "core_io.h"
#include "validation.h"
#include "primitives/transaction.h"
#include "txmempool.h"
#include "policy/fees.h"
#include "util.h"

// Implementation is in test_checktransaction.cpp
extern CMutableTransaction GetValidTransaction();

// Fake the input of transaction 5295156213414ed77f6e538e7e8ebe14492156906b9fe995b242477818789364
// - 532639cc6bebed47c1c69ae36dd498c68a012e74ad12729adbd3dbb56f8f3f4a, 0
class FakeCoinsViewDB : public CCoinsView
{
public:
    FakeCoinsViewDB() {}

    bool GetSaplingAnchorAt(const uint256& rt, SaplingMerkleTree& tree) const
    {
        return false;
    }

    bool GetNullifier(const uint256& nf, ShieldedType type) const
    {
        return false;
    }

    bool GetCoin(const uint256& txid, Coin& coin) const
    {
        CTxOut txOut;
        txOut.nValue = 4288035;
        coin.out = txOut;
        coin.nHeight = 92045;
        return true;
    }

    bool HaveCoin(const COutPoint& outpoint) const
    {
        return true;
    }

    uint256 GetBestBlock() const
    {
        uint256 a;
        return a;
    }

    uint256 GetBestAnchor(ShieldedType type) const
    {
        uint256 a;
        return a;
    }

    bool BatchWrite(CCoinsMap& mapCoins,
                    const uint256& hashBlock,
                    const uint256& hashSaplingAnchor,
                    CAnchorsSaplingMap& mapSaplingAnchors,
                    CNullifiersMap& mapSaplingNullifiers)
    {
        return false;
    }

    bool GetStats(CCoinsStats& stats) const
    {
        return false;
    }
};

TEST(Mempool, TxInputLimit)
{
    SelectParams(CBaseChainParams::REGTEST);

    CTxMemPool pool;
    bool missingInputs;

    // Create an obviously-invalid transaction
    // We intentionally set tx.nVersion = 0 to reliably trigger an error, as
    // it's the first check that occurs after the -mempooltxinputlimit check,
    // and it means that we don't have to mock out a lot of global state.
    CMutableTransaction mtx;
    mtx.nVersion = 0;
    mtx.vin.resize(10);

    // Check it fails as expected
    CValidationState state1;
    CTransaction tx1(mtx);
    EXPECT_FALSE(AcceptToMemoryPool(pool, state1, MakeTransactionRef(tx1), false, &missingInputs, nullptr, true, 0));
    EXPECT_EQ(state1.GetRejectReason(), "bad-txns-version-too-low");

    // Set a limit
    mapArgs["-mempooltxinputlimit"] = "10";

    // Check it still fails as expected
    CValidationState state2;
    EXPECT_FALSE(AcceptToMemoryPool(pool, state2, MakeTransactionRef(tx1), false, &missingInputs, nullptr, true, 0));
    EXPECT_EQ(state2.GetRejectReason(), "bad-txns-version-too-low");

    // Resize the transaction
    mtx.vin.resize(11);

    // Check it now fails due to exceeding the limit
    CValidationState state3;
    CTransaction tx3(mtx);
    EXPECT_FALSE(AcceptToMemoryPool(pool, state3, MakeTransactionRef(tx3), false, &missingInputs, nullptr, true, 0));
    // The -mempooltxinputlimit check doesn't set a reason
    EXPECT_EQ(state3.GetRejectReason(), "");

    // Check it no longer fails due to exceeding the limit
    CValidationState state4;
    EXPECT_FALSE(AcceptToMemoryPool(pool, state4, MakeTransactionRef(tx3), false, &missingInputs, nullptr, true, 0));
    EXPECT_EQ(state4.GetRejectReason(), "bad-txns-version-too-low");

    // Check it now fails due to exceeding the limit
    CValidationState state5;
    EXPECT_FALSE(AcceptToMemoryPool(pool, state5, MakeTransactionRef(tx3), false, &missingInputs, nullptr, true, 0));
    // The -mempooltxinputlimit check doesn't set a reason
    EXPECT_EQ(state5.GetRejectReason(), "");

    // Clear the limit
    mapArgs.erase("-mempooltxinputlimit");

    // Check it no longer fails due to exceeding the limit
    CValidationState state6;
    EXPECT_FALSE(AcceptToMemoryPool(pool, state6, MakeTransactionRef(tx3), false, &missingInputs, nullptr, true, 0));
    EXPECT_EQ(state6.GetRejectReason(), "bad-txns-version-too-low");
}

// Valid overwinter v3 format tx gets rejected because overwinter hasn't activated yet.
TEST(Mempool, OverwinterNotActiveYet)
{
    SelectParams(CBaseChainParams::REGTEST);

    CTxMemPool pool;
    bool missingInputs;
    CMutableTransaction mtx = GetValidTransaction();
    mtx.nExpiryHeight = 0;
    CValidationState state1;

    CTransaction tx1(mtx);
    EXPECT_FALSE(AcceptToMemoryPool(pool, state1, MakeTransactionRef(tx1), false, &missingInputs, nullptr, true, 0));
    EXPECT_EQ(state1.GetRejectReason(), "tx-overwinter-not-active");

}
