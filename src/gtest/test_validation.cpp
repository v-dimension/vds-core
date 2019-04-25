#include <gtest/gtest.h>

#include "consensus/validation.h"
#include "validation.h"

extern bool ReceivedBlockTransactions(const CBlock& block, CValidationState& state, CBlockIndex* pindexNew, const CDiskBlockPos& pos);

void ExpectOptionalAmount(CAmount expected, boost::optional<CAmount> actual)
{
    EXPECT_TRUE((bool)actual);
    if (actual) {
        EXPECT_EQ(expected, *actual);
    }
}

class FakeClueViewDB: public CClueView
{
public:
    FakeClueViewDB() {}
};

// Fake an empty view
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
        return false;
    }

    bool HaveCoin(const COutPoint& outpoint) const
    {
        return false;
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
                    CNullifiersMap saplingNullifiersMap)
    {
        return false;
    }

    bool GetStats(CCoinsStats& stats) const
    {
        return false;
    }
};

TEST(Validation, ContextualCheckInputsPassesWithCoinbase)
{
    // Create fake coinbase transaction
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    CTransaction tx(mtx);
    ASSERT_TRUE(tx.IsCoinBase());

    // Fake an empty view
    FakeCoinsViewDB fakeDB;
    FakeClueViewDB fakeClue;
    CCoinsViewCache view(&fakeDB);
    CClueViewCache clueview(&fakeClue);

    {
        CValidationState state;
        PrecomputedTransactionData txdata(tx);
        EXPECT_TRUE(ContextualCheckInputs(tx, state, view, clueview, false, 0, false, txdata, Params(CBaseChainParams::MAIN).GetConsensus(), nullptr));
    }
}
