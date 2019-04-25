#include <gtest/gtest.h>

#include "test/data/sapling_key_components.json.h"

#include "keystore.h"
#include "random.h"
#ifdef ENABLE_WALLET
#include "wallet/crypter.h"
#endif
#include "vds/Address.hpp"
#include "vds/zip32.h"

#include "json_test_vectors.h"

#define MAKE_STRING(x) std::string((x), (x)+sizeof(x))

TEST(keystore_tests, StoreAndRetrieveHDSeed)
{
    CBasicKeyStore keyStore;
    HDSeed seedOut;

    // When we haven't set a seed, we shouldn't get one
    EXPECT_FALSE(keyStore.HaveHDSeed());
    EXPECT_FALSE(keyStore.GetHDSeed(seedOut));

    // Generate a random seed
    auto seed = HDSeed::Random();

    // We should be able to set and retrieve the seed
    ASSERT_TRUE(keyStore.SetHDSeed(seed));
    EXPECT_TRUE(keyStore.HaveHDSeed());
    ASSERT_TRUE(keyStore.GetHDSeed(seedOut));
    EXPECT_EQ(seed, seedOut);

    // Generate another random seed
    auto seed2 = HDSeed::Random();
    EXPECT_NE(seed, seed2);

    // We should not be able to set and retrieve a different seed
    EXPECT_FALSE(keyStore.SetHDSeed(seed2));
    ASSERT_TRUE(keyStore.GetHDSeed(seedOut));
    EXPECT_EQ(seed, seedOut);
}

TEST(keystore_tests, sapling_keys)
{
    // ["sk, ask, nsk, ovk, ak, nk, ivk, default_d, default_pk_d, note_v, note_r, note_cm, note_pos, note_nf"],
    UniValue sapling_keys = read_json(MAKE_STRING(json_tests::sapling_key_components));

    // Skipping over comments in sapling_key_components.json file
    for (size_t i = 2; i < 12; i++) {
        uint256 skSeed, ask, nsk, ovk, ak, nk, ivk;
        skSeed.SetHex(sapling_keys[i][0].getValStr());
        ask.SetHex(sapling_keys[i][1].getValStr());
        nsk.SetHex(sapling_keys[i][2].getValStr());
        ovk.SetHex(sapling_keys[i][3].getValStr());
        ak.SetHex(sapling_keys[i][4].getValStr());
        nk.SetHex(sapling_keys[i][5].getValStr());
        ivk.SetHex(sapling_keys[i][6].getValStr());

        libzcash::diversifier_t default_d;
        std::copy_n(ParseHex(sapling_keys[i][7].getValStr()).begin(), 11, default_d.begin());

        uint256 default_pk_d;
        default_pk_d.SetHex(sapling_keys[i][8].getValStr());

        auto sk = libzcash::SaplingSpendingKey(skSeed);

        // Check that expanded spending key from primitives and from sk are the same
        auto exp_sk_2 = libzcash::SaplingExpandedSpendingKey(ask, nsk, ovk);
        auto exp_sk = sk.expanded_spending_key();
        EXPECT_EQ(exp_sk, exp_sk_2);

        // Check that full viewing key derived from sk and expanded sk are the same
        auto full_viewing_key = sk.full_viewing_key();
        EXPECT_EQ(full_viewing_key, exp_sk.full_viewing_key());

        // Check that full viewing key from primitives and from sk are the same
        auto full_viewing_key_2 = libzcash::SaplingFullViewingKey(ak, nk, ovk);
        EXPECT_EQ(full_viewing_key, full_viewing_key_2);

        // Check that incoming viewing key from primitives and from sk are the same
        auto in_viewing_key = full_viewing_key.in_viewing_key();
        auto in_viewing_key_2 = libzcash::SaplingIncomingViewingKey(ivk);
        EXPECT_EQ(in_viewing_key, in_viewing_key_2);

        // Check that the default address from primitives and from sk method are the same
        auto default_addr = sk.default_address();
        auto addrOpt2 = in_viewing_key.address(default_d);
        EXPECT_TRUE(addrOpt2);
        auto default_addr_2 = addrOpt2.value();
        EXPECT_EQ(default_addr, default_addr_2);

        auto default_addr_3 = libzcash::SaplingPaymentAddress(default_d, default_pk_d);
        EXPECT_EQ(default_addr_2, default_addr_3);
        EXPECT_EQ(default_addr, default_addr_3);
    }
}

// Sapling
TEST(keystore_tests, StoreAndRetrieveSaplingSpendingKey)
{
    CBasicKeyStore keyStore;
    libzcash::SaplingExtendedSpendingKey skOut;
    libzcash::SaplingFullViewingKey fvkOut;
    libzcash::SaplingIncomingViewingKey ivkOut;

    std::vector<unsigned char, secure_allocator<unsigned char>> rawSeed(32);
    HDSeed seed(rawSeed);
    auto sk = libzcash::SaplingExtendedSpendingKey::Master(seed);
    auto fvk = sk.expsk.full_viewing_key();
    auto ivk = fvk.in_viewing_key();
    auto addr = sk.DefaultAddress();

    // Sanity-check: we can't get a key we haven't added
    EXPECT_FALSE(keyStore.HaveSaplingSpendingKey(fvk));
    EXPECT_FALSE(keyStore.GetSaplingSpendingKey(fvk, skOut));
    // Sanity-check: we can't get a full viewing key we haven't added
    EXPECT_FALSE(keyStore.HaveSaplingFullViewingKey(ivk));
    EXPECT_FALSE(keyStore.GetSaplingFullViewingKey(ivk, fvkOut));
    // Sanity-check: we can't get an incoming viewing key we haven't added
    EXPECT_FALSE(keyStore.HaveSaplingIncomingViewingKey(addr));
    EXPECT_FALSE(keyStore.GetSaplingIncomingViewingKey(addr, ivkOut));

    // When we specify the default address, we get the full mapping
    keyStore.AddSaplingSpendingKey(sk, addr);
    EXPECT_TRUE(keyStore.HaveSaplingSpendingKey(fvk));
    EXPECT_TRUE(keyStore.GetSaplingSpendingKey(fvk, skOut));
    EXPECT_TRUE(keyStore.HaveSaplingFullViewingKey(ivk));
    EXPECT_TRUE(keyStore.GetSaplingFullViewingKey(ivk, fvkOut));
    EXPECT_TRUE(keyStore.HaveSaplingIncomingViewingKey(addr));
    EXPECT_TRUE(keyStore.GetSaplingIncomingViewingKey(addr, ivkOut));
    EXPECT_EQ(sk, skOut);
    EXPECT_EQ(fvk, fvkOut);
    EXPECT_EQ(ivk, ivkOut);
}

#ifdef ENABLE_WALLET
class TestCCryptoKeyStore : public CCryptoKeyStore
{
public:
    bool EncryptKeys(CKeyingMaterial& vMasterKeyIn)
    {
        return CCryptoKeyStore::EncryptKeys(vMasterKeyIn);
    }
    bool Unlock(const CKeyingMaterial& vMasterKeyIn)
    {
        return CCryptoKeyStore::Unlock(vMasterKeyIn);
    }
};

TEST(keystore_tests, StoreAndRetrieveHDSeedInEncryptedStore)
{
    TestCCryptoKeyStore keyStore;
    CKeyingMaterial vMasterKey(32, 0);
    GetRandBytes(vMasterKey.data(), 32);
    HDSeed seedOut;

    // 1) Test adding a seed to an unencrypted key store, then encrypting it
    auto seed = HDSeed::Random();
    EXPECT_FALSE(keyStore.HaveHDSeed());
    EXPECT_FALSE(keyStore.GetHDSeed(seedOut));

    ASSERT_TRUE(keyStore.SetHDSeed(seed));
    EXPECT_TRUE(keyStore.HaveHDSeed());
    ASSERT_TRUE(keyStore.GetHDSeed(seedOut));
    EXPECT_EQ(seed, seedOut);

    ASSERT_TRUE(keyStore.EncryptKeys(vMasterKey));
    EXPECT_FALSE(keyStore.GetHDSeed(seedOut));

    // Unlocking with a random key should fail
    CKeyingMaterial vRandomKey(32, 0);
    GetRandBytes(vRandomKey.data(), 32);
    EXPECT_FALSE(keyStore.Unlock(vRandomKey));

    // Unlocking with a slightly-modified vMasterKey should fail
    CKeyingMaterial vModifiedKey(vMasterKey);
    vModifiedKey[0] += 1;
    EXPECT_FALSE(keyStore.Unlock(vModifiedKey));

    // Unlocking with vMasterKey should succeed
    ASSERT_TRUE(keyStore.Unlock(vMasterKey));
    ASSERT_TRUE(keyStore.GetHDSeed(seedOut));
    EXPECT_EQ(seed, seedOut);

    // 2) Test replacing the seed in an already-encrypted key store fails
    auto seed2 = HDSeed::Random();
    EXPECT_FALSE(keyStore.SetHDSeed(seed2));
    EXPECT_TRUE(keyStore.HaveHDSeed());
    ASSERT_TRUE(keyStore.GetHDSeed(seedOut));
    EXPECT_EQ(seed, seedOut);

    // 3) Test adding a new seed to an already-encrypted key store
    TestCCryptoKeyStore keyStore2;

    // Add a Sprout address so the wallet has something to test when decrypting
    // ASSERT_TRUE(keyStore2.AddSaplingSpendingKey(libzcash::SaplingSpendingKey::random())); // TODO: add a new sapling address to keystore2

    ASSERT_TRUE(keyStore2.EncryptKeys(vMasterKey));
    ASSERT_TRUE(keyStore2.Unlock(vMasterKey));

    EXPECT_FALSE(keyStore2.HaveHDSeed());
    EXPECT_FALSE(keyStore2.GetHDSeed(seedOut));

    auto seed3 = HDSeed::Random();
    ASSERT_TRUE(keyStore2.SetHDSeed(seed3));
    EXPECT_TRUE(keyStore2.HaveHDSeed());
    ASSERT_TRUE(keyStore2.GetHDSeed(seedOut));
    EXPECT_EQ(seed3, seedOut);
}


#endif
