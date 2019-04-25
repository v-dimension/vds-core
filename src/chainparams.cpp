// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validation.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"
#include <key_io.h>
#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "base58.h"

using namespace std;

#include "chainparamsseeds.h"
///////////////////////////////////////////// // qtum
#include <libdevcore/SHA3.h>
#include <libdevcore/RLP.h>
#include "arith_uint256.h"
/////////////////////////////////////////////

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, int64_t nVibPool,
                                 uint32_t nTime, uint256 nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward,
                                 const std::vector<unsigned char> vSolution)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << vector<unsigned char>((const unsigned char*) pszTimestamp, (const unsigned char*) pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].nFlag = 0;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    genesis.hashFinalSaplingRoot = SaplingMerkleTree::empty_root();
    genesis.nVersion = nVersion;
    genesis.nVibPool = nVibPool;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.hashStateRoot = uint256(h256Touint(dev::h256("e965ffd002cd6ad0e2dc402b8044de833e06b23127ea8c3d80aec91410771495"))); // qtum
    genesis.hashUTXORoot = uint256(h256Touint(dev::sha3(dev::rlp("")))); // qtum
    genesis.nSolution = vSolution;
    return genesis;
}

static CBlock CreateGenesisBlock(int64_t nVibPool, uint32_t nTime, uint256 nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward, const std::vector<unsigned char> vSolution)
{
    const char* pszTimestamp = "Bitcoin000000000000000000001d07114997c2fbd5e277ae19d85b6adbb1e00d3d92b2";
    // "address": "Vchf78qDRpnF2nJipiFaXVL5b8hdLUPC2F5",
    // "btcaddr": "1HoaX1yHkoFi6ojZn5xBgFbBYP7CW2FZpZ",
    // "hash160": "b16a7e3a2b2f58e561b929997b5484ee342051b8",
    // "scriptPubKey": "76a914b8512034ee84547b9929b961e5582f2b3a7e6ab188ac",

    std::vector<unsigned char> script = ParseHex("76a914b8512034ee84547b9929b961e5582f2b3a7e6ab188ac");
    const CScript genesisOutputScript = CScript(script.begin(), script.end());

    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nVibPool, nTime, nNonce, nBits, nVersion, genesisReward, vSolution);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams
{
public:

    CMainParams()
    {
        strNetworkID = "main";
        strCurrencyUnits = "VC";
        bip44CoinType = 133;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nMasternodePaymentsStartBlock = 100000; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 158000; // actual historical value
        consensus.nMasternodePaymentsIncreasePeriod = 576 * 30; // 17280 - actual historical value
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nSuperblockStartBlock = 0;
        consensus.nSuperblockCycle = 40;
        consensus.nBidPeriod = 60;
        consensus.nBidLimit = 100 * COIN;

        consensus.nSubsidyHalvingInterval = 211680;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint / UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;

        consensus.nFixUTXOCacheHFHeight = 0;
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nBitcoinUTXOHeight = 297; // TODO: here change to candy end block
        consensus.nBitcoinRootEndHeight = 231839;

        consensus.nBlockCountPerDay = 1440;
        consensus.nWeekCount1stSeason = 3;
        consensus.nWeekCountOfSeason = 1;
        consensus.nBlockCountOfWeek = consensus.nBlockCountPerDay * 7;
        consensus.nBlockCountOf1stSeason = consensus.nBlockCountOfWeek * consensus.nWeekCount1stSeason;
        consensus.nBlockCountOfSeason = consensus.nBlockCountOfWeek * consensus.nWeekCountOfSeason;

        consensus.nClueChildrenDepth = 12;
        consensus.nClueChildrenWidth = 12;
        consensus.nClueMaturity = consensus.nBlockCountOfWeek;

        consensus.nVibStartHeight = 563012;
        consensus.nVibClue = 10;
        consensus.nVibLucky = 20;

        consensus.nTandiaPayPeriod = 144;
        consensus.nTandiaBallotPeriod = 10080;
        consensus.nTandiaBallotStart = 110500;

        consensus.nFounderPayHeight = consensus.nBlockCountOf1stSeason;
        consensus.nFounderAmount = 12000000 * COIN;
        consensus.nFounderScript = ParseHex("76a9146974d7944e5475c4982a4c0912efb17172b0598788ac");

        strPubkeyVibPreIco = "VcRM27JjdzyxvyFtXewtJHrk6NQGyo9TN7U"; //"1VVVVVVvzycHkuGinFxUnFgn5kqwFuV9P"
        const size_t N = 96, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
        /**
         * The message start string should be awesome! ⓥ❤ (ASCII)
         */
        pchMessageStart[0] = 0x24;
        pchMessageStart[1] = 0xe5;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0x64;
        vAlertPubKey = ParseHex("04b7ecf0baa90495ceb4e4090f6b2fd37eec1e9c85fac68a487f3ce11589692e4a317479316ee814e066638e1db54e37a10689b70286e6315b1087b6615d179264");
        nDefaultPort = 6533;
        nMinerThreads = 0;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;


        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60 * 60; // fulfilled requests expire in 1 hour
        strSporkPubKey = "04549ac134f694c0243f503e8c8a9a986f5de6610049c40b07816809b0d1d06a21b07be27b9bb555931773f62ba6cf35a25fd52f694d4e1106ccd237a7bb899fdd";
        strMasternodePaymentsPubKey = "04549ac134f694c0243f503e8c8a9a986f5de6610049c40b07816809b0d1d06a21b07be27b9bb555931773f62ba6cf35a25fd52f694d4e1106ccd237a7bb899fdd";
        /**
         * Build the genesis block. Note that the output of its generation
         * transaction cannot be spent since it did not originally exist in the
         * database (and is in any case of zero value).
         *
         */

        genesis = CreateGenesisBlock(

                      7052517017282037,
                      1547165612, // nTime
                      uint256S("00000000000000000000000000000000000000000000000000000000000000c1"), // nNonce
                      0x2007ffff, // nBits
                      4, // nVersion
                      1747482982717963, // genesisReward
                      ParseHex("08bc9767284a389bf0db4ff042d3c18c7d398b9dede5781b75f4a5deec7d51ad92301ae2c96f9e7f3671f3d4cf1b519f88eeab1d31d1c98c82f09fab020e0cdf4ffbb305"));

        consensus.hashGenesisBlock = genesis.GetHash();
//        std::cout <<  consensus.hashGenesisBlock.GetHex() << std::endl;
        assert(consensus.hashGenesisBlock == uint256S("0804fd488d9f5787d025d8b1e9e199301b5b42bcbe779a4e875983103c6036a8"));
        assert(genesis.hashMerkleRoot == uint256S("898ea66248eba5b44db100123c4f09c4e9fe670142268674684752a92461d133"));

        vFixedSeeds.clear();
        vSeeds.clear();


        // guarantees the first 2 characters, when base58 encoded, are "Vc"
        base58Prefixes[PUBKEY_ADDRESS] = {0x10, 0x1C};
        // guarantees the first 2 characters, when base58 encoded, are "Vs"
        base58Prefixes[SCRIPT_ADDRESS] = {0x10, 0x41};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY] = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x0B, 0x36};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8, 0xAB, 0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY] = {0x0F, 0xDB};

        base58BTCPrefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 0);
        base58BTCPrefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 5);
        base58BTCPrefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 128);

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "vs";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "vviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "vivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";
        bech32HRPs[WITNESS_KEY]                  = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
                {300, uint256S("963eb04b69717938075e48c55559e8bc382ba8abc19a4b8212421d630d5fd864")},
                {52683, uint256S("33080b760439352ba9d6c9915fd777011a8f594791f149c3743c7d4736c7efa0")}
            }
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
            "13hYCAMdStpxWCBTKoHHZ2fq6FgcuDQ3kv",
            "1DYNUp3MHkdSS7M5k9c14duRhneBzGdmyL",
            "1LY62AtewUiJPXijHHRaFqFKvR5drFWKYg",
            "1GRU6r1KewLcaVQD85BJDfCGKHr9QFrqJN",
            "1AVR2qYkMzDg1YxoLRxwfGebaAkcRVXTNM",
            "12mu3ssMCctmvi9Q9J2XuoExch8JmAP5vj",
            "15asgTHNWBTxAtDdv9Xhe8azgApdu3DQrn",
            "1CRDZFb4ZwiL7ipXbxPXSLKhE7JXf1vhku",
            "1DTqtiiqhBVfYLf4QpgSoiknpAedJfb2kL",
            "1HWQ168GPgqnd6wrx1reYqCyytFoEaCzSa",
            "14jcHNndYTzTjjLAkFg3YfBQkLLYSBFLdw",
            "1GQ2SqaDQ5FHRLkwRAWmW33qgH7MN767jV",
            "1MEZhHNJnb3sYZ4HMtQBTCX52GcVjmzAJ9",
            "18ZAu5uR6uTR8Cpqe6tePfEbySeStGjH2G",
            "1FLZG6hwUgz7pTHHt9CJfvcnDzJZKtgn88",
            "152dc9tr7orA92wHKt7FGNMmbAtd1xr9rR",
            "1BtNPDMf72GmEoNLTkcZgnj3pAYAVasuhU",
            "1Dy83ZFtfekTmDzqiPw1ZSFi7h2FQn3kTy",
            "121j6w3VSFsz49zAKWYJk5yu1wiMXzvb8i",
            "1EvjGdTj7FJaejdBvzrDT8NuA95JT4DYaP",
            "16cUmvxgFntHJzNWir3T7GzNbmENVQZ6hw",
            "15trmMYDgKvpGH9gFWSJ3WHE3g33gdfsYM",
            "15NH8rfYbztQPCKNy6kKkgPJVGy395uf7P",
            "16npZB4AkjGb2WUqnPZirMttsMVzXEAF9g",
            "14RgprMLZFp36U7W8ansJaudRTqqz1bWSU",
            "1DztbsD4ukuqJwv9JoNEFEP95eiU2PdRPi",
            "1EjT2cTtHNoDQet4pRV9pExuh6UPaT5LzS",
            "14Dh7yLbGErbbubUKpxCVDXp2mxyV2F5Gs",
            "19HiG6ARNkJ4QWDWmxdMKpSspGVxM8tkA2",
            "1LmJMcMY3RPjMjL2MQDfD5QmokFGcyApuj",
            "16hZaBZoAWF2GsxuUfSFLzQvXxnGLV6vjh",
            "1HUydQVEYo5B8autKbnif91gKrBgYGuXQf",
            "1DtskuaGsVY4iKst5tgmSoGLgE2zEFw8RE"

        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams
{
public:

    CTestNetParams()
    {
        strNetworkID = "test";
        strCurrencyUnits = "vc";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nMasternodePaymentsStartBlock = 10000; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 46000;
        consensus.nMasternodePaymentsIncreasePeriod = 576;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nSuperblockStartBlock = 0;
        consensus.nSuperblockCycle = 40;
        consensus.nBidPeriod = 60;
        consensus.nBidLimit = 100 * COIN;

        consensus.nSubsidyHalvingInterval = 211680;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;

        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        consensus.nPowMaxAdjustDown = 32; //
        consensus.nPowMaxAdjustUp = 16; //
        consensus.nPowTargetSpacing = 10;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;


        assert(maxUint / UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nFixUTXOCacheHFHeight = 0;
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nBitcoinUTXOHeight = 297; // TODO: here change to candy end block
        consensus.nBitcoinRootEndHeight = 231839;

        consensus.nBlockCountPerDay = 1440;
        consensus.nWeekCount1stSeason = 3;
        consensus.nWeekCountOfSeason = 1;
        consensus.nBlockCountOfWeek = consensus.nBlockCountPerDay * 7;
        consensus.nBlockCountOf1stSeason = consensus.nBlockCountOfWeek * consensus.nWeekCount1stSeason;
        consensus.nBlockCountOfSeason = consensus.nBlockCountOfWeek * consensus.nWeekCountOfSeason;

        consensus.nClueMaturity = consensus.nBlockCountOfWeek;

        consensus.nClueChildrenDepth = 12;
        consensus.nClueChildrenWidth = 12;

        consensus.nVibStartHeight = 300;
        consensus.nVibClue = 10;
        consensus.nVibLucky = 20;

        consensus.nTandiaPayPeriod = 144;
        consensus.nTandiaBallotPeriod = 10080;
        consensus.nTandiaBallotStart = 110500;

        consensus.nFounderPayHeight = consensus.nBlockCountOf1stSeason;
        consensus.nFounderAmount = 12000000 * COIN;
        consensus.nFounderScript = ParseHex("76a9146974d7944e5475c4982a4c0912efb17172b0598788ac");

        strPubkeyVibPreIco = "vag5Xvo2pikduEKL6i5UbKbrESSQNvTqgDL";
        const size_t N = 96, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xbf;
        vAlertPubKey = ParseHex("044e7a1553392325c871c5ace5d6ad73501c66f4c185d6b0453cf45dec5a1322e705c672ac1a27ef7cdaf588c10effdf50ed5f95f85f2f54a5f6159fca394ed0c6");
        nDefaultPort = 26533;
        nMinerThreads = 0;
        nMaxTipAge = 12 * 60 * 60;
        nPruneAfterHeight = 1000;

        nFulfilledRequestExpireTime = 60 * 60; // fulfilled requests expire in 1 hour
        strSporkPubKey = "04549ac134f694c0243f503e8c8a9a986f5de6610049c40b07816809b0d1d06a21b07be27b9bb555931773f62ba6cf35a25fd52f694d4e1106ccd237a7bb899fdd";
        strMasternodePaymentsPubKey = "04549ac134f694c0243f503e8c8a9a986f5de6610049c40b07816809b0d1d06a21b07be27b9bb555931773f62ba6cf35a25fd52f694d4e1106ccd237a7bb899fdd";

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis = CreateGenesisBlock(

                      7052517017282037,
                      1547165612, // nTime
                      uint256S("0000000000000000000000000000000000000000000000000000000000000001"), // nNonce
                      0x2007ffff, // nBits
                      4, // nVersion
                      1747482982717963, // genesisReward
                      ParseHex("0c12ac1006b7febbb2d90b909f1565c99e16a1f5544ecab24512662c0604aba4e33819d928b1a38b59f986a835ad764231c31724c6961b19993c3c65ea740e95c87f36b9"));
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("bd94031d0ba5bbb72b50eecd5f5444056e5f0f788538e24261878178cdab6a62"));
        assert(genesis.hashMerkleRoot == uint256S("898ea66248eba5b44db100123c4f09c4e9fe670142268674684752a92461d133"));

        vFixedSeeds.clear();
        vSeeds.clear();

        // guarantees the first 2 characters, when base58 encoded, are "vc"
        base58Prefixes[PUBKEY_ADDRESS] = {0x1E, 0x2B};
        // guarantees the first 2 characters, when base58 encoded, are "vs"
        base58Prefixes[SCRIPT_ADDRESS] = {0x1E, 0x55};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY] = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x6B, 0x99};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8, 0xAC, 0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY] = {0x6A, 0xC2};

        base58BTCPrefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58BTCPrefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58BTCPrefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 239);

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "vtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "vviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "vivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";
        bech32HRPs[WITNESS_KEY]                  = "tb";
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            0,
            0,
            0
        };
        // Founders reward script expects a vector of 2-of-3 multisig addresses
        // PrivKey: cVPR1vvU7RU296c8jonmK1DnL8A7htMTRXTpoFWkwBu3fWJBzddo
        // Founders reward script expects an address
        vFoundersRewardAddress = {
            "vasfGCr5uNmv154DAY6C5fZy21AeDmyuKBx",
            "vaaWu99k1Tsftzxp6RLVHyj2HEWKzuKNAb3",
            "vaaXsJAA9b877L3v38nvGbmakqyA7SxvwwQ",
            "vaarfKRkuaviG5N5tw7C3SZq1bg3dCaopw6",
            "vab5FEtXgFgcW64C8ACUjcZWobHwqMbe36y",
            "vabdmLtCsxdWFdtkBFjHKKJsZTTL38M5NZ4",
            "vabqx4cuzNq71GHxtiFKcHyW8t6YLbZ978E",
            "vabveUN98NNAjiaGEcnQgLpfXh217b8eWkb",
            "vac13xRGmHikbFqxEfVMEi1KyFaA7diKUfd",
            "vacWRJy1jGjFWCUyo8bsDL3rEh5hKEJpRVd",
            "vacZ7yGTMEjch4NxYePB1cCErTwMTUSHyhB",
            "vacvPphjryM1eodDqTbAtiGhQnafbtGNL4Z",
            "vad8mQVmt6VBcmJ9wmNHNkhLvM6otq2FMGt",
            "vadEnYbzPNQocxt8ioqimnKvSm5qqv6Ls7x",
            "vadG99GUkg47JXSYpTPkxUormiM6VSrJPVS",
            "vadKNgXTZb1sopBGVJPEecTxsrWx4kAnDZm",
            "vaePj5FyNsegoQTwY3pyi3fgFEopu6CYnfn",
            "vaeiNwxLCtpmHq4tVmLTR9YmVGDfdhJSyyr",
            "vaejPFakG2ZygmrhY6VsmqrBoKXgKbFRSUV",
            "vafHTGvxM2E4yL9QgN6eJD9vvTFeuyMUy1e",
            "vafMTpvZXypNsUp2Stn4BEXp2JRSqgvwMC7",
            "vafkEidPmqw8NYSApsZijtRku7LMy6vNY9s",
            "vafmNWBiBHxjmPG2L4PK7DeZPrqG3h7QFPD",
            "vag8Vw8iYsAMLTmmAtwKvGPmcDxc7qrvQzm",
            "vag9yAynXYt8h6n8KyfSmZApzaH9AAtY2Na",
            "vagTBnPPYZi8ABVXaZTpvnvL3rmWc91gU11",
            "vagTxWLzpPUH15HJ7di8pYqQbyaVnYhRRzA",
            "vaghy3FvjSRo7tQxNfbiGBHfm2oY2NLnXkm",
            "vahAaGEGZniuyj3LfTsvCTMo439z3P667bT",
            "vahLosF5YhYsSZLUVDfN5Yk7WkYnAQ8d8fr",
            "vahfJx5MXUoNvGpy8cFsLKUuj2mSrJedRGN",
            "vahpQZsrsJCXhTo7cnsXkjxcNtU3hX1N35F",
            "vahwBQ9akxHGYCMhCbfqTFMtFA8MyeunMy3",
        };
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams
{
public:

    CRegTestParams()
    {
        strNetworkID = "regtest";
        strCurrencyUnits = "vc";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nMasternodePaymentsStartBlock = 240;
        consensus.nMasternodePaymentsIncreaseBlock = 350;
        consensus.nMasternodePaymentsIncreasePeriod = 10;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nSuperblockStartBlock = 0;
        consensus.nSuperblockCycle = 40;
        consensus.nBidPeriod = 10;
        consensus.nBidLimit = 1 * COIN;

        consensus.nSubsidyHalvingInterval = 210;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 1;
        assert(maxUint / UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPowTargetSpacing = 1;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.nFixUTXOCacheHFHeight = 0;
        consensus.nMinerConfirmationWindow = 144; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nBitcoinUTXOHeight = 120;
        consensus.nBitcoinRootEndHeight = 360;
        consensus.fPowNoRetargeting = false;

        consensus.nBlockCountPerDay = 100;
        consensus.nWeekCount1stSeason = 3;
        consensus.nWeekCountOfSeason = 1;
        consensus.nBlockCountOfWeek = consensus.nBlockCountPerDay * 7;
        consensus.nBlockCountOf1stSeason = consensus.nBlockCountOfWeek * consensus.nWeekCount1stSeason;
        consensus.nBlockCountOfSeason = consensus.nBlockCountOfWeek * consensus.nWeekCountOfSeason;

        consensus.nClueMaturity = consensus.nBlockCountOfWeek;
        consensus.nClueChildrenDepth = 12;
        consensus.nClueChildrenWidth = 12;

        consensus.nVibStartHeight = 140;
        consensus.nVibClue = 3;
        consensus.nVibLucky = 3;

        consensus.nTandiaPayPeriod = 10;
        consensus.nTandiaBallotPeriod = 70;
        consensus.nTandiaBallotStart = 105;

        consensus.nFounderPayHeight = consensus.nBlockCountOf1stSeason;
        consensus.nFounderAmount = 12000000 * COIN;
        consensus.nFounderScript = ParseHex("76a9146974d7944e5475c4982a4c0912efb17172b0598788ac");

        strPubkeyVibPreIco = "vag5Xvo2pikduEKL6i5UbKbrESSQNvTqgDL";
        const size_t N = 96, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nMinerThreads = 1;
        nMaxTipAge = 24 * 60 * 60;

        genesis = CreateGenesisBlock(
                      7052517017282037,
                      1547165612,
                      uint256S("00000000000000000000000000000000000000000000000000000000000000aa"),
                      0x207fffff,
                      4,
                      1747482982717963,
                      ParseHex("05301f3bc8725d28e321b3959ae31572a21c06e9535dd8b0b665950d8949b10d3ee60ed2e2fca3ec7630e20fa5e1d6feabf89d1c185dc6157cb9d0029c0f05f50ac3f439"));
        consensus.hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 16533;
//        std::cout << "GenesisBlockHash: " << consensus.hashGenesisBlock.GetHex() << std::endl;
        assert(consensus.hashGenesisBlock == uint256S("61a8f1d40cac7b7b611e4bedf8d821f98c4b1d4dbef895237e1209e50c75f5e2"));
        assert(genesis.hashMerkleRoot == uint256S("898ea66248eba5b44db100123c4f09c4e9fe670142268674684752a92461d133"));
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear(); //! Regtest mode doesn't have any DNS seeds.

        // guarantees the first 2 characters, when base58 encoded, are "vc"
        base58Prefixes[PUBKEY_ADDRESS] = {0x1E, 0x2B};
        // guarantees the first 2 characters, when base58 encoded, are "vs"
        base58Prefixes[SCRIPT_ADDRESS] = {0x1E, 0x55};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY] = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x6B, 0x99};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8, 0xAC, 0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY] = {0x6A, 0xC2};

        base58BTCPrefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58BTCPrefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58BTCPrefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 239);

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "vregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "vviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "vivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";
        bech32HRPs[WITNESS_KEY]                  = "bcrt";

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            0,
            0,
            0
        };

        // PrivKey: cVPR1vvU7RU296c8jonmK1DnL8A7htMTRXTpoFWkwBu3fWJBzddo
        // Founders reward script expects an address
        vFoundersRewardAddress = {
            "vasfGCr5uNmv154DAY6C5fZy21AeDmyuKBx",
            "vaaWu99k1Tsftzxp6RLVHyj2HEWKzuKNAb3",
            "vaaXsJAA9b877L3v38nvGbmakqyA7SxvwwQ",
            "vaarfKRkuaviG5N5tw7C3SZq1bg3dCaopw6",
            "vab5FEtXgFgcW64C8ACUjcZWobHwqMbe36y",
            "vabdmLtCsxdWFdtkBFjHKKJsZTTL38M5NZ4",
            "vabqx4cuzNq71GHxtiFKcHyW8t6YLbZ978E",
            "vabveUN98NNAjiaGEcnQgLpfXh217b8eWkb",
            "vac13xRGmHikbFqxEfVMEi1KyFaA7diKUfd",
            "vacWRJy1jGjFWCUyo8bsDL3rEh5hKEJpRVd",
            "vacZ7yGTMEjch4NxYePB1cCErTwMTUSHyhB",
            "vacvPphjryM1eodDqTbAtiGhQnafbtGNL4Z",
            "vad8mQVmt6VBcmJ9wmNHNkhLvM6otq2FMGt",
            "vadEnYbzPNQocxt8ioqimnKvSm5qqv6Ls7x",
            "vadG99GUkg47JXSYpTPkxUormiM6VSrJPVS",
            "vadKNgXTZb1sopBGVJPEecTxsrWx4kAnDZm",
            "vaePj5FyNsegoQTwY3pyi3fgFEopu6CYnfn",
            "vaeiNwxLCtpmHq4tVmLTR9YmVGDfdhJSyyr",
            "vaejPFakG2ZygmrhY6VsmqrBoKXgKbFRSUV",
            "vafHTGvxM2E4yL9QgN6eJD9vvTFeuyMUy1e",
            "vafMTpvZXypNsUp2Stn4BEXp2JRSqgvwMC7",
            "vafkEidPmqw8NYSApsZijtRku7LMy6vNY9s",
            "vafmNWBiBHxjmPG2L4PK7DeZPrqG3h7QFPD",
            "vag8Vw8iYsAMLTmmAtwKvGPmcDxc7qrvQzm",
            "vag9yAynXYt8h6n8KyfSmZApzaH9AAtY2Na",
            "vagTBnPPYZi8ABVXaZTpvnvL3rmWc91gU11",
            "vagTxWLzpPUH15HJ7di8pYqQbyaVnYhRRzA",
            "vaghy3FvjSRo7tQxNfbiGBHfm2oY2NLnXkm",
            "vahAaGEGZniuyj3LfTsvCTMo439z3P667bT",
            "vahLosF5YhYsSZLUVDfN5Yk7WkYnAQ8d8fr",
            "vahfJx5MXUoNvGpy8cFsLKUuj2mSrJedRGN",
            "vahpQZsrsJCXhTo7cnsXkjxcNtU3hX1N35F",
            "vahwBQ9akxHGYCMhCbfqTFMtFA8MyeunMy3",
        };
    }
};
static CRegTestParams regTestParams;

static CChainParams* pCurrentParams = 0;

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
        return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
        return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }
}

// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)

std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const
{
    assert(nHeight > 0);

    size_t addressChangeInterval = vFoundersRewardAddress.size();
    size_t i = nHeight % addressChangeInterval;
    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address for mainnet but regtest

CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const
{
    assert(nHeight > 0);

    CTxDestination destination = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(destination));
    return GetScriptForDestination(destination);
}

CScript CChainParams::GetFoundersRewardScriptAtIndex(int nIndex) const
{
    assert(nIndex >= 0);

    CTxDestination destination = DecodeDestination(GetFoundersRewardAddressAtIndex(nIndex).c_str());
    assert(IsValidDestination(destination));
    return GetScriptForDestination(destination);
}


std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const
{
    i = i % vFoundersRewardAddress.size();
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}
