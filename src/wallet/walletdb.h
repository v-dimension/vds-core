// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VDS_WALLET_WALLETDB_H
#define VDS_WALLET_WALLETDB_H

#include "amount.h"
#include "wallet/db.h"
#include "key.h"
#include "keystore.h"
#include "crypter.h"
#include "vds/Address.hpp"
#include "vds/zip32.h"

#include <list>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

struct CBlockLocator;
class CKeyPool;
class CMasterKey;
class CScript;
class CWallet;
class CWalletTx;
class uint160;
class uint256;

/** Error statuses for the wallet database */
enum DBErrors {
    DB_LOAD_OK,
    DB_CORRUPT,
    DB_NONCRITICAL_ERROR,
    DB_TOO_NEW,
    DB_LOAD_FAIL,
    DB_NEED_REWRITE
};

/* simple HD chain data model */
class CHDChain
{
public:
    uint32_t nExternalChainCounter;
    uint32_t saplingAccountCounter;
    CPubKey masterPubKey; //!< master pub key, which is m of m/0'/0'/c'

    static const int VERSION_HD_BASE = 1;
    static const int CURRENT_VERSION = VERSION_HD_BASE;
    int nVersion;
    int64_t nCreateTime; // 0 means unknown

    CHDChain()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(this->nVersion);
        READWRITE(nCreateTime);
        READWRITE(nExternalChainCounter);
        READWRITE(saplingAccountCounter);
        READWRITE(masterPubKey);
    }

    void SetNull()
    {
        nVersion = CHDChain::CURRENT_VERSION;
        nCreateTime = 0;
        nExternalChainCounter = 0;
        masterPubKey = CPubKey();
    }
};

enum KeyCategory {
    KeyCategoryUnknown = 0x00,
    KeyCategoryHD = 0x01,
    KeyCategoryLonely = 0x02,//imported private key
    KeyCategoryWitness = 0x04,
    KeyCategoryMultisig = 0x08,
    KeyCategoryVID = 0x10,
    KeyCategoryHDVID = KeyCategoryHD | KeyCategoryVID,
    KeyCategorySapling = 0x20,
    KeyCategoryHDLonely = KeyCategoryHD | KeyCategoryLonely,
};

class CKeyMetadata
{
public:
    static const int CURRENT_VERSION = 1;
    int nVersion;
    int64_t nCreateTime; // 0 means unknown
    KeyCategory keyCategory;
    std::string hdKeypath; //optional HD/bip32 keypath
    CPubKey hdMasterPubKey; //HD master PubKey used to derive this key

    CKeyMetadata()
    {
        SetNull();
    }
    CKeyMetadata(int64_t nCreateTime_, KeyCategory category = KeyCategoryHD)
    {
        nVersion = CKeyMetadata::CURRENT_VERSION;
        nCreateTime = nCreateTime_;
        keyCategory = category;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(this->nVersion);
        READWRITE(nCreateTime);
        int category = keyCategory;
        READWRITE(category);
        keyCategory = (KeyCategory)category;
        READWRITE(hdKeypath);
        READWRITE(hdMasterPubKey);
    }

    void SetNull()
    {
        nVersion = CKeyMetadata::CURRENT_VERSION;
        nCreateTime = 0;
        keyCategory = KeyCategoryHD;
        hdKeypath.clear();
        hdMasterPubKey = CPubKey();
    }

    bool IsLonely()
    {
        return (keyCategory & KeyCategoryLonely) == KeyCategoryLonely;
    }

    bool IsHD()
    {
        return keyCategory == KeyCategoryHD;
    }
};

/** Access to the wallet database (wallet.dat) */
class CWalletDB : public CDB
{
public:
    CWalletDB(const std::string& strFilename, const char* pszMode = "r+", bool fFlushOnClose = true) : CDB(strFilename, pszMode, fFlushOnClose)
    {
    }

    bool WriteName(const std::string& strAddress, const std::string& strName);
    bool EraseName(const std::string& strAddress);

    bool WritePurpose(const std::string& strAddress, const std::string& purpose);
    bool ErasePurpose(const std::string& strAddress);

    bool WriteTx(uint256 hash, const CWalletTx& wtx);
    bool WriteTx(const CWalletTx& wtx);
    bool EraseTx(uint256 hash);

    bool WriteKeyMeta(const CPubKey& vchPubKey, const CKeyMetadata& keyMeta);
    bool WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata& keyMeta);
    bool WriteCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret, const CKeyMetadata& keyMeta);
    bool WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey);

    bool ReadScriptMeta(const CScriptID& scriptID, CKeyMetadata& metaData);
    bool WriteScriptMeta(const CScriptID& scriptID, const CKeyMetadata& kMasterKey);
    bool WriteCScript(const uint160& hash, const CScript& redeemScript);
    bool EraseScriptMeta(const CScriptID& scriptID);

    bool WriteWatchOnly(const CScript& script);
    bool EraseWatchOnly(const CScript& script);

    bool WriteBestBlock(const CBlockLocator& locator);
    bool ReadBestBlock(CBlockLocator& locator);

    bool WriteOrderPosNext(int64_t nOrderPosNext);

    bool WriteDefaultKey(const CPubKey& vchPubKey);

    bool WriteWitnessCacheSize(int64_t nWitnessCacheSize);

    bool ReadPool(int64_t nPool, CKeyPool& keypool);
    bool WritePool(int64_t nPool, const CKeyPool& keypool);
    bool ErasePool(int64_t nPool);

    bool WriteMinVersion(int nVersion);

    /// Write destination data key,value tuple to database
    bool WriteDestData(const std::string& address, const std::string& key, const std::string& value);
    /// Erase destination data tuple from wallet database
    bool EraseDestData(const std::string& address, const std::string& key);

    DBErrors ReorderTransactions(CWallet* pwallet);
    DBErrors LoadWallet(CWallet* pwallet);
    DBErrors FindWalletTx(CWallet* pwallet, std::vector<uint256>& vTxHash, std::vector<CWalletTx>& vWtx);
    DBErrors ZapWalletTx(CWallet* pwallet, std::vector<CWalletTx>& vWtx);
    static bool Recover(CDBEnv& dbenv, const std::string& filename, bool fOnlyKeys);
    static bool Recover(CDBEnv& dbenv, const std::string& filename);

    bool WriteHDSeed(const HDSeed& seed);
    bool WriteCryptedHDSeed(const uint256& seedFp, const std::vector<unsigned char>& vchCryptedSecret);
    //! write the hdchain model (external chain child index counter)
    bool WriteHDChain(const CHDChain& chain);

    /// Write spending key to wallet database, where key is payment address and value is spending key.
    bool WriteSaplingZKey(const libzcash::SaplingIncomingViewingKey& ivk,
                          const libzcash::SaplingExtendedSpendingKey& key,
                          const CKeyMetadata&  keyMeta);
    bool WriteSaplingPaymentAddress(const libzcash::SaplingPaymentAddress& addr,
                                    const libzcash::SaplingIncomingViewingKey& ivk);
    bool WriteCryptedSaplingZKey(const libzcash::SaplingExtendedFullViewingKey& extfvk,
                                 const std::vector<unsigned char>& vchCryptedSecret,
                                 const CKeyMetadata& keyMeta);

    //! write hd master seed
    bool WriteHDMasterSeed(const CPubKey& pubkey, const CKeyingMaterial& masterSeed);

    static void IncrementUpdateCounter();
    static unsigned int GetUpdateCounter();

private:
    CWalletDB(const CWalletDB&);
    void operator=(const CWalletDB&);
};

bool BackupWallet(const CWallet& wallet, const std::string& strDest);
void ThreadFlushWalletDB(const std::string& strFile);

#endif // VDS_WALLET_WALLETDB_H
