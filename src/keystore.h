// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VDS_KEYSTORE_H
#define VDS_KEYSTORE_H

#include "key.h"
#include "pubkey.h"
#include "script/script.h"
#include <script/standard.h>
#include "sync.h"
#include "vds/Address.hpp"
#include "vds/NoteEncryption.hpp"
#include "vds/zip32.h"

#include <boost/signals2/signal.hpp>
#include <boost/variant.hpp>

/** A virtual base class for key stores */
class CKeyStore
{
protected:
    mutable CCriticalSection cs_KeyStore;
    mutable CCriticalSection cs_SpendingKeyStore;

public:
    virtual ~CKeyStore() {}

    //! Set the HD seed for this keystore
    virtual bool SetHDSeed(const HDSeed& seed) = 0;
    virtual bool HaveHDSeed() const = 0;
    //! Get the HD seed for this keystore
    virtual bool GetHDSeed(HDSeed& seedOut) const = 0;

    //! Add a key to the store.
    virtual bool AddKeyPubKey(const CKey& key, const CPubKey& pubkey) = 0;
    virtual bool AddKey(const CKey& key);

    //! Check whether a key corresponding to a given address is present in the store.
    virtual bool HaveKey(const CKeyID& address) const = 0;
    virtual bool GetKey(const CKeyID& address, CKey& keyOut) const = 0;
    virtual void GetKeys(std::set<CKeyID>& setAddress) const = 0;
    virtual bool GetPubKey(const CKeyID& address, CPubKey& vchPubKeyOut) const;

    //! Support for BIP 0013 : see https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
    virtual bool AddCScript(const CScript& redeemScript) = 0;
    virtual bool HaveCScript(const CScriptID& hash) const = 0;
    virtual bool GetCScript(const CScriptID& hash, CScript& redeemScriptOut) const = 0;

    //! Support for Watch-only addresses
    virtual bool AddWatchOnly(const CScript& dest) = 0;
    virtual bool RemoveWatchOnly(const CScript& dest) = 0;
    virtual bool HaveWatchOnly(const CScript& dest) const = 0;
    virtual bool HaveWatchOnly() const = 0;

    //! Add a Sapling spending key to the store.
    virtual bool AddSaplingSpendingKey(
        const libzcash::SaplingExtendedSpendingKey& sk,
        const libzcash::SaplingPaymentAddress& defaultAddr) = 0;

    //! Check whether a Sapling spending key corresponding to a given Sapling viewing key is present in the store.
    virtual bool HaveSaplingSpendingKey(const libzcash::SaplingFullViewingKey& fvk) const = 0;
    virtual bool GetSaplingSpendingKey(const libzcash::SaplingFullViewingKey& fvk, libzcash::SaplingExtendedSpendingKey& skOut) const = 0;

    //! Support for Sapling full viewing keys
    virtual bool AddSaplingFullViewingKey(
        const libzcash::SaplingFullViewingKey& fvk,
        const libzcash::SaplingPaymentAddress& defaultAddr) = 0;
    virtual bool HaveSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey& ivk) const = 0;
    virtual bool GetSaplingFullViewingKey(
        const libzcash::SaplingIncomingViewingKey& ivk,
        libzcash::SaplingFullViewingKey& fvkOut) const = 0;

    //! Sapling incoming viewing keys
    virtual bool AddSaplingIncomingViewingKey(
        const libzcash::SaplingIncomingViewingKey& ivk,
        const libzcash::SaplingPaymentAddress& addr) = 0;
    virtual bool HaveSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress& addr) const = 0;
    virtual bool GetSaplingIncomingViewingKey(
        const libzcash::SaplingPaymentAddress& addr,
        libzcash::SaplingIncomingViewingKey& ivkOut) const = 0;
    virtual void GetSaplingPaymentAddresses(std::set<libzcash::SaplingPaymentAddress>& setAddress) const = 0;

};

typedef std::map<CKeyID, CKey> KeyMap;
typedef std::map<CScriptID, CScript > ScriptMap;
typedef std::set<CScript> WatchOnlySet;

// Full viewing key has equivalent functionality to a transparent address
typedef std::map<libzcash::SaplingFullViewingKey, libzcash::SaplingExtendedSpendingKey> SaplingSpendingKeyMap;
typedef std::map<libzcash::SaplingIncomingViewingKey, libzcash::SaplingFullViewingKey> SaplingFullViewingKeyMap;
typedef std::map<libzcash::SaplingPaymentAddress, libzcash::SaplingIncomingViewingKey> SaplingIncomingViewingKeyMap;

/** Basic key store, that keeps keys in an address->secret map */
class CBasicKeyStore : public CKeyStore
{
protected:
    HDSeed hdSeed;
    KeyMap mapKeys;
    ScriptMap mapScripts;
    WatchOnlySet setWatchOnly;
    WatchOnlySet setBTCWatchOnly;

    SaplingSpendingKeyMap mapSaplingSpendingKeys;
    SaplingFullViewingKeyMap mapSaplingFullViewingKeys;
    SaplingIncomingViewingKeyMap mapSaplingIncomingViewingKeys;

public:
    bool SetHDSeed(const HDSeed& seed);
    bool HaveHDSeed() const;
    bool GetHDSeed(HDSeed& seedOut) const;

    bool AddKeyPubKey(const CKey& key, const CPubKey& pubkey);
    bool HaveKey(const CKeyID& address) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapKeys.count(address) > 0);
        }
        return result;
    }
    void GetKeys(std::set<CKeyID>& setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.begin();
            while (mi != mapKeys.end()) {
                setAddress.insert((*mi).first);
                mi++;
            }
        }
    }
    bool GetKey(const CKeyID& address, CKey& keyOut) const
    {
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.find(address);
            if (mi != mapKeys.end()) {
                keyOut = mi->second;
                return true;
            }
        }
        return false;
    }
    virtual bool AddCScript(const CScript& redeemScript);
    virtual bool HaveCScript(const CScriptID& hash) const;
    virtual bool GetCScript(const CScriptID& hash, CScript& redeemScriptOut) const;

    virtual bool AddWatchOnly(const CScript& dest);
    virtual bool RemoveWatchOnly(const CScript& dest);
    virtual bool HaveWatchOnly(const CScript& dest) const;
    virtual bool HaveWatchOnly() const;

    bool AddBTCWatchOnly(const CScript& dest);
    bool RemoveBTCWatchOnly(const CScript& dest);
    bool HaveBTCWatchOnly(const CScript& dest) const;
    bool HaveBTCWatchOnly() const;

    //! Sapling
    bool AddSaplingSpendingKey(
        const libzcash::SaplingExtendedSpendingKey& sk,
        const libzcash::SaplingPaymentAddress& defaultAddr);
    bool HaveSaplingSpendingKey(const libzcash::SaplingFullViewingKey& fvk) const
    {
        bool result;
        {
            LOCK(cs_SpendingKeyStore);
            result = (mapSaplingSpendingKeys.count(fvk) > 0);
        }
        return result;
    }
    bool GetSaplingSpendingKey(const libzcash::SaplingFullViewingKey& fvk, libzcash::SaplingExtendedSpendingKey& skOut) const
    {
        {
            LOCK(cs_SpendingKeyStore);

            SaplingSpendingKeyMap::const_iterator mi = mapSaplingSpendingKeys.find(fvk);
            if (mi != mapSaplingSpendingKeys.end()) {
                skOut = mi->second;
                return true;
            }
        }
        return false;
    }

    virtual bool AddSaplingFullViewingKey(
        const libzcash::SaplingFullViewingKey& fvk,
        const libzcash::SaplingPaymentAddress& defaultAddr);
    virtual bool HaveSaplingFullViewingKey(const libzcash::SaplingIncomingViewingKey& ivk) const;
    virtual bool GetSaplingFullViewingKey(
        const libzcash::SaplingIncomingViewingKey& ivk,
        libzcash::SaplingFullViewingKey& fvkOut) const;

    virtual bool AddSaplingIncomingViewingKey(
        const libzcash::SaplingIncomingViewingKey& ivk,
        const libzcash::SaplingPaymentAddress& addr);
    virtual bool HaveSaplingIncomingViewingKey(const libzcash::SaplingPaymentAddress& addr) const;
    virtual bool GetSaplingIncomingViewingKey(
        const libzcash::SaplingPaymentAddress& addr,
        libzcash::SaplingIncomingViewingKey& ivkOut) const;

    bool GetSaplingExtendedSpendingKey(
        const libzcash::SaplingPaymentAddress& addr,
        libzcash::SaplingExtendedSpendingKey& extskOut) const;

    void GetSaplingPaymentAddresses(std::set<libzcash::SaplingPaymentAddress>& setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_SpendingKeyStore);
            auto mi = mapSaplingIncomingViewingKeys.begin();
            while (mi != mapSaplingIncomingViewingKeys.end()) {
                setAddress.insert((*mi).first);
                mi++;
            }
        }
    }

};

typedef std::vector<unsigned char, secure_allocator<unsigned char> > CKeyingMaterial;
typedef std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char> > > CryptedKeyMap;

//! Sapling
typedef std::map<libzcash::SaplingExtendedFullViewingKey, std::vector<unsigned char> > CryptedSaplingSpendingKeyMap;
#endif // VDS_KEYSTORE_H
