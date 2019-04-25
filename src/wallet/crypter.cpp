// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypter.h"

#include "script/script.h"
#include "script/standard.h"
#include "streams.h"
#include "util.h"

#include "utilstrencodings.h"

#include <string>
#include <vector>
#include <boost/foreach.hpp>
#include <openssl/aes.h>
#include <openssl/evp.h>

bool CCrypter::SetKeyFromPassphrase(const SecureString& strKeyData, const std::vector<unsigned char>& chSalt, const unsigned int nRounds, const unsigned int nDerivationMethod)
{
    if (nRounds < 1 || chSalt.size() != WALLET_CRYPTO_SALT_SIZE)
        return false;

    int i = 0;
    if (nDerivationMethod == 0)
        i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), &chSalt[0],
                           (unsigned char*)&strKeyData[0], strKeyData.size(), nRounds, chKey, chIV);

    if (i != (int)WALLET_CRYPTO_KEY_SIZE) {
        memory_cleanse(chKey, sizeof(chKey));
        memory_cleanse(chIV, sizeof(chIV));
        return false;
    }

    fKeySet = true;
    return true;
}

bool CCrypter::SetKey(const CKeyingMaterial& chNewKey, const std::vector<unsigned char>& chNewIV)
{
    if (chNewKey.size() != WALLET_CRYPTO_KEY_SIZE || chNewIV.size() != WALLET_CRYPTO_KEY_SIZE)
        return false;

    memcpy(&chKey[0], &chNewKey[0], sizeof chKey);
    memcpy(&chIV[0], &chNewIV[0], sizeof chIV);

    fKeySet = true;
    return true;
}

bool CCrypter::Encrypt(const CKeyingMaterial& vchPlaintext, std::vector<unsigned char>& vchCiphertext)
{
    if (!fKeySet)
        return false;

    // max ciphertext len for a n bytes of plaintext is
    // n + AES_BLOCK_SIZE - 1 bytes
    int nLen = vchPlaintext.size();
    int nCLen = nLen + AES_BLOCK_SIZE, nFLen = 0;
    vchCiphertext = std::vector<unsigned char> (nCLen);

    bool fOk = true;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    assert(ctx);
    if (fOk) fOk = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, chKey, chIV) != 0;
    if (fOk) fOk = EVP_EncryptUpdate(ctx, &vchCiphertext[0], &nCLen, &vchPlaintext[0], nLen) != 0;
    if (fOk) fOk = EVP_EncryptFinal_ex(ctx, (&vchCiphertext[0]) + nCLen, &nFLen) != 0;
    EVP_CIPHER_CTX_free(ctx);

    if (!fOk) return false;

    vchCiphertext.resize(nCLen + nFLen);
    return true;
}

bool CCrypter::Decrypt(const std::vector<unsigned char>& vchCiphertext, CKeyingMaterial& vchPlaintext)
{
    if (!fKeySet)
        return false;

    // plaintext will always be equal to or lesser than length of ciphertext
    int nLen = vchCiphertext.size();
    int nPLen = nLen, nFLen = 0;

    vchPlaintext = CKeyingMaterial(nPLen);

    bool fOk = true;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    assert(ctx);
    if (fOk) fOk = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, chKey, chIV) != 0;
    if (fOk) fOk = EVP_DecryptUpdate(ctx, &vchPlaintext[0], &nPLen, &vchCiphertext[0], nLen) != 0;
    if (fOk) fOk = EVP_DecryptFinal_ex(ctx, (&vchPlaintext[0]) + nPLen, &nFLen) != 0;
    EVP_CIPHER_CTX_free(ctx);

    if (!fOk) return false;

    vchPlaintext.resize(nPLen + nFLen);
    return true;
}


static bool EncryptSecret(const CKeyingMaterial& vMasterKey, const CKeyingMaterial& vchPlaintext, const uint256& nIV, std::vector<unsigned char>& vchCiphertext)
{
    CCrypter cKeyCrypter;
    std::vector<unsigned char> chIV(WALLET_CRYPTO_KEY_SIZE);
    memcpy(&chIV[0], &nIV, WALLET_CRYPTO_KEY_SIZE);
    if (!cKeyCrypter.SetKey(vMasterKey, chIV))
        return false;
    return cKeyCrypter.Encrypt(*((const CKeyingMaterial*)&vchPlaintext), vchCiphertext);
}

static bool DecryptSecret(const CKeyingMaterial& vMasterKey, const std::vector<unsigned char>& vchCiphertext, const uint256& nIV, CKeyingMaterial& vchPlaintext)
{
    CCrypter cKeyCrypter;
    std::vector<unsigned char> chIV(WALLET_CRYPTO_KEY_SIZE);
    memcpy(&chIV[0], &nIV, WALLET_CRYPTO_KEY_SIZE);
    if (!cKeyCrypter.SetKey(vMasterKey, chIV))
        return false;
    return cKeyCrypter.Decrypt(vchCiphertext, *((CKeyingMaterial*)&vchPlaintext));
}

static bool DecryptHDSeed(
    const CKeyingMaterial& vMasterKey,
    const std::vector<unsigned char>& vchCryptedSecret,
    const uint256& seedFp,
    HDSeed& seed)
{
    CKeyingMaterial vchSecret;

    // Use seed's fingerprint as IV
    // TODO: Handle IV properly when we make encryption a supported feature
    if (!DecryptSecret(vMasterKey, vchCryptedSecret, seedFp, vchSecret))
        return false;

    seed = HDSeed(vchSecret);
    return seed.Fingerprint() == seedFp;
}

static bool DecryptKey(const CKeyingMaterial& vMasterKey, const std::vector<unsigned char>& vchCryptedSecret, const CPubKey& vchPubKey, CKey& key)
{
    CKeyingMaterial vchSecret;
    if (!DecryptSecret(vMasterKey, vchCryptedSecret, vchPubKey.GetHash(), vchSecret))
        return false;

    if (vchSecret.size() != 32)
        return false;

    key.Set(vchSecret.begin(), vchSecret.end(), vchPubKey.IsCompressed());
    return key.VerifyPubKey(vchPubKey);
}

static bool DecryptSaplingSpendingKey(const CKeyingMaterial& vMasterKey,
                                      const std::vector<unsigned char>& vchCryptedSecret,
                                      const libzcash::SaplingExtendedFullViewingKey& extfvk,
                                      libzcash::SaplingExtendedSpendingKey& sk)
{
    CKeyingMaterial vchSecret;
    if (!DecryptSecret(vMasterKey, vchCryptedSecret, extfvk.fvk.GetFingerprint(), vchSecret))
        return false;

    if (vchSecret.size() != ZIP32_XSK_SIZE)
        return false;

    std::vector<unsigned char> serialized(vchSecret.begin(), vchSecret.end());
    CDataStream ss(serialized, SER_NETWORK, PROTOCOL_VERSION);
    ss >> sk;
    return sk.expsk.full_viewing_key() == extfvk.fvk;
}

bool CCryptoKeyStore::SetCrypted()
{
    LOCK2(cs_KeyStore, cs_SpendingKeyStore);
    if (fUseCrypto)
        return true;
    if (!(mapKeys.empty() && mapSaplingSpendingKeys.empty()))
        return false;
    fUseCrypto = true;

    return true;
}

bool CCryptoKeyStore::Lock()
{
    if (!SetCrypted())
        return false;

    {
        LOCK(cs_KeyStore);
        vMasterKey.clear();
    }

    NotifyStatusChanged(this);
    return true;
}

bool CCryptoKeyStore::Unlock(const CKeyingMaterial& vMasterKeyIn)
{
    {
        LOCK2(cs_KeyStore, cs_SpendingKeyStore);
        if (!SetCrypted())
            return false;

        bool keyPass = false;
        bool keyFail = false;
        if (!cryptedHDSeed.first.IsNull()) {
            HDSeed seed;
            if (!DecryptHDSeed(vMasterKeyIn, cryptedHDSeed.second, cryptedHDSeed.first, seed)) {
                keyFail = true;
            } else {
                keyPass = true;
            }
        }
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        for (; mi != mapCryptedKeys.end(); ++mi) {
            const CPubKey& vchPubKey = (*mi).second.first;
            const std::vector<unsigned char>& vchCryptedSecret = (*mi).second.second;
            CKey key;
            if (!DecryptKey(vMasterKeyIn, vchCryptedSecret, vchPubKey, key)) {
                keyFail = true;
                break;
            }
            keyPass = true;
            if (fDecryptionThoroughlyChecked)
                break;
        }
        CryptedSaplingSpendingKeyMap::const_iterator miSapling = mapCryptedSaplingSpendingKeys.begin();
        for (; miSapling != mapCryptedSaplingSpendingKeys.end(); ++miSapling) {
            const libzcash::SaplingExtendedFullViewingKey& extfvk = (*miSapling).first;
            const std::vector<unsigned char>& vchCryptedSecret = (*miSapling).second;
            libzcash::SaplingExtendedSpendingKey sk;
            if (!DecryptSaplingSpendingKey(vMasterKeyIn, vchCryptedSecret, extfvk, sk)) {
                keyFail = true;
                break;
            }
            keyPass = true;
            if (fDecryptionThoroughlyChecked)
                break;
        }
        if (keyPass && keyFail) {
            LogPrintf("The wallet is probably corrupted: Some keys decrypt but not all.\n");
            assert(false);
        }
        if (keyFail || !keyPass)
            return false;
        vMasterKey = vMasterKeyIn;
        fDecryptionThoroughlyChecked = true;
    }
    NotifyStatusChanged(this);
    return true;
}

bool CCryptoKeyStore::AddKeyPubKey(const CKey& key, const CPubKey& pubkey)
{
    {
        LOCK(cs_KeyStore);
        if (!IsCrypted())
            return CBasicKeyStore::AddKeyPubKey(key, pubkey);

        if (IsLocked())
            return false;

        std::vector<unsigned char> vchCryptedSecret;
        CKeyingMaterial vchSecret(key.begin(), key.end());
        if (!EncryptSecret(vMasterKey, vchSecret, pubkey.GetHash(), vchCryptedSecret))
            return false;

        if (!AddCryptedKey(pubkey, vchCryptedSecret))
            return false;
    }
    return true;
}


bool CCryptoKeyStore::AddCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret)
{
    {
        LOCK2(cs_KeyStore, cs_SpendingKeyStore);
        if (!SetCrypted())
            return false;

        mapCryptedKeys[vchPubKey.GetID()] = make_pair(vchPubKey, vchCryptedSecret);
    }
    return true;
}

bool CCryptoKeyStore::GetKey(const CKeyID& address, CKey& keyOut) const
{
    {
        LOCK(cs_KeyStore);
        if (!IsCrypted())
            return CBasicKeyStore::GetKey(address, keyOut);

        CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
        if (mi != mapCryptedKeys.end()) {
            const CPubKey& vchPubKey = (*mi).second.first;
            const std::vector<unsigned char>& vchCryptedSecret = (*mi).second.second;
            return DecryptKey(vMasterKey, vchCryptedSecret, vchPubKey, keyOut);
        }
    }
    return false;
}

bool CCryptoKeyStore::GetPubKey(const CKeyID& address, CPubKey& vchPubKeyOut) const
{
    {
        LOCK(cs_KeyStore);
        if (!IsCrypted())
            return CKeyStore::GetPubKey(address, vchPubKeyOut);

        CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
        if (mi != mapCryptedKeys.end()) {
            vchPubKeyOut = (*mi).second.first;
            return true;
        }
    }
    return false;
}

bool CCryptoKeyStore::AddSaplingSpendingKey(
    const libzcash::SaplingExtendedSpendingKey& sk,
    const libzcash::SaplingPaymentAddress& defaultAddr)
{
    {
        LOCK2(cs_KeyStore, cs_SpendingKeyStore);

        if (!IsCrypted()) {
            return CBasicKeyStore::AddSaplingSpendingKey(sk, defaultAddr);
        }

        if (IsLocked()) {
            return false;
        }

        std::vector<unsigned char> vchCryptedSecret;

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << sk;
        CKeyingMaterial vchSecret(ss.begin(), ss.end());
        auto extfvk = sk.ToXFVK();
        if (!EncryptSecret(vMasterKey, vchSecret, extfvk.fvk.GetFingerprint(), vchCryptedSecret)) {
            return false;
        }

        if (!AddCryptedSaplingSpendingKey(extfvk, vchCryptedSecret, defaultAddr)) {
            return false;
        }
    }
    return true;
}

bool CCryptoKeyStore::AddCryptedSaplingSpendingKey(
    const libzcash::SaplingExtendedFullViewingKey& extfvk,
    const std::vector<unsigned char>& vchCryptedSecret,
    const libzcash::SaplingPaymentAddress& defaultAddr)
{
    {
        LOCK2(cs_KeyStore, cs_SpendingKeyStore);
        if (!SetCrypted()) {
            return false;
        }

        // if SaplingFullViewingKey is not in SaplingFullViewingKeyMap, add it
        if (!AddSaplingFullViewingKey(extfvk.fvk, defaultAddr)) {
            return false;
        }

        mapCryptedSaplingSpendingKeys[extfvk] = vchCryptedSecret;
    }
    return true;
}

bool CCryptoKeyStore::GetSaplingSpendingKey(const libzcash::SaplingFullViewingKey& fvk, libzcash::SaplingExtendedSpendingKey& skOut) const
{
    {
        LOCK(cs_SpendingKeyStore);
        if (!IsCrypted())
            return CBasicKeyStore::GetSaplingSpendingKey(fvk, skOut);

        for (auto entry : mapCryptedSaplingSpendingKeys) {
            if (entry.first.fvk == fvk) {
                const std::vector<unsigned char>& vchCryptedSecret = entry.second;
                return DecryptSaplingSpendingKey(vMasterKey, vchCryptedSecret, entry.first, skOut);
            }
        }
    }
    return false;
}

bool CCryptoKeyStore::EncryptKeys(CKeyingMaterial& vMasterKeyIn)
{
    {
        LOCK2(cs_KeyStore, cs_SpendingKeyStore);
        if (!mapCryptedKeys.empty() || IsCrypted())
            return false;

        fUseCrypto = true;
        if (!hdSeed.IsNull()) {
            {
                std::vector<unsigned char> vchCryptedSecret;
                // Use seed's fingerprint as IV
                // TODO: Handle this properly when we make encryption a supported feature
                auto seedFp = hdSeed.Fingerprint();
                if (!EncryptSecret(vMasterKeyIn, hdSeed.RawSeed(), seedFp, vchCryptedSecret)) {
                    return false;
                }
            }
            hdSeed = HDSeed();
        }
        BOOST_FOREACH(KeyMap::value_type & mKey, mapKeys) {
            const CKey& key = mKey.second;
            CPubKey vchPubKey = key.GetPubKey();
            CKeyingMaterial vchSecret(key.begin(), key.end());
            std::vector<unsigned char> vchCryptedSecret;
            if (!EncryptSecret(vMasterKeyIn, vchSecret, vchPubKey.GetHash(), vchCryptedSecret)) {
                return false;
            }
            if (!AddCryptedKey(vchPubKey, vchCryptedSecret)) {
                return false;
            }
        }
        mapKeys.clear();
        //! Sapling key support
        BOOST_FOREACH(SaplingSpendingKeyMap::value_type & mSaplingSpendingKey, mapSaplingSpendingKeys) {
            const auto& sk = mSaplingSpendingKey.second;
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << sk;
            CKeyingMaterial vchSecret(ss.begin(), ss.end());
            auto extfvk = sk.ToXFVK();
            std::vector<unsigned char> vchCryptedSecret;
            if (!EncryptSecret(vMasterKeyIn, vchSecret, extfvk.fvk.GetFingerprint(), vchCryptedSecret)) {
                return false;
            }
            if (!AddCryptedSaplingSpendingKey(extfvk, vchCryptedSecret, sk.DefaultAddress())) {
                return false;
            }
        }
        mapSaplingSpendingKeys.clear();
    }
    return true;
}

bool CCryptoKeyStore::EncryptSeed(const CKeyingMaterial& seedIn, const uint256& seedPubHash, std::vector<unsigned char>& vchCiphertext) const
{
    LOCK(cs_KeyStore);
    if (!EncryptSecret(vMasterKey, seedIn, seedPubHash, vchCiphertext))
        return false;

    return true;
}

bool CCryptoKeyStore::DecryptSeed(const std::vector<unsigned char>& vchCiphertextIn, const uint256& seedPubHash, CKeyingMaterial& seedOut) const
{
    LOCK(cs_KeyStore);
    if (!DecryptSecret(vMasterKey, vchCiphertextIn, seedPubHash, seedOut))
        return false;

    return true;
}
