// Copyright (c) 2014-2019 The vds Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SRC_BIP38_KEY_H_
#define SRC_BIP38_KEY_H_

#include <cstdio>
#include <string>
#include "key.h"

// BIP38 is a method for encrypting private keys with a passphrase
// https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

bool IsValidBIP38Key(const char* bip38Key);

// decrypts a BIP38 key using the given passphrase and returns false if passphrase is incorrect
// key32 should be size of 32
// strPrivKey is base58 encoded private key
// passphrase must be unicode NFC normalized: http://www.unicode.org/reports/tr15/#Norm_Forms
bool DecryptBIP38Key(unsigned char* key32, std::string& strPrivKey, const char* bip38Key, const char* passphrase);

// encrypts key with passphrase
// passphrase must be unicode NFC normalized
// returns encrypted bip38 key
std::string EncryptBIP38Key(const CKey& key, const char* passphrase);

#endif /* SRC_BIP38_KEY_H_ */
