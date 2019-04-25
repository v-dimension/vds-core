// Copyright (c) 2014-2019 The vds Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef SRC_WALLET_BIP39_MNEMONIC_H_
#define SRC_WALLET_BIP39_MNEMONIC_H_

#include <stddef.h>
#include <inttypes.h>
#include <string>
#include <vector>
#include "bip39_words_english.h"
using namespace std;

// BIP39 is method for generating a deterministic wallet seed from a mnemonic phrase
// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

// Input mnemonic code by user
bool InputMnemonicCode(std::string& phrase);
// Asking user to input mnemonic code and check if match the previous one
bool CheckMnemonicCodeMatch(const std::string& prePhrase);

// returns number of bytes written to phrase including NULL terminator, or phraseLen needed if phrase is NULL
size_t BIP39Encode(char* phrase, size_t phraseLen, const unsigned char* data, size_t dataLen, const char* wordList[]);

// returns number of bytes written to data, or dataLen needed if data is NULL
size_t BIP39Decode(unsigned char* data, size_t dataLen, const char* phrase, const char* wordList[]);

// verifies that all phrase words are contained in wordlist and checksum is valid
int BIP39PhraseIsValid(const char* phrase, const char* wordList[]);

bool BIP39PhrasePosValid(const char* phrase, const char* wordList[], const int nNumFix, vector<uint32_t>& posInvalid);

// key64 must hold 64 bytes (512 bits), phrase and passphrase must be unicode NFKD normalized
// http://www.unicode.org/reports/tr15/#Norm_Forms
// BUG: does not currently support passphrases containing NULL characters
void BIP39DeriveKey(unsigned char* key64, const char* phrase, const char* passphrase);

#endif /* SRC_WALLET_BIP39_MNEMONIC_H_ */
