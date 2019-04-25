// Copyright (c) 2014-2019 The vds Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bip39_mnemonic.h"
#include <assert.h>
#include <cstring>
#include <iostream>
#include "crypto/sha256.h"
#include "crypto/common.h"
#include "crypto/pbkdf2.h"
#include "support/cleanse.h"

bool InputMnemonicCode(std::string& phrase)
{
    while (true) {
        int x = 0;
        phrase.clear();
        for (int i = 0; i < 12; ++i) {
            std::string word;
            std::cin >> word;
            if (i > 0) {
                phrase.append(" ");
            }
            phrase.append(word);
        }
        if (BIP39PhraseIsValid(phrase.c_str(), s_bip39Words)) {
            break;
        } else {
            std::cout << "Invalid mnemonic code, please input again" << std::endl;
            x++;
            return false;
        }
    }
    return true;
}

bool CheckMnemonicCodeMatch(const std::string& prePhrase)
{
    while (true) {
        std::string phrase;
        std::cout << "Please input the mnemonic code just shown:" << std::endl;
        if (!InputMnemonicCode(phrase))
            return false;
        if (phrase == prePhrase) {
            std::cout << "Congratulations! Your input passed" << std::endl;
            break;
        } else {
            std::cout << "Error: your input mismatch the mnemonic code" << std::endl;
            return false;
        }
    }
    return true;
}

size_t BIP39Encode(char* phrase, size_t phraseLen, const unsigned char* data, size_t dataLen, const char* wordList[])
{
    uint32_t x;
    uint8_t* buf = new uint8_t[dataLen + 32];
    const char* word;
    size_t i, len = 0;

    assert(wordList != NULL);
    assert(data != NULL || dataLen == 0);
    assert(dataLen > 0 && (dataLen % 4) == 0);
    if (!data || (dataLen % 4) != 0) return 0; // data length must be a multiple of 32 bits

    memcpy(buf, data, dataLen);

    // append SHA256 checksum
    CSHA256 hasher;
    hasher.Write(data, dataLen);
    hasher.Finalize(&buf[dataLen]);

    for (i = 0; i < dataLen * 3 / 4; i++) {
        x = ReadBE32(&buf[i * 11 / 8]);
        word = wordList[(x >> (32 - (11 + ((i * 11) % 8)))) % s_bip39WordListCount];
        if (i > 0 && phrase && len < phraseLen) phrase[len] = ' ';
        if (i > 0) len++;
        if (phrase && len < phraseLen) strncpy(&phrase[len], word, phraseLen - len);
        len += strlen(word);
    }

    var_clean(&word);
    var_clean(&x);
    memory_cleanse(buf, dataLen + 32);
    delete[] buf;
    return (!phrase || len + 1 <= phraseLen) ? len + 1 : 0;
}

// returns number of bytes written to data, or dataLen needed if data is NULL

size_t BIP39Decode(unsigned char* data, size_t dataLen, const char* phrase, const char* wordList[])
{
    uint32_t x, y, count = 0, idx[24], i;
    uint8_t b = 0, hash[32];
    const char* word = phrase;
    size_t r = 0;

    assert(wordList != NULL);
    assert(phrase != NULL);

    while (word && *word && count < 24) {
        for (i = 0, idx[count] = INT32_MAX; i < s_bip39WordListCount; i++) { // not fast, but simple and correct
            if (strncmp(word, wordList[i], strlen(wordList[i])) != 0 ||
                    (word[strlen(wordList[i])] != ' ' && word[strlen(wordList[i])] != '\0')) continue;
            idx[count] = i;
            break;
        }

        if (idx[count] == INT32_MAX) break; // phrase contains unknown word
        count++;
        word = strchr(word, ' ');
        if (word) word++;
    }

    if ((count % 3) == 0 && (!word || *word == '\0')) { // check that phrase has correct number of words
        uint8_t* buf = new uint8_t[(count * 11 + 7) / 8];

        for (i = 0; i < (count * 11 + 7) / 8; i++) {
            x = idx[i * 8 / 11];
            y = (i * 8 / 11 + 1 < count) ? idx[i * 8 / 11 + 1] : 0;
            b = ((x * s_bip39WordListCount + y) >> ((i * 8 / 11 + 2) * 11 - (i + 1) * 8)) & 0xff;
            buf[i] = b;
        }

        CSHA256 hasher;
        hasher.Write(buf, count * 4 / 3);
        hasher.Finalize(hash);

        if (b >> (8 - count / 3) == (hash[0] >> (8 - count / 3))) { // verify checksum
            r = count * 4 / 3;
            if (data && r <= dataLen) memcpy(data, buf, r);
        }

        memory_cleanse(buf, sizeof (buf));
        delete[] buf;
    }

    var_clean(&b);
    var_clean(&x, &y);
    memory_cleanse(idx, sizeof (idx));
    return (!data || r <= dataLen) ? r : 0;
}

// verifies that all phrase words are contained in wordlist and checksum is valid

int BIP39PhraseIsValid(const char* phrase, const char* wordList[])
{
    assert(wordList != NULL);
    assert(phrase != NULL);
    return (BIP39Decode(NULL, 0, phrase, wordList) > 0);
}

bool BIP39PhrasePosValid(const char* phrase, const char* wordList[], const int nNumFix, vector<uint32_t>& posInvalid)
{
    assert(wordList != NULL);
    assert(phrase != NULL);

    uint32_t count = 0, idx[24], i;
    const char* word = phrase;
    while (word && *word && count < 24) {
        for (i = 0, idx[count] = INT32_MAX; i < s_bip39WordListCount; i++) { // not fast, but simple and correct
            if (strncmp(word, wordList[i], strlen(wordList[i])) != 0 ||
                    (word[strlen(wordList[i])] != ' ' && word[strlen(wordList[i])] != '\0')) continue;
            idx[count] = i;
            break;
        }
        // phrase contains unknown word,record its position
        if (idx[count] == INT32_MAX) {
            posInvalid.push_back(count);
        }
        count++;
        word = strchr(word, ' ');
        if (word) {
            word++;
        }
    }

    if (count != nNumFix)
        return false;

    if (posInvalid.size() > 0)
        return false;

    return true;
}

// key64 must hold 64 bytes (512 bits), phrase and passphrase must be unicode NFKD normalized
// http://www.unicode.org/reports/tr15/#Norm_Forms
// BUG: does not currently support passphrases containing NULL characters

void BIP39DeriveKey(unsigned char* key64, const char* phrase, const char* passphrase)
{
    assert(key64 != NULL);
    assert(phrase != NULL);

    int saltlen = strlen("mnemonic") + (passphrase ? strlen(passphrase) : 0) + 1;
    char* salt = new char[saltlen];
    strcpy(salt, "mnemonic");
    if (passphrase) {
        strcpy(salt + strlen("mnemonic"), passphrase);
    }

    PBKDF2<CHMAC_SHA512>(key64, 64, (const unsigned char*) phrase, strlen(phrase), (unsigned char*) salt, strlen(salt), 2048);
    memory_cleanse(salt, saltlen);
    delete[] salt;
}
