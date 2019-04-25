// Copyright (c) 2014-2019 The vds Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bip38_key.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include "crypto/sha256.h"
#include "crypto/scrypt.h"
#include "crypto/common.h"
#include "support/cleanse.h"
#include "uint256.h"
#include "base58.h"
#include "key.h"
#include <key_io.h>

#define BIP38_NOEC_PREFIX      0x0142
#define BIP38_EC_PREFIX        0x0143
#define BIP38_NOEC_FLAG        (0x80 | 0x40)
#define BIP38_COMPRESSED_FLAG  0x20
#define BIP38_LOTSEQUENCE_FLAG 0x04
#define BIP38_INVALID_FLAG     (0x10 | 0x08 | 0x02 | 0x01)
#define BIP38_SCRYPT_N         16384
#define BIP38_SCRYPT_R         8
#define BIP38_SCRYPT_P         8
#define BIP38_SCRYPT_EC_N      1024
#define BIP38_SCRYPT_EC_R      1
#define BIP38_SCRYPT_EC_P      1

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t sboxi[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

#define xt(x) (((x) << 1) ^ ((((x) >> 7) & 1)*0x1b))

static void _AES256ECBEncrypt(const void* key32, void* buf16)
{
    size_t i, j;
    uint32_t key[32 / 4], buf[16 / 4];
    uint8_t* x = (uint8_t*) buf, *k = (uint8_t*) key, r = 1, a, b, c, d, e;

    memcpy(key, key32, sizeof (key));
    memcpy(buf, buf16, sizeof (buf));

    for (i = 0; i < 14; i++) {
        for (j = 0; j < 4; j++) buf[j] ^= key[j + (i & 1) * 4]; // add round key

        for (j = 0; j < 16; j++) x[j] = sbox[x[j]]; // sub bytes

        // shift rows
        a = x[1], x[1] = x[5], x[5] = x[9], x[9] = x[13], x[13] = a, a = x[10], x[10] = x[2], x[2] = a;
        a = x[3], x[3] = x[15], x[15] = x[11], x[11] = x[7], x[7] = a, a = x[14], x[14] = x[6], x[6] = a;

        for (j = 0; i < 13 && j < 16; j += 4) { // mix columns
            a = x[j], b = x[j + 1], c = x[j + 2], d = x[j + 3], e = a ^ b ^ c ^ d;
            x[j] ^= e ^ xt(a ^ b), x[j + 1] ^= e ^ xt(b ^ c), x[j + 2] ^= e ^ xt(c ^ d), x[j + 3] ^= e ^ xt(d ^ a);
        }

        if ((i % 2) != 0) { // expand key
            k[0] ^= sbox[k[29]] ^ r, k[1] ^= sbox[k[30]], k[2] ^= sbox[k[31]], k[3] ^= sbox[k[28]], r = xt(r);
            for (j = 4; j < 16; j += 4) k[j] ^= k[j - 4], k[j + 1] ^= k[j - 3], k[j + 2] ^= k[j - 2], k[j + 3] ^= k[j - 1];
            k[16] ^= sbox[k[12]], k[17] ^= sbox[k[13]], k[18] ^= sbox[k[14]], k[19] ^= sbox[k[15]];
            for (j = 20; j < 32; j += 4) k[j] ^= k[j - 4], k[j + 1] ^= k[j - 3], k[j + 2] ^= k[j - 2], k[j + 3] ^= k[j - 1];
        }
    }

    var_clean(&r, &a, &b, &c, &d, &e);
    for (i = 0; i < 4; i++) buf[i] ^= key[i]; // final add round key
    memory_cleanse(key, sizeof (key));
    memcpy(buf16, buf, sizeof (buf));
    memory_cleanse(buf, sizeof (buf));
}

static void _AES256ECBDecrypt(const void* key32, void* buf16)
{
    size_t i, j;
    uint32_t key[32 / 4], buf[16 / 4];
    uint8_t* x = (uint8_t*) buf, *k = (uint8_t*) key, r = 1, a, b, c, d, e, f, g, h;

    memcpy(key, key32, sizeof (key));
    memcpy(buf, buf16, sizeof (buf));

    for (i = 0; i < 7; i++) { // expand key
        k[0] ^= sbox[k[29]] ^ r, k[1] ^= sbox[k[30]], k[2] ^= sbox[k[31]], k[3] ^= sbox[k[28]], r = xt(r);
        for (j = 4; j < 16; j += 4) k[j] ^= k[j - 4], k[j + 1] ^= k[j - 3], k[j + 2] ^= k[j - 2], k[j + 3] ^= k[j - 1];
        k[16] ^= sbox[k[12]], k[17] ^= sbox[k[13]], k[18] ^= sbox[k[14]], k[19] ^= sbox[k[15]];
        for (j = 20; j < 32; j += 4) k[j] ^= k[j - 4], k[j + 1] ^= k[j - 3], k[j + 2] ^= k[j - 2], k[j + 3] ^= k[j - 1];
    }

    for (i = 0; i < 14; i++) {
        for (j = 0; j < 4; j++) buf[j] ^= key[j + (i & 1) * 4]; // add round key

        for (j = 0; i > 0 && j < 16; j += 4) { // unmix columns
            a = x[j], b = x[j + 1], c = x[j + 2], d = x[j + 3], e = a ^ b ^ c ^ d;
            h = xt(e), f = e ^ xt(xt(h ^ a ^ c)), g = e ^ xt(xt(h ^ b ^ d));
            x[j] ^= f ^ xt(a ^ b), x[j + 1] ^= g ^ xt(b ^ c), x[j + 2] ^= f ^ xt(c ^ d), x[j + 3] ^= g ^ xt(d ^ a);
        }

        // unshift rows
        a = x[1], x[1] = x[13], x[13] = x[9], x[9] = x[5], x[5] = a, a = x[2], x[2] = x[10], x[10] = a;
        a = x[3], x[3] = x[7], x[7] = x[11], x[11] = x[15], x[15] = a, a = x[6], x[6] = x[14], x[14] = a;

        for (j = 0; j < 16; j++) x[j] = sboxi[x[j]]; // unsub bytes

        if ((i % 2) == 0) { // unexpand key
            for (j = 28; j > 16; j -= 4) k[j] ^= k[j - 4], k[j + 1] ^= k[j - 3], k[j + 2] ^= k[j - 2], k[j + 3] ^= k[j - 1];
            k[16] ^= sbox[k[12]], k[17] ^= sbox[k[13]], k[18] ^= sbox[k[14]], k[19] ^= sbox[k[15]];
            for (j = 12; j > 0; j -= 4) k[j] ^= k[j - 4], k[j + 1] ^= k[j - 3], k[j + 2] ^= k[j - 2], k[j + 3] ^= k[j - 1];
            r = (r >> 1) ^ ((r & 1) * 0x8d);
            k[0] ^= sbox[k[29]] ^ r, k[1] ^= sbox[k[30]], k[2] ^= sbox[k[31]], k[3] ^= sbox[k[28]];
        }
    }

    var_clean(&r, &a, &b, &c, &d, &e, &f, &g, &h);
    for (i = 0; i < 4; i++) buf[i] ^= key[i]; // final add round key
    memory_cleanse(key, sizeof (key));
    memcpy(buf16, buf, sizeof (buf));
    memory_cleanse(buf, sizeof (buf));
}

static uint256 _BIP38DerivePassfactor(uint8_t flag, const uint8_t* entropy, const char* passphrase)
{
    size_t len = strlen(passphrase);
    uint256 prefactor, passfactor;

    Scrypt(prefactor.begin(), prefactor.size(), (const unsigned char*) passphrase, len, entropy, (flag & BIP38_LOTSEQUENCE_FLAG) ? 4 : 8,
           BIP38_SCRYPT_N, BIP38_SCRYPT_R, BIP38_SCRYPT_P);

    if (flag & BIP38_LOTSEQUENCE_FLAG) {
        // passfactor = SHA256(SHA256(prefactor + entropy))
        uint8_t* d = new uint8_t[prefactor.size() + sizeof (uint64_t)];

        memcpy(d, prefactor.begin(), prefactor.size());
        memcpy(&d[prefactor.size()], entropy, sizeof (uint64_t));
        CSHA256().Write((const unsigned char*) d, sizeof (d)).Finalize(prefactor.begin());

        memory_cleanse(d, sizeof (d));
        delete[] d;
    } else passfactor = prefactor;

    var_clean(&len);
    var_clean(prefactor.begin());
    return passfactor;
}

static void _BIP38DeriveKey(unsigned char* output64, const unsigned char* passpoint33, const uint8_t* addresshash, const uint8_t* entropy)
{
    uint8_t salt[sizeof (uint32_t) + sizeof (uint64_t)];

    memcpy(salt, addresshash, sizeof (uint32_t));
    memcpy(&salt[sizeof (uint32_t)], entropy, sizeof (uint64_t)); // salt = addresshash + entropy

    Scrypt(output64, 64, passpoint33, 33, salt, sizeof (salt), BIP38_SCRYPT_EC_N, BIP38_SCRYPT_EC_R, BIP38_SCRYPT_EC_P);
    memory_cleanse(salt, sizeof (salt));
}

bool IsValidBIP38Key(const char* bip38Key)
{
    assert(bip38Key != NULL);

    std::vector<unsigned char> data;
    if (!DecodeBase58Check(bip38Key, data) )
        return false;
    if (data.size() != 39)
        return false; // invalid length

    uint16_t prefix = ReadBE16(data.data());
    uint8_t flag = data[2];

    if (prefix == BIP38_NOEC_PREFIX) { // non EC multiplied key
        return ((flag & BIP38_NOEC_FLAG) == BIP38_NOEC_FLAG && (flag & BIP38_LOTSEQUENCE_FLAG) == 0 &&
                (flag & BIP38_INVALID_FLAG) == 0);
    } else if (prefix == BIP38_EC_PREFIX) { // EC multiplied key
        return false; //don't support EC multiplied key
        // return ((flag & BIP38_NOEC_FLAG) == 0 && (flag & BIP38_INVALID_FLAG) == 0);
    } else {
        return false; // invalid prefix
    }
}

bool DecryptBIP38Key(unsigned char* key32, std::string& strSecret, const char* bip38Key, const char* passphrase)
{
    std::vector<unsigned char> data;
    if (!DecodeBase58Check(bip38Key, data))
        return false;
    if (data.size() != 39)
        return false; // invalid length

    uint16_t prefix = ReadBE16(data.data());
    if (prefix != BIP38_NOEC_PREFIX) {
        //BIP38_EC_PREFIX, don't support EC multipled key
        return false;
    }
    uint8_t flag = data[2];
    uint8_t addresshash[4] = {0};
    memcpy(addresshash, &data[3], 4);
    size_t pwLen = strlen(passphrase);

    // non EC multiplied key
    // data = prefix + flag + addresshash + encrypted1 + encrypted2
    unsigned char encrypted1[16] = {0};
    memcpy(encrypted1, &data[7], 16);
    unsigned char encrypted2[16] = {0};
    memcpy(encrypted2, &data[23], 16);

    unsigned char derived[64] = {0};
    Scrypt(derived, sizeof (derived), (const unsigned char*) passphrase, pwLen, addresshash, sizeof (addresshash),
           BIP38_SCRYPT_N, BIP38_SCRYPT_R, BIP38_SCRYPT_P);

    unsigned char* derived1 = derived; //length 32
    unsigned char* derived2 = &derived[32]; //length 32
    _AES256ECBDecrypt(derived2, encrypted1);
    for (int i = 0; i < 16; ++i) {
        key32[i] = encrypted1[i] ^ derived1[i];
    }
    _AES256ECBDecrypt(derived2, encrypted2);
    for (int i = 16; i < 32; ++i) {
        key32[i] = encrypted2[i - 16] ^ derived1[i];
    }
    var_clean(derived, encrypted1, encrypted2);

    CKey privKey;
    privKey.Set(key32, key32 + 32, (flag & BIP38_COMPRESSED_FLAG) == BIP38_COMPRESSED_FLAG);
    strSecret = CBitcoinSecret(privKey).ToString();

    CTxDestination bitcoinAddress = privKey.GetPubKey().GetID();
    std::string strAddress = EncodeDestination(bitcoinAddress);
    unsigned char hash[32] = {0};
    CSHA256().Write((const unsigned char*) strAddress.c_str(), strAddress.size()).Finalize(hash);
    return memcmp(&hash, &addresshash, sizeof (uint32_t)) == 0;
}

std::string EncryptBIP38Key(const CKey& key, const char* passphrase)
{
    uint16_t prefix = BIP38_NOEC_PREFIX;
    uint8_t flag = BIP38_NOEC_FLAG;

    if (key.IsCompressed())
        flag |= BIP38_COMPRESSED_FLAG;
    std::string address = EncodeDestination(key.GetPubKey().GetID());
    unsigned char hash[32] = {0};
    CSHA256().Write((const unsigned char*) address.c_str(), address.size()).Finalize(hash);
    uint8_t salt[4] = {0};
    memcpy(salt, &hash, 4);

    unsigned char derived[64] = {0};
    Scrypt(derived, sizeof (derived), (const unsigned char*) passphrase, strlen(passphrase), salt, sizeof (salt),
           BIP38_SCRYPT_N, BIP38_SCRYPT_R, BIP38_SCRYPT_P);

    unsigned char* derived1 = derived; //length 32
    unsigned char* derived2 = &derived[32]; //length 32

    unsigned char encrypted1[16] = {0};
    unsigned char encrypted2[16] = {0};
    const unsigned char* keydata = key.begin();
    for (int i = 0; i < 16; ++i) {
        encrypted1[i] = *keydata++ ^ derived1[i];
    }
    _AES256ECBEncrypt(derived2, encrypted1);

    for (int i = 16; i < 32; ++i) {
        encrypted2[i - 16] = *keydata++ ^ derived1[i];
    }
    _AES256ECBEncrypt(derived2, encrypted2);

    uint8_t buf[39];
    size_t off = 0;
    WriteBE16(&buf[off], prefix);
    off += sizeof (prefix);
    buf[off] = flag;
    off += sizeof (flag);
    WriteBE32(&buf[off], ReadBE32(salt));
    off += sizeof (salt);
    memcpy(&buf[off], encrypted1, sizeof (encrypted1));
    off += sizeof (encrypted1);
    memcpy(&buf[off], encrypted2, sizeof (encrypted2));
    off += sizeof (encrypted2);

    var_clean(derived, encrypted1, encrypted2);
    return EncodeBase58Check(std::vector<unsigned char>(buf, buf + off));
}
