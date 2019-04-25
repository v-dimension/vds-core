#ifndef SRC_CRYPTO_PBKDF2_H_
#define SRC_CRYPTO_PBKDF2_H_

#include <cstdlib>
#include <cassert>
#include <cstring>
#include "common.h"
#include "hmac_sha512.h"
#include "hmac_sha256.h"
#include "support/cleanse.h"

//HMAC_SHA is CHMAC_SHA512 or CHMAC_SHA256
// dk = T1 || T2 || ... || Tdklen/hlen
// Ti = U1 xor U2 xor ... xor Urounds
// U1 = hmac_hash(password, salt || be32(i))
// U2 = hmac_hash(password, U1)
// ...
// Urounds = hmac_hash(password, Urounds-1)
template<class HMAC_SHA>
void PBKDF2(const unsigned char *dk, size_t dkLen, const unsigned char *password, size_t passwordLen, const unsigned char *salt, size_t saltLen, unsigned rounds)
{
    const size_t hashLen = HMAC_SHA::OUTPUT_SIZE;//CHMAC_SHA512 return 64 bytes

    assert(dk != NULL || dkLen == 0);
    assert(hashLen > 0 && (hashLen % 4) == 0);
    assert(password != NULL || passwordLen == 0);
    assert(salt != NULL || saltLen == 0);
    assert(rounds > 0);

    unsigned char s[saltLen + sizeof(uint32_t)];
    memcpy(s, salt, saltLen);

    unsigned char U[hashLen], T[hashLen];
    for (uint32_t i = 0; i < (dkLen + hashLen - 1)/hashLen; i++) {
    	WriteBE32(s + saltLen, i + 1);

    	HMAC_SHA(password, passwordLen).Write(s, sizeof(s)).Finalize(U);// U1 = hmac_hash(password, salt || be32(i))
        memcpy(T, U, sizeof(U));

        for (unsigned r = 1; r < rounds; r++) {
        	HMAC_SHA(password, passwordLen).Write(U, sizeof(U)).Finalize(U);// Urounds = hmac_hash(password, Urounds-1)
            for (size_t h = 0; h < hashLen; h++)
            	T[h] ^= U[h]; // Ti = U1 ^ U2 ^ ... ^ Urounds
        }
        // dk = T1 || T2 || ... || Tdklen/hlen
        memcpy((void *)(dk + i*hashLen), T, (i*hashLen + hashLen <= dkLen) ? hashLen : dkLen % hashLen);
    }

    memory_cleanse(s, sizeof(s));
    memory_cleanse(U, sizeof(U));
    memory_cleanse(T, sizeof(T));
}

#endif /* SRC_CRYPTO_PBKDF2_H_ */
