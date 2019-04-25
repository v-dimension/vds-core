#include "scrypt.h"
#include <cstdint>
#include <cassert>
#include <cstring>
#include "pbkdf2.h"
#include "common.h"
#include "support/cleanse.h"

// bitwise left rotation
#define rol32(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

// salsa20/8 stream cypher: http://cr.yp.to/snuffle.html

static void _salsa20_8(uint32_t b[16])
{
    uint32_t x0 = b[0], x1 = b[1], x2 = b[2], x3 = b[3], x4 = b[4], x5 = b[5], x6 = b[6], x7 = b[7],
            x8 = b[8], x9 = b[9], xa = b[10], xb = b[11], xc = b[12], xd = b[13], xe = b[14], xf = b[15];

    for (unsigned i = 0; i < 8; i += 2) {
        // operate on columns
        x4 ^= rol32(x0 + xc, 7), x8 ^= rol32(x4 + x0, 9), xc ^= rol32(x8 + x4, 13), x0 ^= rol32(xc + x8, 18);
        x9 ^= rol32(x5 + x1, 7), xd ^= rol32(x9 + x5, 9), x1 ^= rol32(xd + x9, 13), x5 ^= rol32(x1 + xd, 18);
        xe ^= rol32(xa + x6, 7), x2 ^= rol32(xe + xa, 9), x6 ^= rol32(x2 + xe, 13), xa ^= rol32(x6 + x2, 18);
        x3 ^= rol32(xf + xb, 7), x7 ^= rol32(x3 + xf, 9), xb ^= rol32(x7 + x3, 13), xf ^= rol32(xb + x7, 18);

        // operate on rows
        x1 ^= rol32(x0 + x3, 7), x2 ^= rol32(x1 + x0, 9), x3 ^= rol32(x2 + x1, 13), x0 ^= rol32(x3 + x2, 18);
        x6 ^= rol32(x5 + x4, 7), x7 ^= rol32(x6 + x5, 9), x4 ^= rol32(x7 + x6, 13), x5 ^= rol32(x4 + x7, 18);
        xb ^= rol32(xa + x9, 7), x8 ^= rol32(xb + xa, 9), x9 ^= rol32(x8 + xb, 13), xa ^= rol32(x9 + x8, 18);
        xc ^= rol32(xf + xe, 7), xd ^= rol32(xc + xf, 9), xe ^= rol32(xd + xc, 13), xf ^= rol32(xe + xd, 18);
    }

    b[0] += x0, b[1] += x1, b[2] += x2, b[3] += x3, b[4] += x4, b[5] += x5, b[6] += x6, b[7] += x7;
    b[8] += x8, b[9] += x9, b[10] += xa, b[11] += xb, b[12] += xc, b[13] += xd, b[14] += xe, b[15] += xf;
}

static void _blockmix_salsa8(uint64_t *dest, const uint64_t *src, uint64_t *b, unsigned r)
{
    memcpy(b, &src[(2 * r - 1)*8], 64);

    for (unsigned i = 0; i < 2 * r; i += 2) {
        for (unsigned j = 0; j < 8; j++) b[j] ^= src[i * 8 + j];
        _salsa20_8((uint32_t *) b);
        memcpy(&dest[i * 4], b, 64);
        for (unsigned j = 0; j < 8; j++) b[j] ^= src[i * 8 + 8 + j];
        _salsa20_8((uint32_t *) b);
        memcpy(&dest[i * 4 + r * 8], b, 64);
    }
}

// scrypt key derivation: http://www.tarsnap.com/scrypt.html

void Scrypt(unsigned char *dk, size_t dkLen, const unsigned char *pw, size_t pwLen, const unsigned char *salt, size_t saltLen,
        unsigned n, unsigned r, unsigned p)
{
    uint64_t x[16 * r], y[16 * r], z[8], m;
    uint64_t *v = new uint64_t[128 * r * n];
    uint32_t b[32 * r * p];

    assert(v != NULL);
    assert(dk != NULL || dkLen == 0);
    assert(pw != NULL || pwLen == 0);
    assert(salt != NULL || saltLen == 0);
    assert(n > 0);
    assert(r > 0);
    assert(p > 0);

    PBKDF2<CHMAC_SHA256>((unsigned char *) b, sizeof (b), pw, pwLen, salt, saltLen, 1);

    for (int i = 0; i < p; i++) {
        for (unsigned j = 0; j < 32 * r; j++)
            WriteLE32((unsigned char *) ((uint32_t *) x + j), b[i * 32 * r + j]);
        //        	((uint32_t *)x)[j] = le32(b[i*32*r + j]);

        for (unsigned j = 0; j < n; j += 2) {
            memcpy(&v[j * (16 * r)], x, 128 * r);
            _blockmix_salsa8(y, x, z, r);
            memcpy(&v[(j + 1)*(16 * r)], y, 128 * r);
            _blockmix_salsa8(x, y, z, r);
        }

        for (unsigned j = 0; j < n; j += 2) {
            WriteLE64((unsigned char *) &m, x[(2 * r - 1)*8]);
            m &= n - 1;
            //            m = le64(x[(2*r - 1)*8]) & (n - 1);
            for (unsigned k = 0; k < 16 * r; k++) x[k] ^= v[m * (16 * r) + k];
            _blockmix_salsa8(y, x, z, r);
            WriteLE64((unsigned char *) &m, y[(2 * r - 1)*8]);
            m &= n - 1;
            //            m = le64(y[(2*r - 1)*8]) & (n - 1);
            for (unsigned k = 0; k < 16 * r; k++) y[k] ^= v[m * (16 * r) + k];
            _blockmix_salsa8(x, y, z, r);
        }

        for (unsigned j = 0; j < 32 * r; j++)
            WriteLE32((unsigned char *) (b + i * 32 * r + j), ((uint32_t *) x)[j]);
        //        	b[i*32*r + j] = le32(((uint32_t *)x)[j]);
    }
    PBKDF2<CHMAC_SHA256>(dk, dkLen, pw, pwLen, (unsigned char *) b, sizeof (b), 1);
    //    BRPBKDF2(dk, dkLen, BRSHA256, 256/8, pw, pwLen, b, sizeof(b), 1);
    memory_cleanse(b, sizeof (b));
    memory_cleanse(x, sizeof (x));
    memory_cleanse(y, sizeof (y));
    memory_cleanse(z, sizeof (z));
    memory_cleanse(v, 128 * r * n);
    delete[] v;
}

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16])
{
    uint32_t x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, x11, x12, x13, x14, x15;
    int i;

    x00 = (B[ 0] ^= Bx[ 0]);
    x01 = (B[ 1] ^= Bx[ 1]);
    x02 = (B[ 2] ^= Bx[ 2]);
    x03 = (B[ 3] ^= Bx[ 3]);
    x04 = (B[ 4] ^= Bx[ 4]);
    x05 = (B[ 5] ^= Bx[ 5]);
    x06 = (B[ 6] ^= Bx[ 6]);
    x07 = (B[ 7] ^= Bx[ 7]);
    x08 = (B[ 8] ^= Bx[ 8]);
    x09 = (B[ 9] ^= Bx[ 9]);
    x10 = (B[10] ^= Bx[10]);
    x11 = (B[11] ^= Bx[11]);
    x12 = (B[12] ^= Bx[12]);
    x13 = (B[13] ^= Bx[13]);
    x14 = (B[14] ^= Bx[14]);
    x15 = (B[15] ^= Bx[15]);
    for (i = 0; i < 8; i += 2) {
        /* Operate on columns. */
        x04 ^= ROTL(x00 + x12, 7);
        x09 ^= ROTL(x05 + x01, 7);
        x14 ^= ROTL(x10 + x06, 7);
        x03 ^= ROTL(x15 + x11, 7);

        x08 ^= ROTL(x04 + x00, 9);
        x13 ^= ROTL(x09 + x05, 9);
        x02 ^= ROTL(x14 + x10, 9);
        x07 ^= ROTL(x03 + x15, 9);

        x12 ^= ROTL(x08 + x04, 13);
        x01 ^= ROTL(x13 + x09, 13);
        x06 ^= ROTL(x02 + x14, 13);
        x11 ^= ROTL(x07 + x03, 13);

        x00 ^= ROTL(x12 + x08, 18);
        x05 ^= ROTL(x01 + x13, 18);
        x10 ^= ROTL(x06 + x02, 18);
        x15 ^= ROTL(x11 + x07, 18);

        /* Operate on rows. */
        x01 ^= ROTL(x00 + x03, 7);
        x06 ^= ROTL(x05 + x04, 7);
        x11 ^= ROTL(x10 + x09, 7);
        x12 ^= ROTL(x15 + x14, 7);

        x02 ^= ROTL(x01 + x00, 9);
        x07 ^= ROTL(x06 + x05, 9);
        x08 ^= ROTL(x11 + x10, 9);
        x13 ^= ROTL(x12 + x15, 9);

        x03 ^= ROTL(x02 + x01, 13);
        x04 ^= ROTL(x07 + x06, 13);
        x09 ^= ROTL(x08 + x11, 13);
        x14 ^= ROTL(x13 + x12, 13);

        x00 ^= ROTL(x03 + x02, 18);
        x05 ^= ROTL(x04 + x07, 18);
        x10 ^= ROTL(x09 + x08, 18);
        x15 ^= ROTL(x14 + x13, 18);
    }
    B[ 0] += x00;
    B[ 1] += x01;
    B[ 2] += x02;
    B[ 3] += x03;
    B[ 4] += x04;
    B[ 5] += x05;
    B[ 6] += x06;
    B[ 7] += x07;
    B[ 8] += x08;
    B[ 9] += x09;
    B[10] += x10;
    B[11] += x11;
    B[12] += x12;
    B[13] += x13;
    B[14] += x14;
    B[15] += x15;
}

void scrypt_1024_1_1_256_sp_generic(const char *input, char *output, char *scratchpad)
{
    uint8_t B[128];
    uint32_t X[32];
    uint32_t *V;
    uint32_t i, j, k;

    V = (uint32_t *) (((uintptr_t) (scratchpad) + 63) & ~(uintptr_t) (63));

    PBKDF2<CHMAC_SHA256>((uint8_t *) B, 128, (unsigned char *) input, headerLen, (unsigned char *) input, headerLen, 1);

    for (k = 0; k < 32; k++)
        X[k] = le32dec(&B[4 * k]);

    for (i = 0; i < 1024; i++) {
        memcpy(&V[i * 32], X, 128);
        xor_salsa8(&X[0], &X[16]);
        xor_salsa8(&X[16], &X[0]);
    }
    for (i = 0; i < 1024; i++) {
        j = 32 * (X[16] & 1023);
        for (k = 0; k < 32; k++)
            X[k] ^= V[j + k];
        xor_salsa8(&X[0], &X[16]);
        xor_salsa8(&X[16], &X[0]);
    }

    for (k = 0; k < 32; k++)
        le32enc(&B[4 * k], X[k]);

    PBKDF2<CHMAC_SHA256>((uint8_t *) output, 32, (unsigned char *) input, headerLen, (uint8_t *) B, 128, 1);
}

void scrypt_1024_1_1_256(const char *input, char *output)
{
    char scratchpad[SCRYPT_SCRATCHPAD_SIZE];
    scrypt_1024_1_1_256_sp_generic(input, output, scratchpad);
}
