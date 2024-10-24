/*********************************************************************
* Filename:   sha256.c
* Original Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Implementation of the SHA-256 hashing algorithm.
              SHA-256 is one of the three algorithms in the SHA2
              specification. The others, SHA-384 and SHA-512, are not
              offered in this implementation.
              Algorithm specification can be found here:
               * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf
              This implementation uses little endian byte order.
*********************************************************************/
#include <string.h>
#include "sph_sha256.h"

#define CH(X, Y, Z)    ((X & Y) ^ (~X & Z))
#define MAJ(X, Y, Z)   ((X & Y) ^ (X & Z) ^ (Y & Z))
#define ROTR(x, n)     SPH_ROTR32(x, n)
#define SHR(x, n)      SPH_T32((x) >> (n))
#define S0(x)    (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)    (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)    (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x)    (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/* Initial hash values */
static const sph_u32 H224[8] = {
    SPH_C32(0xc1059ed8), SPH_C32(0x367cd507),
    SPH_C32(0x3070dd17), SPH_C32(0xf70e5939),
    SPH_C32(0xffc00b31), SPH_C32(0x68581511),
    SPH_C32(0x64f98fa7), SPH_C32(0xbefa4fa4)
};

static const sph_u32 H256[8] = {
    SPH_C32(0x6a09e667), SPH_C32(0xbb67ae85),
    SPH_C32(0x3c6ef372), SPH_C32(0xa54ff53a),
    SPH_C32(0x510e527f), SPH_C32(0x9b05688c),
    SPH_C32(0x1f83d9ab), SPH_C32(0x5be0cd19)
};

static const sph_u32 K256[64] = {
    SPH_C32(0x428A2F98), SPH_C32(0x71374491),
    SPH_C32(0xB5C0FBCF), SPH_C32(0xE9B5DBA5),
    SPH_C32(0x3956C25B), SPH_C32(0x59F111F1),
    SPH_C32(0x923F82A4), SPH_C32(0xAB1C5ED5),
    SPH_C32(0xD807AA98), SPH_C32(0x12835B01),
    SPH_C32(0x243185BE), SPH_C32(0x550C7DC3),
    SPH_C32(0x72BE5D74), SPH_C32(0x80DEB1FE),
    SPH_C32(0x9BDC06A7), SPH_C32(0xC19BF174),
    SPH_C32(0xE49B69C1), SPH_C32(0xEFBE4786),
    SPH_C32(0x0FC19DC6), SPH_C32(0x240CA1CC),
    SPH_C32(0x2DE92C6F), SPH_C32(0x4A7484AA),
    SPH_C32(0x5CB0A9DC), SPH_C32(0x76F988DA),
    SPH_C32(0x983E5152), SPH_C32(0xA831C66D),
    SPH_C32(0xB00327C8), SPH_C32(0xBF597FC7),
    SPH_C32(0xC6E00BF3), SPH_C32(0xD5A79147),
    SPH_C32(0x06CA6351), SPH_C32(0x14292967),
    SPH_C32(0x27B70A85), SPH_C32(0x2E1B2138),
    SPH_C32(0x4D2C6DFC), SPH_C32(0x53380D13),
    SPH_C32(0x650A7354), SPH_C32(0x766A0ABB),
    SPH_C32(0x81C2C92E), SPH_C32(0x92722C85),
    SPH_C32(0xA2BFE8A1), SPH_C32(0xA81A664B),
    SPH_C32(0xC24B8B70), SPH_C32(0xC76C51A3),
    SPH_C32(0xD192E819), SPH_C32(0xD6990624),
    SPH_C32(0xF40E3585), SPH_C32(0x106AA070),
    SPH_C32(0x19A4C116), SPH_C32(0x1E376C08),
    SPH_C32(0x2748774C), SPH_C32(0x34B0BCB5),
    SPH_C32(0x391C0CB3), SPH_C32(0x4ED8AA4A),
    SPH_C32(0x5B9CCA4F), SPH_C32(0x682E6FF3),
    SPH_C32(0x748F82EE), SPH_C32(0x78A5636F),
    SPH_C32(0x84C87814), SPH_C32(0x8CC70208),
    SPH_C32(0x90BEFFFA), SPH_C32(0xA4506CEB),
    SPH_C32(0xBEF9A3F7), SPH_C32(0xC67178F2)
};

/* SHA-256 round function */
static void sha256_round(const sph_u32 *data, sph_u32 *val)
{
    sph_u32 W[64];
    sph_u32 A, B, C, D, E, F, G, H;
    int i;

    for (i = 0; i < 16; i++)
        W[i] = SPH_T32(SPH_BE32(data[i]));
    for (i = 16; i < 64; i++)
        W[i] = SPH_T32(s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16]);

    A = val[0];
    B = val[1];
    C = val[2];
    D = val[3];
    E = val[4];
    F = val[5];
    G = val[6];
    H = val[7];

    for (i = 0; i < 64; i++) {
        sph_u32 T1, T2;

        T1 = SPH_T32(H + S1(E) + CH(E, F, G) + K256[i] + W[i]);
        T2 = SPH_T32(S0(A) + MAJ(A, B, C));
        H = G;
        G = F;
        F = E;
        E = SPH_T32(D + T1);
        D = C;
        C = B;
        B = A;
        A = SPH_T32(T1 + T2);
    }

    val[0] = SPH_T32(val[0] + A);
    val[1] = SPH_T32(val[1] + B);
    val[2] = SPH_T32(val[2] + C);
    val[3] = SPH_T32(val[3] + D);
    val[4] = SPH_T32(val[4] + E);
    val[5] = SPH_T32(val[5] + F);
    val[6] = SPH_T32(val[6] + G);
    val[7] = SPH_T32(val[7] + H);
}

/* SHA-256 final padding and digest computation */
static void sha256_close(void *cc, unsigned ub, unsigned n, void *dst, size_t out_size_w32)
{
    sph_sha256_context *ctx = cc;
    unsigned char *buf;
    size_t ptr;
    sph_u32 bit_len;
    sph_u64 th, tl;

    buf = ctx->buf;
    ptr = (size_t)(ctx->count & 0x3F);
    bit_len = ((unsigned)ptr << 3) + n;
    buf[ptr ++] = (0x80U | ((ub & 0x80U) >> 7));
    th = (ctx->count >> 29) & SPH_T64(0x1F);
    tl = SPH_T64(ctx->count << 3) | SPH_T64(bit_len);

    if (ptr > 56) {
        memset(buf + ptr, 0, (size_t)(64 - ptr));
        sha256_round((sph_u32 *)buf, ctx->val);
        ptr = 0;
    }
    memset(buf + ptr, 0, (size_t)(56 - ptr));
    *(sph_u32 *)(buf + 56) = SPH_BE32((sph_u32)th);
    *(sph_u32 *)(buf + 60) = SPH_BE32((sph_u32)tl);
    sha256_round((sph_u32 *)buf, ctx->val);
    
    for (ptr = 0; ptr < out_size_w32; ptr++)
        ((sph_u32 *)dst)[ptr] = SPH_BE32(ctx->val[ptr]);
}

/* Make these functions externally visible */
__attribute__((visibility("default")))
void sph_sha224_init(void *cc)
{
    sph_sha224_context *ctx = cc;
    memcpy(ctx->val, H224, sizeof H224);
    ctx->count = 0;
}

__attribute__((visibility("default")))
void sph_sha256_init(void *cc)
{
    sph_sha256_context *ctx = cc;
    memcpy(ctx->val, H256, sizeof H256);
    ctx->count = 0;
}

__attribute__((visibility("default")))
void sph_sha224(void *cc, const void *data, size_t len)
{
    sph_sha256(cc, data, len);
}

__attribute__((visibility("default")))
void sph_sha256(void *cc, const void *data, size_t len)
{
    sph_sha256_context *ctx = cc;
    size_t current;
    unsigned char *buf;
    
    buf = ctx->buf;
    current = (size_t)(ctx->count & 0x3F);
    ctx->count += len;
    if (current != 0) {
        size_t rem = 64 - current;
        if (len < rem) {
            memcpy(buf + current, data, len);
            return;
        }
        memcpy(buf + current, data, rem);
        data = (const unsigned char *)data + rem;
        len -= rem;
        sha256_round((sph_u32 *)buf, ctx->val);
    }
    while (len >= 64) {
        sha256_round((const sph_u32 *)data, ctx->val);
        data = (const unsigned char *)data + 64;
        len -= 64;
    }
    if (len > 0)
        memcpy(buf, data, len);
}

__attribute__((visibility("default")))
void sph_sha224_close(void *cc, void *dst)
{
    sha256_close(cc, 0, 0, dst, 7);
}

__attribute__((visibility("default")))
void sph_sha256_close(void *cc, void *dst)
{
    sha256_close(cc, 0, 0, dst, 8);
}

__attribute__((visibility("default")))
void sph_sha224_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
    sha256_close(cc, ub, n, dst, 7);
}

__attribute__((visibility("default")))
void sph_sha256_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
    sha256_close(cc, ub, n, dst, 8);
}
