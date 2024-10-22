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

static const sph_u32 K256[64] = {
    SPH_C32(0x428A2F98), SPH_C32(0x71374491),
    SPH_C32(0xB5C0FBCF), SPH_C32(0xE9B5DBA5),
    /* ... (rest of K256 constants) ... */
};

static void
sha256_round(const sph_u32 *data, sph_u32 *val)
{
    sph_u32 T1, T2, A, B, C, D, E, F, G, H;
    sph_u32 W[64];
    int i;

    for (i = 0; i < 16; i++)
        W[i] = sph_dec32be_aligned(data + i);
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
    for (i = 0; i < 64; i ++) {
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

/* SHA-224 initialization constants */
static const sph_u32 H224[8] = {
    SPH_C32(0xC1059ED8), SPH_C32(0x367CD507),
    SPH_C32(0x3070DD17), SPH_C32(0xF70E5939),
    SPH_C32(0xFFC00B31), SPH_C32(0x68581511),
    SPH_C32(0x64F98FA7), SPH_C32(0xBEFA4FA4)
};

/* SHA-256 initialization constants */
static const sph_u32 H256[8] = {
    SPH_C32(0x6A09E667), SPH_C32(0xBB67AE85),
    SPH_C32(0x3C6EF372), SPH_C32(0xA54FF53A),
    SPH_C32(0x510E527F), SPH_C32(0x9B05688C),
    SPH_C32(0x1F83D9AB), SPH_C32(0x5BE0CD19)
};

void
sph_sha224_init(void *cc)
{
    sph_sha224_context *ctx = cc;

    memcpy(ctx->val, H224, sizeof H224);
    ctx->count = 0;
}

void
sph_sha256_init(void *cc)
{
    sph_sha256_context *ctx = cc;

    memcpy(ctx->val, H256, sizeof H256);
    ctx->count = 0;
}

void
sph_sha224(void *cc, const void *data, size_t len)
{
    sph_sha256(cc, data, len);
}

void
sph_sha256(void *cc, const void *data, size_t len)
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

static void
sha256_close(void *cc, unsigned ub, unsigned n, void *dst, size_t out_size_w32)
{
    sph_sha256_context *ctx = cc;
    unsigned char *buf;
    size_t current;
    unsigned char d[64];
    unsigned char *out;
    size_t u;

    buf = ctx->buf;
    current = (size_t)(ctx->count & 0x3F);
    buf[current++] = 0x80;
    if (current > 56) {
        memset(buf + current, 0, 64 - current);
        sha256_round((sph_u32 *)buf, ctx->val);
        current = 0;
    }
    memset(buf + current, 0, 56 - current);
    sph_enc64be(d + 56, SPH_T64(ctx->count << 3));
    sha256_round((sph_u32 *)buf, ctx->val);
    for (u = 0; u < out_size_w32; u++)
        sph_enc32be(d + (u << 2), ctx->val[u]);
    memcpy(dst, d, out_size_w32 << 2);
    memset(ctx, 0, sizeof(*ctx));
}

void
sph_sha224_close(void *cc, void *dst)
{
    sha256_close(cc, 0, 0, dst, 7);
}

void
sph_sha256_close(void *cc, void *dst)
{
    sha256_close(cc, 0, 0, dst, 8);
}

void
sph_sha224_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
    sha256_close(cc, ub, n, dst, 7);
}

void
sph_sha256_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
    sha256_close(cc, ub, n, dst, 8);
}
