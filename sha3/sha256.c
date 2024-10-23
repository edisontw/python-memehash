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
    SPH_C32(0x3956C25B), SPH_C32(0x59F111F1),
    SPH_C32(0x923F82A4), SPH_C32(0xAB1C5ED5),
    // ... (rest of K256 constants) ...
};

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
