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

// Remove the visibility attributes and make the functions truly external
extern void sph_sha224_init(void *cc);
extern void sph_sha256_init(void *cc);
extern void sph_sha224(void *cc, const void *data, size_t len);
extern void sph_sha256(void *cc, const void *data, size_t len);
extern void sph_sha224_close(void *cc, void *dst);
extern void sph_sha256_close(void *cc, void *dst);
extern void sph_sha224_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst);
extern void sph_sha256_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst);

// Rest of your existing defines
#define CH(X, Y, Z)    ((X & Y) ^ (~X & Z))
#define MAJ(X, Y, Z)   ((X & Y) ^ (X & Z) ^ (Y & Z))
#define ROTR(x, n)     SPH_ROTR32(x, n)
#define SHR(x, n)      SPH_T32((x) >> (n))
#define S0(x)    (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)    (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)    (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x)    (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

// Initial hash values
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

// Your existing K256 array...

// Function implementations without visibility attributes
void sph_sha224_init(void *cc)
{
    sph_sha224_context *ctx = cc;
    memcpy(ctx->val, H224, sizeof H224);
    ctx->count = 0;
}

void sph_sha256_init(void *cc)
{
    sph_sha256_context *ctx = cc;
    memcpy(ctx->val, H256, sizeof H256);
    ctx->count = 0;
}

void sph_sha224(void *cc, const void *data, size_t len)
{
    sph_sha256(cc, data, len);
}

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

void sph_sha224_close(void *cc, void *dst)
{
    sha256_close(cc, 0, 0, dst, 7);
}

void sph_sha256_close(void *cc, void *dst)
{
    sha256_close(cc, 0, 0, dst, 8);
}

void sph_sha224_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
    sha256_close(cc, ub, n, dst, 7);
}

void sph_sha256_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
    sha256_close(cc, ub, n, dst, 8);
}
