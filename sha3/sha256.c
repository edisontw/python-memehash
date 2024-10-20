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
#include "sph_sha256.h"
#include <string.h>

#define CH(X, Y, Z)    ((X & Y) ^ (~X & Z))
#define MAJ(X, Y, Z)   ((X & Y) ^ (X & Z) ^ (Y & Z))
#define ROTR(x, n)     (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n)      ((x) >> (n))
#define S0(x)          (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)          (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)          (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x)          (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

static const sph_u32 K[64] = {
    // ... (same as before)
};

static void
sha256_round(const sph_u32 *data, sph_u32 *val)
{
    sph_u32 T1, T2, A, B, C, D, E, F, G, H;
    sph_u32 W[64];
    int i;

    for (i = 0; i < 16; i++)
        W[i] = sph_dec32be(data + i);
    for (i = 16; i < 64; i++)
        W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
    A = val[0];
    B = val[1];
    C = val[2];
    D = val[3];
    E = val[4];
    F = val[5];
    G = val[6];
    H = val[7];
    for (i = 0; i < 64; i++) {
        T1 = H + S1(E) + CH(E, F, G) + K[i] + W[i];
        T2 = S0(A) + MAJ(A, B, C);
        H = G;
        G = F;
        F = E;
        E = D + T1;
        D = C;
        C = B;
        B = A;
        A = T1 + T2;
    }
    val[0] += A;
    val[1] += B;
    val[2] += C;
    val[3] += D;
    val[4] += E;
    val[5] += F;
    val[6] += G;
    val[7] += H;
}

void
sph_sha256_init(sph_sha256_context *cc)
{
    cc->count = 0;
    cc->state[0] = 0x6A09E667;
    cc->state[1] = 0xBB67AE85;
    cc->state[2] = 0x3C6EF372;
    cc->state[3] = 0xA54FF53A;
    cc->state[4] = 0x510E527F;
    cc->state[5] = 0x9B05688C;
    cc->state[6] = 0x1F83D9AB;
    cc->state[7] = 0x5BE0CD19;
    cc->ptr = 0;
}

void
sph_sha256(sph_sha256_context *cc, const void *data, size_t len)
{
    size_t current;
    unsigned char *buf;

    buf = cc->buf;
    current = cc->ptr;
    while (len > 0) {
        size_t clen;

        clen = 64 - current;
        if (clen > len)
            clen = len;
        memcpy(buf + current, data, clen);
        data = (const unsigned char *)data + clen;
        current += clen;
        len -= clen;
        if (current == 64) {
            sha256_round((sph_u32 *)buf, cc->state);
            current = 0;
        }
    }
    cc->ptr = current;
    cc->count += len;
}

void
sph_sha256_close(sph_sha256_context *cc, void *dst)
{
    unsigned char *buf;
    size_t ptr;
    sph_u64 bb;

    buf = cc->buf;
    ptr = cc->ptr;
    bb = cc->count << 3;
    buf[ptr++] = 0x80;
    if (ptr > 56) {
        memset(buf + ptr, 0, 64 - ptr);
        sha256_round((sph_u32 *)buf, cc->state);
        memset(buf, 0, 56);
    } else {
        memset(buf + ptr, 0, 56 - ptr);
    }
    sph_enc64be(buf + 56, bb);
    sha256_round((sph_u32 *)buf, cc->state);
    sph_enc32be((unsigned char *)dst + 0, cc->state[0]);
    sph_enc32be((unsigned char *)dst + 4, cc->state[1]);
    sph_enc32be((unsigned char *)dst + 8, cc->state[2]);
    sph_enc32be((unsigned char *)dst + 12, cc->state[3]);
    sph_enc32be((unsigned char *)dst + 16, cc->state[4]);
    sph_enc32be((unsigned char *)dst + 20, cc->state[5]);
    sph_enc32be((unsigned char *)dst + 24, cc->state[6]);
    sph_enc32be((unsigned char *)dst + 28, cc->state[7]);
}

void
sph_sha256_addbits_and_close(sph_sha256_context *cc, unsigned ub, unsigned n, void *dst)
{
    unsigned char *buf;
    size_t ptr;
    sph_u64 bb;

    buf = cc->buf;
    ptr = cc->ptr;
    bb = cc->count << 3;
    bb += n;
    if (n > 0) {
        unsigned z;

        buf[ptr ++] = ((ub & 0xFF) << (8 - n)) & 0xFF;
        if (ptr == 64) {
            sha256_round((sph_u32 *)buf, cc->state);
            ptr = 0;
        }
        z = 0x80 >> n;
        buf[ptr ++] = z;
    } else {
        buf[ptr ++] = 0x80;
    }
    if (ptr > 56) {
        memset(buf + ptr, 0, 64 - ptr);
        sha256_round((sph_u32 *)buf, cc->state);
        memset(buf, 0, 56);
    } else {
        memset(buf + ptr, 0, 56 - ptr);
    }
    sph_enc64be(buf + 56, bb);
    sha256_round((sph_u32 *)buf, cc->state);
    sph_enc32be((unsigned char *)dst + 0, cc->state[0]);
    sph_enc32be((unsigned char *)dst + 4, cc->state[1]);
    sph_enc32be((unsigned char *)dst + 8, cc->state[2]);
    sph_enc32be((unsigned char *)dst + 12, cc->state[3]);
    sph_enc32be((unsigned char *)dst + 16, cc->state[4]);
    sph_enc32be((unsigned char *)dst + 20, cc->state[5]);
    sph_enc32be((unsigned char *)dst + 24, cc->state[6]);
    sph_enc32be((unsigned char *)dst + 28, cc->state[7]);
}

void
sph_sha256_comp(const sph_u32 msg[16], sph_u32 val[8])
{
    sha256_round(msg, val);
}
