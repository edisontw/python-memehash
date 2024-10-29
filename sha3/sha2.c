/* $Id: sha2.c 227 2010-06-16 17:28:38Z tp $ */
/*
 * SHA-224 / SHA-256 implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#include <stddef.h>
#include <string.h>
#include "sph_sha2.h"

#define CH(X, Y, Z)    ((((Y) ^ (Z)) & (X)) ^ (Z))
#define MAJ(X, Y, Z)   (((X) & (Y)) | (((X) | (Y)) & (Z)))

#define ROTR    SPH_ROTR32

#define BSG2_0(x)      (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSG2_1(x)      (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSG2_0(x)      (ROTR(x, 7) ^ ROTR(x, 18) ^ SPH_T32((x) >> 3))
#define SSG2_1(x)      (ROTR(x, 17) ^ ROTR(x, 19) ^ SPH_T32((x) >> 10))

static const sph_u32 H224[8] = {
    SPH_C32(0xC1059ED8), SPH_C32(0x367CD507), SPH_C32(0x3070DD17),
    SPH_C32(0xF70E5939), SPH_C32(0xFFC00B31), SPH_C32(0x68581511),
    SPH_C32(0x64F98FA7), SPH_C32(0xBEFA4FA4)
};

static const sph_u32 H256[8] = {
    SPH_C32(0x6A09E667), SPH_C32(0xBB67AE85), SPH_C32(0x3C6EF372),
    SPH_C32(0xA54FF53A), SPH_C32(0x510E527F), SPH_C32(0x9B05688C),
    SPH_C32(0x1F83D9AB), SPH_C32(0x5BE0CD19)
};

static const sph_u32 K[64] = {
    SPH_C32(0x428A2F98), SPH_C32(0x71374491), SPH_C32(0xB5C0FBCF),
    SPH_C32(0xE9B5DBA5), SPH_C32(0x3956C25B), SPH_C32(0x59F111F1),
    /* ... Add all K constants here ... */
    SPH_C32(0xBEF9A3F7), SPH_C32(0xC67178F2)
};

static void
sha2_round(const unsigned char *data, sph_u32 *val)
{
    sph_u32 W[64], T1, T2;
    int i;

    for (i = 0; i < 16; i ++)
        W[i] = sph_dec32be(data + (i << 2));
    for (i = 16; i < 64; i ++)
        W[i] = SSG2_1(W[i - 2]) + W[i - 7] + SSG2_0(W[i - 15]) + W[i - 16];

    for (i = 0; i < 64; i ++) {
        T1 = val[7] + BSG2_1(val[4]) + CH(val[4], val[5], val[6]) + K[i] + W[i];
        T2 = BSG2_0(val[0]) + MAJ(val[0], val[1], val[2]);
        val[7] = val[6];
        val[6] = val[5];
        val[5] = val[4];
        val[4] = val[3] + T1;
        val[3] = val[2];
        val[2] = val[1];
        val[1] = val[0];
        val[0] = T1 + T2;
    }
}

/* see sph_sha2.h */
void
sph_sha224_init(void *cc)
{
    sph_sha224_context *sc;

    sc = cc;
    memcpy(sc->val, H224, sizeof H224);
    sc->count = 0;
}

/* see sph_sha2.h */
void
sph_sha256_init(void *cc)
{
    sph_sha256_context *sc;

    sc = cc;
    memcpy(sc->val, H256, sizeof H256);
    sc->count = 0;
}

static void
sha2_update(void *cc, const void *data, size_t len)
{
    sph_sha224_context *sc;
    unsigned char *buf;
    size_t ptr;
    const unsigned char *in;

    sc = cc;
    buf = sc->buf;
    ptr = (size_t)(sc->count & 63U);
    in = data;
    while (len > 0) {
        size_t clen;

        clen = (sizeof sc->buf) - ptr;
        if (clen > len)
            clen = len;
        memcpy(buf + ptr, in, clen);
        ptr += clen;
        in += clen;
        len -= clen;
        if (ptr == sizeof sc->buf) {
            sha2_round(buf, sc->val);
            ptr = 0;
        }
        sc->count += (sph_u32)clen;
    }
}

/* see sph_sha2.h */
void
sph_sha224(void *cc, const void *data, size_t len)
{
    sha2_update(cc, data, len);
}

/* see sph_sha2.h */
void
sph_sha256(void *cc, const void *data, size_t len)
{
    sha2_update(cc, data, len);
}

static void
sha2_close(void *cc, void *dst, size_t out_size_w32)
{
    sph_sha224_context *sc;
    unsigned char *buf;
    size_t ptr;
    unsigned z;
    unsigned char out[32];

    sc = cc;
    buf = sc->buf;
    ptr = (size_t)(sc->count & 63U);

    buf[ptr ++] = 0x80;
    z = 64 - ptr;
    if (z < 8) {
        memset(buf + ptr, 0, z);
        sha2_round(buf, sc->val);
        memset(buf, 0, 56);
    } else {
        memset(buf + ptr, 0, 56 - ptr);
    }
    sph_enc64be(buf + 56, SPH_T64(sc->count << 3));
    sha2_round(buf, sc->val);

    for (z = 0; z < out_size_w32; z ++)
        sph_enc32be(out + (z << 2), sc->val[z]);
    memcpy(dst, out, out_size_w32 << 2);
}

/* see sph_sha2.h */
void
sph_sha224_close(void *cc, void *dst)
{
    sha2_close(cc, dst, 7);
    sph_sha224_init(cc);
}

/* see sph_sha2.h */
void
sph_sha256_close(void *cc, void *dst)
{
    sha2_close(cc, dst, 8);
    sph_sha256_init(cc);
}
