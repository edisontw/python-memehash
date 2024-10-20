/*********************************************************************
* Filename:   sha256.h
* Original Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef SPH_SHA256_H
#define SPH_SHA256_H

#include <stddef.h>
#include "sph_types.h"

typedef struct {
    unsigned char buf[64];
    size_t ptr;
    sph_u32 state[8];
    sph_u64 count;
} sph_sha256_context;

void sph_sha256_init(sph_sha256_context *cc);
void sph_sha256(sph_sha256_context *cc, const void *data, size_t len);
void sph_sha256_close(sph_sha256_context *cc, void *dst);
void sph_sha256_addbits_and_close(sph_sha256_context *cc, unsigned ub, unsigned n, void *dst);
void sph_sha256_comp(const sph_u32 msg[16], sph_u32 val[8]);

#endif
