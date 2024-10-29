/* $Id: sph_sha2.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * SHA-224, SHA-256, SHA-384 and SHA-512 interface.
 *
 * SHA-256 has been published in FIPS 180-2, now amended with a change
 * notice to include SHA-224 as well (which is a simple variation on
 * SHA-256). SHA-384 and SHA-512 are also defined in FIPS 180-2. FIPS
 * standards can be found at:
 *    http://csrc.nist.gov/publications/fips/
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
 * @file     sph_sha2.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

/* $Id: sph_sha2.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * SHA-224, SHA-256, SHA-384 and SHA-512 interface.
 *
 * @warning   The SHA-224 and SHA-256 functions are now deprecated. Use the
 * SHA-2 functions instead.
 */

#ifndef SPH_SHA2_H__
#define SPH_SHA2_H__

#include <stddef.h>
#include "sph_types.h"

/**
 * Output size (in bits) for SHA-224.
 */
#define SPH_SIZE_sha224   224

/**
 * Output size (in bits) for SHA-256.
 */
#define SPH_SIZE_sha256   256

/**
 * This structure is a context for SHA-224 computations: it contains the
 * intermediate values and some data from the last entered block. Once
 * a SHA-224 computation has been performed, the context can be reused for
 * another computation.
 *
 * The contents of this structure are private. A running SHA-224 computation
 * can be cloned by copying the context (e.g. with a simple memcpy()).
 */
typedef struct {
    unsigned char buf[64];    /* first field, for alignment */
    sph_u32 val[8];
    sph_u32 count;
} sph_sha224_context;

/**
 * This structure is a context for SHA-256 computations. It is identical
 * to the SHA-224 context. However, a context is initialized for SHA-224
 * or SHA-256, and shall be used for the chosen function only.
 */
typedef sph_sha224_context sph_sha256_context;

/**
 * Initialize a SHA-224 context. This process performs no memory allocation.
 *
 * @param cc   the SHA-224 context (pointer to a sph_sha224_context)
 */
void sph_sha224_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the SHA-224 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_sha224(void *cc, const void *data, size_t len);

/**
 * Terminate the current SHA-224 computation and output the result into the
 * provided buffer. The destination buffer must be wide enough to
 * accommodate the result (28 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the SHA-224 context
 * @param dst   the destination buffer
 */
void sph_sha224_close(void *cc, void *dst);

/**
 * Initialize a SHA-256 context. This process performs no memory allocation.
 *
 * @param cc   the SHA-256 context (pointer to a sph_sha256_context)
 */
void sph_sha256_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the SHA-256 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_sha256(void *cc, const void *data, size_t len);

/**
 * Terminate the current SHA-256 computation and output the result into the
 * provided buffer. The destination buffer must be wide enough to
 * accommodate the result (32 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the SHA-256 context
 * @param dst   the destination buffer
 */
void sph_sha256_close(void *cc, void *dst);

#endif
