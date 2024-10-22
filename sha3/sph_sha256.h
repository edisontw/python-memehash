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

/**
 * SHA-224 or SHA-256 context structure.
 */
typedef struct {
    unsigned char buf[64];    /* first field, for alignment */
    sph_u32 val[8];          /* state variables */
    sph_u64 count;           /* processed byte count */
} sph_sha224_context;

typedef sph_sha224_context sph_sha256_context;

/**
 * Initialize an SHA-224 context. This process performs no memory allocation.
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
 * Add a few additional bits (0 to 7) to the current computation, then
 * terminate it and output the result in the provided buffer, which must
 * be wide enough to accommodate the result (28 bytes). If bit number i
 * in <code>ub</code> has value 2^i, then the extra bits are those
 * numbered 7 downto 8-n (this is the big-endian convention at the byte
 * level). The context is automatically reinitialized.
 *
 * @param cc    the SHA-224 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the destination buffer
 */
void sph_sha224_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst);

/**
 * Initialize an SHA-256 context. This process performs no memory allocation.
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

/**
 * Add a few additional bits (0 to 7) to the current computation, then
 * terminate it and output the result in the provided buffer, which must
 * be wide enough to accommodate the result (32 bytes). If bit number i
 * in <code>ub</code> has value 2^i, then the extra bits are those
 * numbered 7 downto 8-n (this is the big-endian convention at the byte
 * level). The context is automatically reinitialized.
 *
 * @param cc    the SHA-256 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the destination buffer
 */
void sph_sha256_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst);

#endif
