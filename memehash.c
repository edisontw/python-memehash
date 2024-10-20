#include "memehash.h"
#include <stdint.h>
#include <string.h>
#include "sha3/sph_blake.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_sha2.h"
#include "sha256.h"

void meme_hash(const char* input, char* output, uint32_t len) {
    // Define contexts for each hash algorithm
    sph_blake512_context     ctx_blake;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    sph_sha256_context       ctx_sha256;

    uint32_t hash[16];   // Intermediate hash result
    uint32_t hashA[16];  // Final hash result

    // Blake hash computation
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, input, len);
    sph_blake512_close(&ctx_blake, hash);

    // SIMD hash computation
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash, 64);
    sph_simd512_close(&ctx_simd, hash);

    // Echo hash computation
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hash, 64);
    sph_echo512_close(&ctx_echo, hash);

    // Cubehash hash computation
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hash, 64);
    sph_cubehash512_close(&ctx_cubehash, hash);

    // Shavite hash computation
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hash, 64);
    sph_shavite512_close(&ctx_shavite, hash);

    // First SHA256 hash computation
    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, hash, 64);
    sph_sha256_close(&ctx_sha256, hashA);

    // Second SHA256 hash computation
    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, hashA, 64);
    sph_sha256_close(&ctx_sha256, hashA);

    // Third SHA256 hash computation
    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, hashA, 64);
    sph_sha256_close(&ctx_sha256, hash);

    // Copy the final hash result to the output buffer
    memcpy(output, hash, 32);
}
