#include "memehash.h"
#include <stdint.h>
#include <string.h>
#include "sha3/sph_blake.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sha2.h"

void meme_hash(const char* input, char* output, uint32_t len) {
    sph_blake512_context     ctx_blake;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    sph_sha256_context       ctx_sha256;

    uint32_t hash[16];
    uint32_t hashA[16];

    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, input, len);
    sph_blake512_close(&ctx_blake, hash);

    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash, 64);
    sph_simd512_close(&ctx_simd, hash);

    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hash, 64);
    sph_echo512_close(&ctx_echo, hash);

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hash, 64);
    sph_cubehash512_close(&ctx_cubehash, hash);

    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hash, 64);
    sph_shavite512_close(&ctx_shavite, hash);

    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, hash, 64);
    sph_sha256_close(&ctx_sha256, hashA);

    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, hashA, 32);
    sph_sha256_close(&ctx_sha256, hashA);

    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, hashA, 32);
    sph_sha256_close(&ctx_sha256, hash);

    memcpy(output, hash, 32);
}
