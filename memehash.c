#include "memehash.h"
#include <stdint.h>
#include <string.h>
#include "sha3/sph_blake.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_sha2.h"

/**
 * 與 "pepe_hash()" 呼叫順序一致:
 *  BLAKE512 -> SIMD512 -> ECHO512 -> CubeHash512 -> SHAvite512 -> (SHA256 x 3)
 * 輸出最終 32 bytes = 256 bits。
 */
void meme_hash(const char* input, char* output, uint32_t len)
{
    sph_blake512_context     ctx_blake;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    sph_sha256_context       ctx_sha;

    // 中間暫存用的 512-bit = 64 bytes
    uint32_t hash[16];
    uint32_t hashA[16];

    // BLAKE-512
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, input, len);
    sph_blake512_close(&ctx_blake, hash);

    // SIMD-512
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash, 64);
    sph_simd512_close(&ctx_simd, hash);

    // ECHO-512
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hash, 64);
    sph_echo512_close(&ctx_echo, hash);

    // CubeHash-512
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hash, 64);
    sph_cubehash512_close(&ctx_cubehash, hash);

    // SHAvite-512
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hash, 64);
    sph_shavite512_close(&ctx_shavite, hash);

    // 第一輪 SHA-256
    sph_sha256_init(&ctx_sha);
    sph_sha256(&ctx_sha, hash, 64);
    sph_sha256_close(&ctx_sha, hashA);

    // 清 32~63 bytes
    for (int i = 8; i < 16; i++) {
        hashA[i] = 0;
    }

    // 第二輪 SHA-256
    sph_sha256_init(&ctx_sha);
    sph_sha256(&ctx_sha, hashA, 64);
    sph_sha256_close(&ctx_sha, hashA);

    for (int i = 8; i < 16; i++) {
        hashA[i] = 0;
    }

    // 第三輪 SHA-256
    sph_sha256_init(&ctx_sha);
    sph_sha256(&ctx_sha, hashA, 64);
    sph_sha256_close(&ctx_sha, hash);

    // 取前 32 bytes (256 bits)
    memcpy(output, hash, 32);
}
