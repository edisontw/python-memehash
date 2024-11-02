#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "memehash.h"
#include <stdint.h>
#include <string.h>
#include "sha3/sph_blake.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_sha2.h"

void meme_hash(const char* input, char* output, uint32_t len) {
    sph_blake512_context     ctx_blake;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    sph_sha256_context       ctx_sha256;

    unsigned char hash0[64], hash1[64], hash2[64], hash3[64], hash4[64], hash5[64], hash6[64], hash7[64];

    // Dummy reference to sph_sha224 to prevent linker errors
    sph_sha224_context dummy_ctx;
    sph_sha224_init(&dummy_ctx);
    sph_sha224(&dummy_ctx, input, len);
    unsigned char dummy_hash[28];
    sph_sha224_close(&dummy_ctx, dummy_hash);

    // BLAKE-512
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, input, len);
    sph_blake512_close(&ctx_blake, hash0);
    printf("After BLAKE-512: ");
    print_hash(hash0, 64);

    // SIMD-512
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash0, 64);
    sph_simd512_close(&ctx_simd, hash1);
    printf("After SIMD-512: ");
    print_hash(hash1, 64);

    // ECHO-512
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hash1, 64);
    sph_echo512_close(&ctx_echo, hash2);
    printf("After ECHO-512: ");
    print_hash(hash2, 64);

    // CubeHash-512
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hash2, 64);
    sph_cubehash512_close(&ctx_cubehash, hash3);
    printf("After CubeHash-512: ");
    print_hash(hash3, 64);

    // SHAvite-512
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hash3, 64);
    sph_shavite512_close(&ctx_shavite, hash4);
    printf("After SHAvite-512: ");
    print_hash(hash4, 64);

    // SHA-256 (First Round)
    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, hash4, 64);  // Use 64 bytes
    sph_sha256_close(&ctx_sha256, hash5);
    printf("After SHA-256 (First): ");
    print_hash(hash5, 32);

    // SHA-256 (Second Round)
    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, hash5, 64);  // Use 64 bytes
    sph_sha256_close(&ctx_sha256, hash6);
    printf("After SHA-256 (Second): ");
    print_hash(hash6, 32);

    // SHA-256 (Third Round)
    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, hash6, 64);  // Use 64 bytes
    sph_sha256_close(&ctx_sha256, hash7);
    printf("After SHA-256 (Third): ");
    print_hash(hash7, 32);

    // Copy the final hash (upper 256 bits)
    memcpy(output, hash7 + 32, 32);
}


void print_hash(unsigned char* hash, int length) {
    for (int i = 0; i < length; ++i)
        printf("%02x", hash[i]);
    printf("\n");
}
