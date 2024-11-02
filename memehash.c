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
    // Declare the hashing contexts for each hash function used
    sph_blake512_context     ctx_blake;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    sph_sha256_context       ctx_sha;

    // Intermediate hash buffers
    uint32_t hash[16];   // Buffer to store the intermediate hash results
    uint32_t hashA[16];  // Buffer for further SHA-256 rounds

    // BLAKE-512
    // Initialize the BLAKE-512 context and perform the hash operation
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, input, len);
    sph_blake512_close(&ctx_blake, hash);

    // SIMD-512
    // Use the output of BLAKE-512 as input for SIMD-512 hashing
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash, 64);
    sph_simd512_close(&ctx_simd, hash);

    // ECHO-512
    // Use the output of SIMD-512 as input for ECHO-512 hashing
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hash, 64);
    sph_echo512_close(&ctx_echo, hash);

    // CubeHash-512
    // Use the output of ECHO-512 as input for CubeHash-512 hashing
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hash, 64);
    sph_cubehash512_close(&ctx_cubehash, hash);

    // SHAvite-512
    // Use the output of CubeHash-512 as input for SHAvite-512 hashing
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hash, 64);
    sph_shavite512_close(&ctx_shavite, hash);

    // SHA-256 (First Round)
    // Initialize SHA-256 context and hash the output of SHAvite-512
    sph_sha256_init(&ctx_sha);
    sph_sha256(&ctx_sha, hash, 64);
    sph_sha256_close(&ctx_sha, hashA);

    // Set the second half of hashA to 0
    // This ensures that the unused portion is zeroed out, avoiding residual data effects
    for (int i = 8; i < 16; i++)
        hashA[i] = 0;

    // SHA-256 (Second Round)
    // Perform a second round of SHA-256 on hashA
    sph_sha256_init(&ctx_sha);
    sph_sha256(&ctx_sha, hashA, 64);
    sph_sha256_close(&ctx_sha, hashA);

    // Set the second half of hashA to 0 again
    // This ensures consistency by clearing out any data not overwritten by the hash
    for (int i = 8; i < 16; i++)
        hashA[i] = 0;

    // SHA-256 (Third Round)
    // Perform a third round of SHA-256 on hashA
    sph_sha256_init(&ctx_sha);
    sph_sha256(&ctx_sha, hashA, 64);
    sph_sha256_close(&ctx_sha, hash);

    // Copy the final hash (upper 256 bits)
    // Only copy the first 32 bytes of the resulting 64-byte hash to the output
    memcpy(output, hash, 32);
}

void print_hash(unsigned char* hash, int length) {
    // Print the hash in hexadecimal format, byte by byte
    for (int i = 0; i < length; ++i)
        printf("%02x", hash[i]);
    printf("\n");
}
