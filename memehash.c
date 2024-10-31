void meme_hash(const char* input, char* output, uint32_t len) {
    sph_blake512_context     ctx_blake;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    sph_sha256_context       ctx_sha256;

    uint64_t hash[8], hash1[8], hash2[8], hash3[8], hash4[8], hash5[8];
    
    // Dummy reference to sph_sha224 to prevent linker errors
    sph_sha224_context dummy_ctx;
    sph_sha224_init(&dummy_ctx);
    sph_sha224(&dummy_ctx, input, len);
    unsigned char dummy_hash[28];
    sph_sha224_close(&dummy_ctx, dummy_hash);
    
    // BLAKE-512
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, input, len);
    sph_blake512_close(&ctx_blake, hash);

    // SIMD-512
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash, 64);
    sph_simd512_close(&ctx_simd, hash1);

    // ECHO-512
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hash1, 64);
    sph_echo512_close(&ctx_echo, hash2);

    // CubeHash-512
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hash2, 64);
    sph_cubehash512_close(&ctx_cubehash, hash3);

    // SHAvite-512
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hash3, 64);
    sph_shavite512_close(&ctx_shavite, hash4);

    // SHA-256 (First Round)
    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, hash4, 64);
    sph_sha256_close(&ctx_sha256, hash5);

    // SHA-256 (Second Round)
    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, hash5, 64);
    sph_sha256_close(&ctx_sha256, hash5);

    // SHA-256 (Third Round)
    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, hash5, 64);
    sph_sha256_close(&ctx_sha256, hash5);

    // Copy the final hash (256 bits)
    memcpy(output, hash5, 32);
}
