#ifndef MEME_H
#define MEME_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// 對外提供的函式原型
void meme_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
