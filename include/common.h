#ifndef __COMMON_H
#define __COMMON_H

#include <stddef.h> // For size_t
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

void print_bytes(const u8* bytes, const size_t len);
void print_words(const u32* words, const size_t len);

#endif // __COMMON_H