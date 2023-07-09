#ifndef __COMMON_H
#define __COMMON_H

#include <stddef.h> // For size_t
#include <stdint.h>
#include <openssl/e_os2.h> // For SHA_256_DIGEST_LENGTH define
#include <gmp.h>

#define min(a,b) ((a < b) ? (a) : (b))

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

void* malloc_or_panic(size_t size);
void* malloc_or_realloc(void* pointer, size_t size);
void gen_rand_bytes(u8* dest, size_t len);
void xor_bytes(u8* dest, const u8* src1, const u8* src2, size_t len);
void print_bytes(const u8* bytes, const size_t len);
void print_words(const u32* words, const size_t len);
int sizeof_mpz(const mpz_t big_int);
void sha3_256_wrapper(const u8* message, size_t message_len, u8** digest);
void sha3_256_free(u8* digest);

#endif // __COMMON_H