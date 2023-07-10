#ifndef __AES_H
#define __AES_H

#include <stddef.h> // For size_t
#include "common.h"

#define AES_128_KEY_LEN 16
#define AES_128_N_RNDS 10
#define AES_128_BLK_LEN_W 4
#define AES_128_EXPKEY_LEN (4*(AES_128_N_RNDS+1))
#define WORD_LEN 4
#define BYTE_LEN 8
#define NIBBLE_LEN 4

typedef u8 aes_key_t[AES_128_KEY_LEN];

typedef struct { 
  union {
    u8 bytes[4][4];
    u32 words[4];
  };
} aes_block_t;

typedef struct {
  u32 expanded_key[AES_128_EXPKEY_LEN];
  aes_key_t key;
  u32 nonce;
  u64 iv;
} aes_ctx_t;

typedef struct {
  u8* output;
  size_t len;
} aes_result_t;

#pragma pack(4)
typedef struct {
  aes_key_t key;
  u32 nonce;
  u64 iv;
} aes_params_t;

void aes_128_gen_key(u8*);
aes_ctx_t* aes_128_ctx_init(aes_key_t*, u64*, u32*);
void aes_128_ctx_free(aes_ctx_t*);
void aes_res_free(aes_result_t*);
aes_result_t* aes_128_encrypt(aes_ctx_t*, const u8*, size_t);
aes_result_t* aes_128_decrypt(aes_ctx_t*, const u8*, size_t);

#endif // __AES_H
