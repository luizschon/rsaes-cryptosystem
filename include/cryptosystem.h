#ifndef __CRYPTOSYSTEM_H
#define __CRYPTOSYSTEM_H

#include <stdbool.h>
#include "aes.h"
#include "rsa.h"

typedef struct {
  u8* output;
  size_t len;
} cs_result_t;

void         cs_result_free(cs_result_t*);
cs_result_t* cs_hybrid_encrypt(aes_ctx_t*, mpz_t, mpz_t, const u8*, size_t);
cs_result_t* cs_hybrid_decrypt(mpz_t, mpz_t, const u8*, size_t);
cs_result_t* cs_auth_hybrid_encrypt(aes_ctx_t*, rsa_key_t, rsa_key_t, rsa_key_t, const u8*, size_t);
cs_result_t* cs_auth_hybrid_decrypt(rsa_key_t, const u8*, size_t);
cs_result_t* cs_sign(aes_ctx_t*, rsa_key_t, rsa_key_t, const u8*, size_t len);
bool         cs_vrfy(const u8*, const u8*, size_t);

#endif // __CRYPTOSYSTEM_h