#ifndef __RSA_H
#define __RSA_H

#include <gmp.h>
#include "common.h"

typedef struct {
    mpz_t n, e, d;
    size_t out_len;
    u8* output;
} rsa_ctx_t;

rsa_ctx_t* rsa_ctx_init();
void rsa_ctx_free(rsa_ctx_t*);
void rsa_encrypt(rsa_ctx_t*, const u8*, size_t);
void rsa_decrypt(rsa_ctx_t*, const u8*, size_t);
void rsa_oaep_sha256_encrypt(const mpz_t, const mpz_t, u8*, const u8*, size_t);
size_t rsa_oaep_sha256_decrypt(const mpz_t, const mpz_t, u8*, const u8*);

#endif // __RSA_H
